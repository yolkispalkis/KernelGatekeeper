// FILE: pkg/ebpf/bpf/connect4.c
//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/fs.h>       // Для структур file, inode, super_block
#include <linux/sched.h>    // Для task_struct, mm_struct
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h> // Для CO-RE
#include "bpf_shared.h"
#include "vmlinux.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

// --- Вспомогательная функция для статистики ---
static __always_inline void kg_stats_inc(int field) {
    __u32 key = 0;
    struct global_stats_t *stats = bpf_map_lookup_elem(&kg_stats, &key);
    if (stats) {
        if (field == 0) __sync_fetch_and_add(&stats->packets, 1);
        else if (field == 1) __sync_fetch_and_add(&stats->redirected, 1);
        // Статистика getsockopt остается в getsockopt.c
    }
}

// --- Основная функция хука ---
SEC("cgroup/connect4")
int kernelgatekeeper_connect4(struct bpf_sock_addr *ctx) {

    // --- Начало новой логики исключения по dev/inode ---
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: bpf_get_current_task_btf failed. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic; // Перейти к основной логике, если не удалось получить task
    }

    // Проверка на kernel thread (у них нет mm)
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) {
        #ifdef DEBUG
        // bpf_printk("CONNECT4_DEBUG: No mm struct for task, likely kernel thread. Proceeding.\n");
        #endif
        goto proceed_to_main_logic; // Ядерные потоки не исключаем по файлу
    }

    // Получаем file->inode->super_block для dev/inode
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
     if (!exe_file) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Cannot read task->mm->exe_file. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }

    struct inode *inode = BPF_CORE_READ(exe_file, f_inode);
    if (!inode) {
         #ifdef DEBUG
         bpf_printk("CONNECT4_WARN: Cannot read exe_file->f_inode. Proceeding without exclusion check.\n");
         #endif
        goto proceed_to_main_logic;
    }

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
     if (!sb) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Cannot read inode->i_sb. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }

    // Читаем dev_t и номер inode
    // BPF_CORE_READ_KERNEL для чтения напрямую (без указателя)
    dev_t dev_kernel = BPF_CORE_READ_KERNEL(sb, s_dev);
    unsigned long ino_kernel = BPF_CORE_READ_KERNEL(inode, i_ino);

    // Формируем ключ для карты
    struct dev_inode_key key = {};
    key.dev_id = (__u64)dev_kernel; // Простое приведение типа. Может потребовать уточнения для 32-бит dev_t.
    key.inode_id = (__u64)ino_kernel;

    // Проверяем наличие в карте исключений
    __u8 *excluded_flag = bpf_map_lookup_elem(&excluded_dev_inodes, &key);
    if (excluded_flag && *excluded_flag == 1) {
        // Исполняемый файл находится в списке исключений.
        #ifdef DEBUG
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        // Логируем только при DEBUG, чтобы не засорять вывод
        bpf_printk("CONNECT4_SKIP: Skipping excluded executable (dev:ino %llu:%llu), comm: %s, pid: %u\n",
                   key.dev_id, key.inode_id, comm, (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF));
        #endif
        return 1; // <<< ВАЖНО: Выход БЕЗ какой-либо обработки
    }
    // --- Конец новой логики исключения ---

proceed_to_main_logic:
    // --- Основная логика перенаправления (старая + немного рефакторинга) ---

    // Интересуют только IPv4 TCP
    if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP) {
        return 1;
    }
    kg_stats_inc(0); // Счетчик пакетов

    // Получаем PID/TGID
    __u64 current_pid_tgid = bpf_get_current_pid_tgid();
    __u32 current_pid = (__u32)(current_pid_tgid & 0xFFFFFFFF);
    __u32 current_uid = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

    // Проверка на нулевой PID (маловероятно после проверок выше, но на всякий случай)
    if (current_pid == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Zero PID encountered after exclusion check. Skipping. TGID_PID: %llu\n", current_pid_tgid);
        #endif
        return 1;
    }

    // Исключаем сами клиентские процессы KernelGatekeeper по PID (если они попали сюда)
    // Эта карта теперь используется только для ЭТОГО.
    __u8 *is_kg_client = bpf_map_lookup_elem(&kg_client_pids, &current_pid);
    if (is_kg_client && *is_kg_client == 1) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_SKIP: Skipping connection from known client PID %u\n", current_pid);
        #endif
        return 1;
    }

    // Проверяем, является ли порт целевым
    __u16 orig_dst_port_h = bpf_ntohs(ctx->user_port); // Порт назначения в host byte order
    __u8 *target_flag = bpf_map_lookup_elem(&target_ports, &orig_dst_port_h);
    if (!target_flag || *target_flag != 1) {
         // Не целевой порт, пропускаем
         // #ifdef DEBUG // Раскомментировать для отладки нецелевых портов
         // char comm[16];
         // bpf_get_current_comm(&comm, sizeof(comm));
         // bpf_printk("CONNECT4_DEBUG: Port %u not targeted, skipping. PID: %u, Comm: %s\n", orig_dst_port_h, current_pid, comm);
         // #endif
        return 1;
    }

    // Получаем куку сокета
    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to get socket cookie for PID %u.\n", current_pid);
        #endif
        return 1; // Не можем продолжить без куки
    }

    // Сохраняем оригинальные данные назначения
    struct original_dest_t details = {};
    details.pid = current_pid;
    details.uid = current_uid;
    details.dst_ip = ctx->user_ip4;   // network byte order
    details.dst_port = ctx->user_port; // network byte order

    int ret = bpf_map_update_elem(&kg_orig_dest, &cookie, &details, BPF_ANY);
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed update kg_orig_dest (PID %u, cookie %llu): %d\n", current_pid, cookie, ret);
        #endif
        // Не перенаправляем, если не смогли сохранить детали
        return 1;
    }

    // Получаем конфигурацию слушателя клиента
    __u32 cfg_key = 0;
    struct kg_config_t *cfg = bpf_map_lookup_elem(&kg_config, &cfg_key);
    if (!cfg || cfg->listener_ip == 0 || cfg->listener_port == 0) { // Добавим проверку на валидность config
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed lookup config or config invalid (PID %u, cookie %llu)\n", current_pid, cookie);
        #endif
        // Очищаем запись, если конфиг не найден/невалиден
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        return 1;
    }

    // --- Перенаправление ---
    __u32 orig_dst_ip_n = ctx->user_ip4; // Сохраним для лога
    ctx->user_ip4 = cfg->listener_ip;
    ctx->user_port = bpf_htons(cfg->listener_port);
    kg_stats_inc(1); // Счетчик перенаправлений

    #ifdef DEBUG
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("CONNECT4_REDIR: Redirected PID %u (comm %s, cookie %llu) dest %x:%u -> %x:%u\n",
               current_pid, comm, cookie, orig_dst_ip_n, orig_dst_port_h, ctx->user_ip4, cfg->listener_port);
    #endif

    return 1; // Всегда возвращаем 1 для cgroup/connect4
}

char _license[] SEC("license") = "GPL";