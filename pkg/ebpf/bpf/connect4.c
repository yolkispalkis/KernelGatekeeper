// FILE: pkg/ebpf/bpf/connect4.c
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_shared.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

// Определения структур для CO-RE
struct task_fs_struct {
    struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct mm_file_struct {
    struct file *exe_file;
} __attribute__((preserve_access_index));

struct file_inode_struct {
    struct inode *f_inode;
} __attribute__((preserve_access_index));

struct inode_sb_struct {
    struct super_block *i_sb;
    unsigned long i_ino;
} __attribute__((preserve_access_index));

struct super_block_struct {
    unsigned long s_dev;
} __attribute__((preserve_access_index));

SEC("cgroup/connect4")
int kernelgatekeeper_connect4(struct bpf_sock_addr *ctx) {
    // --- Начало логики исключения по dev/inode ---
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: bpf_get_current_task_btf failed. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }

    struct mm_struct *mm = NULL;
    if (bpf_core_read(&mm, sizeof(mm), &task->mm) || !mm) {
        #ifdef DEBUG
        // bpf_printk("CONNECT4_DEBUG: No mm struct for task, likely kernel thread. Proceeding.\n");
        #endif
        goto proceed_to_main_logic;
    }

    struct file *exe_file = NULL;
    if (bpf_core_read(&exe_file, sizeof(exe_file), &mm->exe_file) || !exe_file) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Cannot read task->mm->exe_file. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }

    struct inode *inode = NULL;
    if (bpf_core_read(&inode, sizeof(inode), &exe_file->f_inode) || !inode) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Cannot read exe_file->f_inode. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }

    struct super_block *sb = NULL;
    if (bpf_core_read(&sb, sizeof(sb), &inode->i_sb) || !sb) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Cannot read inode->i_sb. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }

    __u64 dev_kernel = 0;
    unsigned long ino_kernel = 0;
    
    if (bpf_core_read(&dev_kernel, sizeof(dev_kernel), &sb->s_dev)) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Cannot read sb->s_dev. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }
    
    if (bpf_core_read(&ino_kernel, sizeof(ino_kernel), &inode->i_ino)) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Cannot read inode->i_ino. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }

    struct dev_inode_key key = {};
    key.dev_id = (__u64)dev_kernel;
    key.inode_id = (__u64)ino_kernel;

    // Проверяем наличие в карте исключений
    __u8 *excluded_flag = bpf_map_lookup_elem(&excluded_dev_inodes, &key);
    if (excluded_flag && *excluded_flag == 1) {
        #ifdef DEBUG
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        bpf_printk("CONNECT4_SKIP: Skipping excluded executable (dev:ino %llu:%llu), comm: %s, pid: %u\n",
                  key.dev_id, key.inode_id, comm, (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF));
        #endif
        return 1;
    }
    // --- Конец логики исключения ---

proceed_to_main_logic:
    // --- Основная логика перенаправления ---
    // Безопасное чтение полей структуры ctx
    __u16 family;
    __u8 protocol;
    
    if (bpf_core_read(&family, sizeof(family), &ctx->family)) {
        return 1;
    }
    
    if (bpf_core_read(&protocol, sizeof(protocol), &ctx->protocol)) {
        return 1;
    }

    if (family != AF_INET || protocol != IPPROTO_TCP) {
        return 1;
    }
    
    kg_stats_inc(0);

    __u64 current_pid_tgid = bpf_get_current_pid_tgid();
    __u32 current_pid = (__u32)(current_pid_tgid & 0xFFFFFFFF);
    __u32 current_uid = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

    if (current_pid == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Zero PID encountered after exclusion check. Skipping. TGID_PID: %llu\n", 
                  current_pid_tgid);
        #endif
        return 1;
    }

    // Проверка списка PID клиентов
    __u8 *is_kg_client = bpf_map_lookup_elem(&kg_client_pids, &current_pid);
    if (is_kg_client && *is_kg_client == 1) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_SKIP: Skipping connection from known client PID %u\n", current_pid);
        #endif
        return 1;
    }

    // Получение порта назначения и проверка целевых портов
    __be16 user_port;
    if (bpf_core_read(&user_port, sizeof(user_port), &ctx->user_port)) {
        return 1;
    }
    
    __u16 orig_dst_port_h = bpf_ntohs(user_port);
    __u8 *target_flag = bpf_map_lookup_elem(&target_ports, &orig_dst_port_h);
    if (!target_flag || *target_flag != 1) {
        return 1;
    }

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to get socket cookie for PID %u.\n", current_pid);
        #endif
        return 1;
    }

    // Получение IP адреса назначения
    __be32 user_ip4;
    if (bpf_core_read(&user_ip4, sizeof(user_ip4), &ctx->user_ip4)) {
        return 1;
    }

    struct original_dest_t details = {};
    details.pid = current_pid;
    details.uid = current_uid;
    details.dst_ip = user_ip4;
    details.dst_port = user_port;

    int ret = bpf_map_update_elem(&kg_orig_dest, &cookie, &details, BPF_ANY);
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed update kg_orig_dest (PID %u, cookie %llu): %d\n", 
                  current_pid, cookie, ret);
        #endif
        return 1;
    }

    // Получение и проверка конфигурации
    __u32 cfg_key = 0;
    struct kg_config_t *cfg = bpf_map_lookup_elem(&kg_config, &cfg_key);
    if (!cfg || cfg->listener_ip == 0 || cfg->listener_port == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed lookup config or config invalid (PID %u, cookie %llu)\n", 
                  current_pid, cookie);
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        return 1;
    }

    // --- Перенаправление ---
    __u32 orig_dst_ip_n = user_ip4;
    
    if (bpf_core_write(&ctx->user_ip4, cfg->listener_ip)) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to write ctx->user_ip4\n");
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        return 1;
    }
    
    if (bpf_core_write(&ctx->user_port, bpf_htons(cfg->listener_port))) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to write ctx->user_port\n");
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        return 1;
    }
    
    kg_stats_inc(1);

    #ifdef DEBUG
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("CONNECT4_REDIR: Redirected PID %u (comm %s, cookie %llu) dest %x:%u -> %x:%u\n",
              current_pid, comm, cookie, orig_dst_ip_n, orig_dst_port_h, cfg->listener_ip, cfg->listener_port);
    #endif

    return 1;
}

char _license[] SEC("license") = "GPL";