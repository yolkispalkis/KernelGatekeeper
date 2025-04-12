// FILE: pkg/ebpf/bpf/connect4.c
//go:build ignore

// Includes for CO-RE
#include "vmlinux.h"        // Generated kernel types
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Custom shared definitions
#include "bpf_shared.h"          // <<< ENSURE THIS IS PRESENT
#include <bpf/bpf_core_read.h>   // Needs to be after vmlinux.h and bpf_helpers.h

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

// --- Вспомогательная функция для статистики ---
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// REMOVE the kg_stats_inc function definition from here
// static __always_inline void kg_stats_inc(int field) { ... }
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

// --- Основная функция хука ---
SEC("cgroup/connect4")
int kernelgatekeeper_connect4(struct bpf_sock_addr *ctx) {

    // --- Начало новой логики исключения по dev/inode ---
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: bpf_get_current_task_btf failed. Proceeding without exclusion check.\n");
        #endif
        goto proceed_to_main_logic;
    }

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) {
         #ifdef DEBUG
         // bpf_printk("CONNECT4_DEBUG: No mm struct for task, likely kernel thread. Proceeding.\n");
         #endif
        goto proceed_to_main_logic;
    }

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

    __u64 dev_kernel = BPF_CORE_READ(sb, s_dev);
    unsigned long ino_kernel = BPF_CORE_READ(inode, i_ino);

    struct dev_inode_key key = {};
    key.dev_id = (__u64)dev_kernel;
    key.inode_id = (__u64)ino_kernel;

    // Проверяем наличие в карте исключений <<< USES excluded_dev_inodes >>>
    __u8 *excluded_flag = bpf_map_lookup_elem(&excluded_dev_inodes, &key); // Map defined in bpf_shared.h
    if (excluded_flag && *excluded_flag == 1) {
        #ifdef DEBUG
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        bpf_printk("CONNECT4_SKIP: Skipping excluded executable (dev:ino %llu:%llu), comm: %s, pid: %u\n",
                   key.dev_id, key.inode_id, comm, (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF));
        #endif
        return 1;
    }
    // --- Конец новой логики исключения ---

proceed_to_main_logic:
    // --- Основная логика перенаправления ---

    if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP) {
        return 1;
    }
    kg_stats_inc(0); // <<< Call function defined in bpf_shared.h

    __u64 current_pid_tgid = bpf_get_current_pid_tgid();
    __u32 current_pid = (__u32)(current_pid_tgid & 0xFFFFFFFF);
    __u32 current_uid = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

    if (current_pid == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_WARN: Zero PID encountered after exclusion check. Skipping. TGID_PID: %llu\n", current_pid_tgid);
        #endif
        return 1;
    }

    // <<< USES kg_client_pids >>>
    __u8 *is_kg_client = bpf_map_lookup_elem(&kg_client_pids, ¤t_pid); // Map defined in bpf_shared.h
    if (is_kg_client && *is_kg_client == 1) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_SKIP: Skipping connection from known client PID %u\n", current_pid);
        #endif
        return 1;
    }

    // <<< USES target_ports >>>
    __u16 orig_dst_port_h = bpf_ntohs(ctx->user_port);
    __u8 *target_flag = bpf_map_lookup_elem(&target_ports, &orig_dst_port_h); // Map defined in bpf_shared.h
    if (!target_flag || *target_flag != 1) {
         // #ifdef DEBUG
         // char comm[16];
         // bpf_get_current_comm(&comm, sizeof(comm));
         // bpf_printk("CONNECT4_DEBUG: Port %u not targeted, skipping. PID: %u, Comm: %s\n", orig_dst_port_h, current_pid, comm);
         // #endif
        return 1;
    }

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to get socket cookie for PID %u.\n", current_pid);
        #endif
        return 1;
    }

    struct original_dest_t details = {};
    details.pid = current_pid;
    details.uid = current_uid;
    details.dst_ip = ctx->user_ip4;
    details.dst_port = ctx->user_port;

    // <<< USES kg_orig_dest >>>
    int ret = bpf_map_update_elem(&kg_orig_dest, &cookie, &details, BPF_ANY); // Map defined in bpf_shared.h
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed update kg_orig_dest (PID %u, cookie %llu): %d\n", current_pid, cookie, ret);
        #endif
        return 1;
    }

    // <<< USES kg_config >>>
    __u32 cfg_key = 0;
    struct kg_config_t *cfg = bpf_map_lookup_elem(&kg_config, &cfg_key); // Map defined in bpf_shared.h
    if (!cfg || cfg->listener_ip == 0 || cfg->listener_port == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed lookup config or config invalid (PID %u, cookie %llu)\n", current_pid, cookie);
        #endif
        // <<< USES kg_orig_dest >>>
        bpf_map_delete_elem(&kg_orig_dest, &cookie); // Map defined in bpf_shared.h
        return 1;
    }

    // --- Перенаправление ---
    __u32 orig_dst_ip_n = ctx->user_ip4;
    ctx->user_ip4 = cfg->listener_ip;
    ctx->user_port = bpf_htons(cfg->listener_port);
    kg_stats_inc(1); // <<< Call function defined in bpf_shared.h

    #ifdef DEBUG
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("CONNECT4_REDIR: Redirected PID %u (comm %s, cookie %llu) dest %x:%u -> %x:%u\n",
               current_pid, comm, cookie, orig_dst_ip_n, orig_dst_port_h, ctx->user_ip4, cfg->listener_port);
    #endif

    return 1;
}

char _license[] SEC("license") = "GPL";