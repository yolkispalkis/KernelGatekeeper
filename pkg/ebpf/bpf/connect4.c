// FILE: pkg/ebpf/bpf/connect4.c
//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_shared.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

static __always_inline void kg_stats_inc(int field) {
    __u32 key = 0;
    struct global_stats_t *stats = bpf_map_lookup_elem(&kg_stats, &key);
    if (stats) {
        if (field == 0) __sync_fetch_and_add(&stats->packets, 1);
        else if (field == 1) __sync_fetch_and_add(&stats->redirected, 1);
    }
}


SEC("cgroup/connect4")
int kernelgatekeeper_connect4(struct bpf_sock_addr *ctx) {

    if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP) {
        return 1;
    }
    kg_stats_inc(0); // Increment packet count

    // Get and log PID early
    __u64 current_pid_tgid_connect4 = bpf_get_current_pid_tgid(); // Get PID/TGID here
    __u32 current_pid_connect4 = current_pid_tgid_connect4 & 0xFFFFFFFF;

    #ifdef DEBUG
    bpf_printk("CONNECT4: Hook triggered. PID_TGID=%llu, Extracted PID=%u\n",
               current_pid_tgid_connect4, current_pid_connect4);
    #endif

    // Check if PID is 0 early
    if (current_pid_connect4 == 0) {
        bpf_printk("CONNECT4_WARN: bpf_get_current_pid_tgid() returned 0 PID_TGID=%llu. Skipping redirection.\n",
                   current_pid_tgid_connect4);
        return 1; // Don't proceed if PID is 0
    }


    __u8 *is_excluded = bpf_map_lookup_elem(&kg_client_pids, &current_pid_connect4);
    if (is_excluded && *is_excluded == 1) {
        #ifdef DEBUG
        bpf_printk("CONNECT4: Skipping connection from excluded client PID %u\n", current_pid_connect4);
        #endif
        return 1;
    }

    __u16 orig_dst_port_h = bpf_ntohs(ctx->user_port);
    __u8 *target_flag = bpf_map_lookup_elem(&target_ports, &orig_dst_port_h);

    if (!target_flag || *target_flag != 1) {
         #ifdef DEBUG
         // Frequent log, maybe disable:
         // bpf_printk("CONNECT4: Port %u not targeted, skipping.\n", orig_dst_port_h);
         #endif
        return 1;
    }

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to get socket cookie for PID %u.\n", current_pid_connect4);
        #endif
        return 1;
    }

    // Log PID just before storing
    #ifdef DEBUG
    bpf_printk("CONNECT4_STORE: Storing details for PID=%u, Cookie=%llu\n", current_pid_connect4, cookie);
    #endif

    struct original_dest_t details = {};
    details.pid = current_pid_connect4; // Store the PID obtained earlier
    details.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    details.dst_ip = ctx->user_ip4;
    details.dst_port = ctx->user_port; // Store in network byte order

    int ret = bpf_map_update_elem(&kg_orig_dest, &cookie, &details, BPF_ANY);
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed update kg_orig_dest (PID %u, cookie %llu): %d\n", current_pid_connect4, cookie, ret);
        #endif
        // Consider not returning here? Maybe redirection is still desired even if map fails?
        // For now, keep original logic: fail if map update fails.
        return 1;
    }

    __u32 cfg_key = 0;
    struct kg_config_t *cfg = bpf_map_lookup_elem(&kg_config, &cfg_key);
    if (!cfg) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed lookup config (PID %u, cookie %llu)\n", current_pid_connect4, cookie);
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie); // Clean up map on config failure
        return 1;
    }

    ctx->user_ip4 = cfg->listener_ip;
    ctx->user_port = bpf_htons(cfg->listener_port);
    kg_stats_inc(1); // Increment redirect count

    #ifdef DEBUG
    bpf_printk("CONNECT4_REDIR: Redirected PID %u (cookie %llu) dest %x:%u -> %x:%u\n",
               current_pid_connect4, cookie, details.dst_ip, orig_dst_port_h, ctx->user_ip4, cfg->listener_port);
    #endif

    return 1;
}

char _license[] SEC("license") = "GPL";