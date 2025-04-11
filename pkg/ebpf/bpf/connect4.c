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
    kg_stats_inc(0);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;

    __u8 *is_excluded = bpf_map_lookup_elem(&kg_client_pids, &pid);
    if (is_excluded && *is_excluded == 1) {
        #ifdef DEBUG
        bpf_printk("CONNECT4: Skipping connection from excluded client PID %u\n", pid);
        #endif
        return 1;
    }

    __u16 orig_dst_port_h = bpf_ntohs(ctx->user_port);
    __u8 *target_flag = bpf_map_lookup_elem(&target_ports, &orig_dst_port_h);

    if (!target_flag || *target_flag != 1) {
         #ifdef DEBUG
         bpf_printk("CONNECT4: Port %u not targeted, skipping.\n", orig_dst_port_h);
         #endif
        return 1;
    }

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to get socket cookie.\n");
        #endif
        return 1;
    }

    struct original_dest_t details = {};
    details.pid = pid;
    details.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    details.dst_ip = ctx->user_ip4;
    details.dst_port = ctx->user_port;

    int ret = bpf_map_update_elem(&kg_orig_dest, &cookie, &details, BPF_ANY);
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to update kg_orig_dest map (cookie %llu): %d\n", cookie, ret);
        #endif
        return 1;
    }

    __u32 cfg_key = 0;
    struct kg_config_t *cfg = bpf_map_lookup_elem(&kg_config, &cfg_key);
    if (!cfg) {
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to lookup config map\n");
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        return 1;
    }

    ctx->user_ip4 = cfg->listener_ip;
    ctx->user_port = bpf_htons(cfg->listener_port);
    kg_stats_inc(1);

    #ifdef DEBUG
    bpf_printk("CONNECT4: Redirecting PID %u (cookie %llu) dest %x:%u -> %x:%u\n",
               pid, cookie, details.dst_ip, orig_dst_port_h, ctx->user_ip4, cfg->listener_port);
    #endif

    return 1;
}

char _license[] SEC("license") = "GPL";
