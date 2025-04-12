// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include "vmlinux.h"        // For sock structure, constants
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h> // Keep this include
#include "bpf_shared.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// REMOVE the kg_stats_inc function definition from here
// static __always_inline void kg_stats_inc(int field) { ... }
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

SEC("cgroup/getsockopt")
int kernelgatekeeper_getsockopt(struct bpf_sockopt *ctx) {

    // Interest check remains the same
    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1;
    }

    // sk NULL check remains the same
    if (ctx->sk == NULL) {
         return 1;
    }

    // Use BPF_CORE_READ for field access
    __u16 family = BPF_CORE_READ(ctx->sk, family);
    __u8 protocol = BPF_CORE_READ(ctx->sk, protocol);

    // Protocol check remains the same
    if (family != AF_INET || protocol != IPPROTO_TCP) {
        return 1;
    }

    // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    // CHANGE sk_dport back to dst_port
    __be16 peer_port_n = BPF_CORE_READ(ctx->sk, dst_port); // Use dst_port
    // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    __u16 peer_port_h = bpf_ntohs(peer_port_n);

    if (peer_port_h == 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Peer port is 0, cannot lookup cookie.\n");
        #endif
        kg_stats_inc(3); // Call the function (now defined in shared header)
        return 1;
    }

    // ... (rest of the function remains the same, including calls to kg_stats_inc) ...

    // Cookie lookup
    __u64 *cookie_ptr = bpf_map_lookup_elem(&kg_port_to_cookie, &peer_port_h);
    if (!cookie_ptr) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Cookie not found for peer port %u.\n", peer_port_h);
        #endif
        kg_stats_inc(3);
        return 1;
    }
    __u64 cookie = *cookie_ptr;

    // Original destination lookup
    struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_orig_dest, &cookie);
    if (!orig_dest) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Original destination not found for cookie %llu (port %u).\n", cookie, peer_port_h);
        #endif
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3);
        return 1;
    }

    // Buffer validation
    if (ctx->optval == NULL || ctx->optval_end == NULL ||
        (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for cookie %llu (port %u).\n", cookie, peer_port_h);
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3);
        return 1;
    }

    // Use bpf_probe_write_user
    struct sockaddr_in sa_out = {};
    sa_out.sin_family = AF_INET;
    sa_out.sin_addr.s_addr = orig_dest->dst_ip;
    sa_out.sin_port = orig_dest->dst_port;

    long ret = bpf_probe_write_user(ctx->optval, &sa_out, sizeof(sa_out));
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: bpf_probe_write_user failed: %ld\n", ret);
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3);
        return 1;
    }

    // Setting optlen, retval, map cleanup, and logging
    ctx->optlen = sizeof(struct sockaddr_in);
    ctx->retval = 0;

    bpf_map_delete_elem(&kg_orig_dest, &cookie);
    bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
    kg_stats_inc(2);

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT: OK orig dest %x:%u cookie %llu port %u\n",
               orig_dest->dst_ip, bpf_ntohs(orig_dest->dst_port), cookie, peer_port_h);
    #endif

    return 1;
}

char _license[] SEC("license") = "GPL";