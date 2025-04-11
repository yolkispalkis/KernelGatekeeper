// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
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

#ifndef _LINUX_SOCKET_H
struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};
struct in_addr {
    unsigned int s_addr;
};
#endif


static __always_inline void kg_stats_inc(int field) {
    __u32 key = 0;
    struct global_stats_t *stats = bpf_map_lookup_elem(&kg_stats, &key);
    if (stats) {
        if (field == 2) __sync_fetch_and_add(&stats->getsockopt_ok, 1);
        else if (field == 3) __sync_fetch_and_add(&stats->getsockopt_fail, 1);
    }
}

SEC("cgroup/getsockopt")
int kernelgatekeeper_getsockopt(struct bpf_sockopt *ctx) {

    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1;
    }

    if (ctx->sk == NULL || ctx->sk->family != AF_INET || ctx->sk->protocol != IPPROTO_TCP) {
         #ifdef DEBUG
         bpf_printk("GETSOCKOPT: Ignoring non-IPv4/TCP getsockopt or NULL sk.\n");
         #endif
        return 1;
    }

    __u16 peer_port_h = bpf_ntohs(ctx->sk->dst_port);
    if (peer_port_h == 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Peer port is 0, cannot lookup cookie.\n");
        #endif
        kg_stats_inc(3);
        return 1;
    }


    __u64 *cookie_ptr = bpf_map_lookup_elem(&kg_port_to_cookie, &peer_port_h);
    if (!cookie_ptr) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Cookie not found for peer port %u.\n", peer_port_h);
        #endif
        kg_stats_inc(3);
        return 1;
    }
    __u64 cookie = *cookie_ptr;

    struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_orig_dest, &cookie);
    if (!orig_dest) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Original destination not found for cookie %llu (port %u).\n", cookie, peer_port_h);
        #endif
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3);
        return 1;
    }

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

    struct sockaddr_in *sa = (struct sockaddr_in *)ctx->optval;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = orig_dest->dst_ip;
    sa->sin_port = orig_dest->dst_port;
    ctx->optlen = sizeof(struct sockaddr_in);
    ctx->retval = 0;

    bpf_map_delete_elem(&kg_orig_dest, &cookie);
    bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
    kg_stats_inc(2);

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT: Successfully returned original dest %x:%u for cookie %llu (port %u).\n",
               orig_dest->dst_ip, bpf_ntohs(orig_dest->dst_port), cookie, peer_port_h);
    #endif

    return 1;
}

char _license[] SEC("license") = "GPL";