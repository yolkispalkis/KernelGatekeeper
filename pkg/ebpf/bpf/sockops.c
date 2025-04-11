// FILE: pkg/ebpf/bpf/sockops.c
//go:build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/socket.h>
#include <linux/in.h>
#include "bpf_shared.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 1
#endif
#ifndef BPF_OK
#define BPF_OK 0
#endif

SEC("sockops")
int kernelgatekeeper_sockops(struct bpf_sock_ops *skops) {

    __u16 op = skops->op;

    #ifdef DEBUG
    bpf_printk("SOCKOPS_DEBUG: family=%u op=%u lport=%u rport=%u lip4=%x rip4=%x reply=%u pid=%llu\n",
               skops->family, op, (__u16)skops->local_port, bpf_ntohs(skops->remote_port),
               skops->local_ip4, skops->remote_ip4, skops->reply, bpf_get_current_pid_tgid());
    #endif

    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    if (skops->family != AF_INET) {
         #ifdef DEBUG
         bpf_printk("SOCKOPS: Ignoring non-AF_INET established connection.\n");
         #endif
        return BPF_OK;
    }

    __u64 sock_cookie = bpf_get_socket_cookie(skops);
    if (sock_cookie == 0) {
         #ifdef DEBUG
         bpf_printk("SOCKOPS_ERR: Failed to get socket cookie (ACTIVE_ESTABLISHED_CB).\n");
         #endif
         return BPF_OK;
    }

    struct original_dest_t *details = bpf_map_lookup_elem(&kg_orig_dest, &sock_cookie);
    if (!details) {

        #ifdef DEBUG
        bpf_printk("SOCKOPS_DEBUG: No original dest found for cookie %llu, likely not redirected by connect4.\n", sock_cookie);
        #endif
        return BPF_OK;
    }

    __u16 src_port_h = (__u16)skops->local_port;

    int ret = bpf_map_update_elem(&kg_port_to_cookie, &src_port_h, &sock_cookie, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS_ERR: Failed to update kg_port_to_cookie (port %u, cookie %llu): %d\n", src_port_h, sock_cookie, ret);

        bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
    } else {
        #ifdef DEBUG
        bpf_printk("SOCKOPS: Stored port->cookie mapping (%u -> %llu)\n", src_port_h, sock_cookie);
        #endif
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
