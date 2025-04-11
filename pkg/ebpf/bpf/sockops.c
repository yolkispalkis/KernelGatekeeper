// FILE: pkg/ebpf/bpf/sockops.c
//go:build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/socket.h>
#include <linux/in.h>
#include "bpf_shared.h"
#include <bpf/bpf_tracing.h> // Include for IPPROTO_TCP if not elsewhere

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
        // This connection wasn't redirected by connect4, ignore.
        #ifdef DEBUG
        bpf_printk("SOCKOPS_DEBUG: No original dest found for cookie %llu, likely not redirected by connect4.\n", sock_cookie);
        #endif
        return BPF_OK;
    }

    // Key for the port_to_cookie map is the source port (local port in sockops context)
    __u16 src_port_h = (__u16)skops->local_port; // Source port (Host Byte Order)

    // Store the mapping from source port -> original destination cookie
    int ret = bpf_map_update_elem(&kg_port_to_cookie, &src_port_h, &sock_cookie, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS_ERR: Failed to update kg_port_to_cookie (port %u, cookie %llu): %d\n", src_port_h, sock_cookie, ret);
        // Clean up the original destination entry if port mapping fails
        bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
    } else {
        #ifdef DEBUG
        bpf_printk("SOCKOPS: Stored port->cookie mapping (%u -> %llu)\n", src_port_h, sock_cookie);
        #endif

        // Send notification to userspace via ring buffer
        struct notification_tuple_t *notif;
        notif = bpf_ringbuf_reserve(&kg_notif_rb, sizeof(*notif), 0);
        if (!notif) {
            bpf_printk("SOCKOPS_ERR: Failed to reserve space in ring buffer for notification.\n");
        } else {
            notif->pid_tgid = bpf_get_current_pid_tgid();
            notif->src_ip = skops->local_ip4;         // Source IP is local IP in this context
            notif->orig_dst_ip = details->dst_ip;     // Original Dest IP from connect4 hook
            notif->src_port = bpf_htons(src_port_h);   // Source port (network order)
            notif->orig_dst_port = details->dst_port; // Original Dest port from connect4 hook (network order)
            notif->protocol = IPPROTO_TCP;            // Assuming TCP
            bpf_ringbuf_submit(notif, 0);
            #ifdef DEBUG
            bpf_printk("SOCKOPS: Submitted notification to ring buffer.\n");
            #endif
        }
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";