// FILE: pkg/ebpf/bpf/sockops.c
//go:build ignore

// Includes for CO-RE
#include "vmlinux.h"        // Generated kernel types (might not be strictly needed if not accessing sk fields directly)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Custom shared definitions
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
    // Reduced verbosity slightly for potentially high-frequency logs
    // bpf_printk("SOCKOPS_DEBUG: family=%u op=%u lport=%u rport=%u lip4=%x rip4=%x reply=%u pid=%llu\n",
    //            skops->family, op, (__u16)skops->local_port, bpf_ntohs(skops->remote_port),
    //            skops->local_ip4, skops->remote_ip4, skops->reply, bpf_get_current_pid_tgid());
    #endif

    // We are only interested in established connections initiated by the client (active side)
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    // Only handle IPv4 for now
    if (skops->family != AF_INET) {
         #ifdef DEBUG
         // bpf_printk("SOCKOPS: Ignoring non-AF_INET established connection.\n");
         #endif
        return BPF_OK;
    }

    // Get the cookie associated with the socket
    __u64 sock_cookie = bpf_get_socket_cookie(skops);
    if (sock_cookie == 0) {
         #ifdef DEBUG
         bpf_printk("SOCKOPS_ERR: Failed to get socket cookie (ACTIVE_ESTABLISHED_CB).\n");
         #endif
         return BPF_OK; // Cannot proceed without cookie
    }

    // Look up the original destination details stored by connect4 using the cookie
    struct original_dest_t *details = bpf_map_lookup_elem(&kg_orig_dest, &sock_cookie);
    if (!details) {
        // This connection wasn't redirected by connect4, or details were cleaned up. Ignore.
        #ifdef DEBUG
        // Frequent log, maybe disable unless needed:
        // bpf_printk("SOCKOPS_DEBUG: No original dest found for cookie %llu, likely not redirected by connect4.\n", sock_cookie);
        #endif
        return BPF_OK;
    }

    // Log PID immediately after lookup
    #ifdef DEBUG
    bpf_printk("SOCKOPS_READ: Read details for Cookie=%llu, PID in details=%u\n", sock_cookie, details->pid);
    #endif

    // Check if PID is 0 after reading
    if (details->pid == 0) {
        bpf_printk("SOCKOPS_WARN: PID read from kg_orig_dest map is 0 for Cookie=%llu. Skipping notification.\n", sock_cookie);
        // Optionally delete the map entry? Depends if getsockopt still needs it.
        // For now, just skip notification.
        return BPF_OK;
    }


    // Key for the port_to_cookie map is the source port (local port in sockops context)
    __u16 src_port_h = (__u16)skops->local_port; // Source port (Host Byte Order)

    // Store the mapping from source port -> original destination cookie
    // This allows the getsockopt hook to find the original destination later
    int ret = bpf_map_update_elem(&kg_port_to_cookie, &src_port_h, &sock_cookie, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS_ERR: Failed to update kg_port_to_cookie (port %u, cookie %llu): %d\n", src_port_h, sock_cookie, ret);
        // Clean up the original destination entry if port mapping fails to avoid dangling entries
        bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
    } else {
        #ifdef DEBUG
        // bpf_printk("SOCKOPS: Stored port->cookie mapping (%u -> %llu)\n", src_port_h, sock_cookie);
        #endif

        // Send notification to userspace via ring buffer
        struct notification_tuple_t *notif;
        notif = bpf_ringbuf_reserve(&kg_notif_rb, sizeof(*notif), 0);
        if (!notif) {
            bpf_printk("SOCKOPS_ERR: Failed to reserve space in ring buffer for notification.\n");
            // If reserve fails, should we clean up maps? Maybe not immediately, could retry later.
        } else {
            // Log PID just before submitting
            #ifdef DEBUG
            bpf_printk("SOCKOPS_SUBMIT: Submitting notification for PID=%u (from details), Cookie=%llu\n", details->pid, sock_cookie);
            #endif

            notif->pid_tgid = (__u64)details->pid; // Use PID from details
            notif->src_ip = skops->local_ip4;         // Source IP is local IP in this context (the app's IP)
            notif->orig_dst_ip = details->dst_ip;     // Original Dest IP from connect4 hook
            notif->src_port = bpf_htons(src_port_h);   // Source port (network order)
            notif->orig_dst_port = details->dst_port; // Original Dest port from connect4 hook (network order)
            notif->protocol = IPPROTO_TCP;            // Assuming TCP

            bpf_ringbuf_submit(notif, 0);
        }
    }

    // The connection establishment should proceed normally (to the client listener)
    return BPF_OK;
}

char _license[] SEC("license") = "GPL";