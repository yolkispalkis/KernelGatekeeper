// FILE: pkg/ebpf/bpf/sockops.c
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_shared.h" // Includes definitions for kg_orig_dest, kg_redir_sport_to_orig

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 1
#endif
#ifndef BPF_OK
#define BPF_OK 0
#endif

SEC("sockops")
int kernelgatekeeper_sockops(struct bpf_sock_ops *skops) {
    __u16 op;
    __u16 family;
    __u64 sock_cookie;
    struct original_dest_t *orig_dest_details;
    struct original_dest_t details_copy = {}; // Make a copy to insert into the new map
    __u16 redir_src_port_h; // Source port of the redirected connection (host byte order)
    int ret;
    // For ring buffer notification (optional, maybe remove if getsockopt is reliable)
    // struct notification_tuple_t *notif;
    // __u32 local_ip4;

    // Read op and family safely
    if (bpf_core_read(&op, sizeof(op), &skops->op)) return BPF_OK;
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) return BPF_OK;
    if (bpf_core_read(&family, sizeof(family), &skops->family)) return BPF_OK;
    if (family != AF_INET) return BPF_OK;

    // Get the socket cookie
    sock_cookie = bpf_get_socket_cookie(skops);
    if (sock_cookie == 0) {
        #ifdef DEBUG
        bpf_printk("SOCKOPS_ERR: Failed to get socket cookie (ACTIVE_ESTABLISHED_CB).\n");
        #endif
        // Cannot proceed without cookie
        kg_stats_inc(5); // sockops_pass_fail
        return BPF_OK;
    }

    // Find the original destination details stored by connect4
    orig_dest_details = bpf_map_lookup_elem(&kg_orig_dest, &sock_cookie);
    if (!orig_dest_details) {
        // Not a connection we redirected or entry already processed/deleted.
        return BPF_OK;
    }

    // Read the source port of the *redirected* connection (Host Byte Order)
    // Read directly skops->local_port (which is u32) and cast
    __u32 local_port_u32;
     if (bpf_core_read(&local_port_u32, sizeof(local_port_u32), &skops->local_port)) {
        #ifdef DEBUG
        bpf_printk("SOCKOPS_ERR: Failed to read skops->local_port for cookie %llu\n", sock_cookie);
        #endif
        // Clean up original entry if we can't proceed
        bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
        kg_stats_inc(5); // sockops_pass_fail
        return BPF_OK;
    }
    redir_src_port_h = (__u16)local_port_u32; // Get lower 16 bits

    // Make a copy of the original destination details before deleting
    // Use bpf_core_read to safely copy the struct fields
    bpf_core_read(&details_copy.dst_ip, sizeof(details_copy.dst_ip), &orig_dest_details->dst_ip);
    bpf_core_read(&details_copy.dst_port, sizeof(details_copy.dst_port), &orig_dest_details->dst_port);
    bpf_core_read(&details_copy.pid, sizeof(details_copy.pid), &orig_dest_details->pid);
    bpf_core_read(&details_copy.uid, sizeof(details_copy.uid), &orig_dest_details->uid);

    // Store the original destination details in the new map, keyed by the redirected source port
    ret = bpf_map_update_elem(&kg_redir_sport_to_orig, &redir_src_port_h, &details_copy, BPF_ANY);
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("SOCKOPS_ERR: Failed update kg_redir_sport_to_orig (key/port %u, cookie %llu): %d\n",
                  redir_src_port_h, sock_cookie, ret);
        #endif
        // Clean up original entry if we failed to pass info forward
        bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
        kg_stats_inc(5); // sockops_pass_fail
        return BPF_OK;
    }

    // IMPORTANT: Delete the entry from the original map now that we've passed the info
    bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
    kg_stats_inc(4); // sockops_pass_ok

    #ifdef DEBUG
    bpf_printk("SOCKOPS_PASS: Passed orig dest info for cookie %llu via redir_port %u\n",
              sock_cookie, redir_src_port_h);
    #endif

    // Optional: Send ring buffer notification (maybe as backup or for richer info)
    /*
    // Get local IP for notification (optional)
    if (bpf_core_read(&local_ip4, sizeof(local_ip4), &skops->local_ip4)) {
        local_ip4 = 0;
    }
    notif = bpf_ringbuf_reserve(&kg_notif_rb, sizeof(*notif), 0);
    if (!notif) {
        bpf_printk("SOCKOPS_ERR: Failed reserve ringbuf space (cookie %llu)\n", sock_cookie);
    } else {
        notif->pid_tgid = (__u64)details_copy.pid << 32 | details_copy.pid; // Example using pid
        notif->src_ip = local_ip4;
        notif->orig_dst_ip = details_copy.dst_ip;
        notif->src_port = bpf_htons(redir_src_port_h); // Port of redirected conn
        notif->orig_dst_port = details_copy.dst_port;
        notif->protocol = IPPROTO_TCP; // Assuming TCP
        bpf_ringbuf_submit(notif, 0);
        #ifdef DEBUG
        bpf_printk("SOCKOPS_NOTIF: Sent notification via ringbuf for redir_port %u\n", redir_src_port_h);
        #endif
    }
    */

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";