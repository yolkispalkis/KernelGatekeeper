//go:build ignore

#include <linux/bpf.h>
#include <linux/types.h>    // For __u* types
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/socket.h>   // For AF_INET
#include <linux/in.h>       // For IPPROTO_TCP
#include "bpf_shared.h"     // Include the updated shared definitions

// Define constants if not already available in headers
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 1 // Callback for active established connections
#endif
#ifndef BPF_OK
#define BPF_OK 0 // Return code for sockops to allow operation
#endif

// Attach to the cgroup sockops hook, specifically reacting to established connections
SEC("sockops")
int kernelgatekeeper_sockops(struct bpf_sock_ops *skops) {

    // Extract the operation type (e.g., connection established, state change, etc.)
    __u16 op = skops->op;

    // Basic debug print of the received sock_ops context
    #ifdef DEBUG
    bpf_printk("SOCKOPS_DEBUG: family=%u op=%u lport=%u rport=%u lip4=%x rip4=%x reply=%u pid=%llu\n",
               skops->family, op, (__u16)skops->local_port, (__u16)skops->remote_port,
               skops->local_ip4, skops->remote_ip4, skops->reply, bpf_get_current_pid_tgid());
    #endif

    // We are only interested when an *outgoing* connection becomes established.
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK; // Allow other operations to proceed normally
    }

    // Check if it's an IPv4 connection (update for IPv6 if needed later)
    if (skops->family != AF_INET) {
         #ifdef DEBUG
         bpf_printk("SOCKOPS: Ignoring non-AF_INET established connection.\n");
         #endif
        return BPF_OK;
    }

    // --- Get Socket Cookie ---
    // The cookie uniquely identifies the socket involved in this operation.
    __u64 sock_cookie = bpf_get_socket_cookie(skops);
    if (sock_cookie == 0) {
         // If we can't get a cookie, we cannot correlate with the connect4 hook data.
         #ifdef DEBUG
         bpf_printk("SOCKOPS_ERR: Failed to get socket cookie (ACTIVE_ESTABLISHED_CB).\n");
         #endif
         return BPF_OK; // Allow connection, but cannot process further
    }

    // --- Retrieve Original Destination Details ---
    // Look up the details stored by the connect4 hook using the socket cookie.
    struct connection_details_t *details = bpf_map_lookup_elem(&connection_details_map, &sock_cookie);
    if (!details) {
        // This means the connect4 hook didn't store details for this cookie,
        // possibly due to map limits, errors, or the connection originating differently.
        #ifdef DEBUG
        bpf_printk("SOCKOPS_WARN: Connection details not found in map for cookie %llu (ACTIVE_ESTABLISHED_CB). Not redirecting.\n", sock_cookie);
        #endif
        return BPF_OK; // Allow connection, but cannot redirect as target port is unknown
    }

    // --- Check if Original Destination Port is Targeted ---
    // Convert the *original* destination port (stored in Network Byte Order)
    // to Host Byte Order for the lookup in the `target_ports` map.
    __u16 orig_dst_port_h = bpf_ntohs(details->orig_dst_port);
    __u8 *target_flag = bpf_map_lookup_elem(&target_ports, &orig_dst_port_h);

    if (!target_flag || *target_flag != 1) {
        // The original destination port is not in our list of ports to proxy.
        #ifdef DEBUG
        bpf_printk("SOCKOPS_DEBUG: Original port %u not targeted (cookie %llu, ACTIVE_ESTABLISHED_CB).\n", orig_dst_port_h, sock_cookie);
        #endif
        // Clean up the details map entry now that we know we won't redirect? (Optional, LRU might handle it)
        // bpf_map_delete_elem(&connection_details_map, &sock_cookie);
        return BPF_OK; // Allow the connection to proceed directly
    }

    // --- Connection Matched: Redirect and Notify ---
    #ifdef DEBUG
    bpf_printk("SOCKOPS: Connection MATCHED original port %u (cookie %llu, ACTIVE_ESTABLISHED_CB): pid=%llu\n",
               orig_dst_port_h, sock_cookie, details->pid_tgid);
    #endif

    // 1. Update Sockmap for Redirection
    // Add this socket's cookie to the sockmap. The sk_msg hook will use this
    // to redirect traffic associated with this cookie to the peer socket (the userspace client).
    int ret = bpf_sock_map_update(skops, &proxy_sock_map, &sock_cookie, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS_ERR: Failed to update proxy_sock_map (sockmap) (cookie %llu, ACTIVE_ESTABLISHED_CB): %d\n", sock_cookie, ret);
        // If sockmap update fails, redirection won't work. We might still send the notification,
        // but the client won't receive the connection via sockmap. Decide if notification is still useful.
        // For now, continue to send notification even if sockmap update fails.
    } else {
         #ifdef DEBUG
         bpf_printk("SOCKOPS: Socket cookie %llu added to proxy_sock_map for redirection (ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
         #endif
    }

    // 2. Send Notification via Ring Buffer
    // Reserve space in the ring buffer for the notification tuple.
    struct notification_tuple_t *event_data = bpf_ringbuf_reserve(&notification_ringbuf, sizeof(struct notification_tuple_t), 0);
    if (!event_data) {
        bpf_printk("SOCKOPS_ERR: Failed to reserve ringbuf space (cookie %llu, ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
    } else {
        // Populate the notification structure with relevant details.
        event_data->pid_tgid      = details->pid_tgid;
        event_data->src_ip        = skops->local_ip4;     // Current source IP (Network Order from skops)
        event_data->src_port      = bpf_htons((__u16)skops->local_port); // Current source port (Host Order from skops -> Network Order)
        event_data->orig_dst_ip   = details->orig_dst_ip;     // Original destination IP (already Network Order)
        event_data->orig_dst_port = details->orig_dst_port; // Original destination Port (already Network Order)
        event_data->protocol      = details->protocol;      // Protocol from stored details

        // Ensure padding is zeroed (important for consistency if userspace reads it)
        __builtin_memset(event_data->padding, 0, sizeof(event_data->padding));

        // Submit the event to the ring buffer.
        bpf_ringbuf_submit(event_data, 0);
        #ifdef DEBUG
         bpf_printk("SOCKOPS: Sent notification to ringbuf (cookie %llu, ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
        #endif
    }

    // 3. Update Statistics (Optional)
    __u32 stats_key_matched = 1; // Assuming key 1 is for matched connections
    struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &stats_key_matched);
    if (stats) {
        // Atomically increment the packet counter (representing matched connections)
        __sync_fetch_and_add(&stats->packets, 1);
    }

    // Optional: Clean up the details map entry now that notification is sent.
    // Leaving it allows potential future lookups if needed, LRU handles cleanup eventually.
    // bpf_map_delete_elem(&connection_details_map, &sock_cookie);

    return BPF_OK; // Allow the operation (which now includes sockmap update)
}

// Define the license for the BPF program
char _license[] SEC("license") = "GPL";