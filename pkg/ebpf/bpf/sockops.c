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
	// Log general sockops entry details in debug mode
	// Note: IPs and ports might be 0 depending on the 'op'
	//       For ACTIVE_ESTABLISHED_CB, remote_ip4 and remote_port should be set.
	bpf_printk("SOCKOPS_DEBUG: family=%u op=%u lport=%u rport=%u lip4=%x rip4=%x reply=%u pid=%llu\n",
			   skops->family, op, (__u16)skops->local_port, bpf_ntohs(skops->remote_port_opt), // Use remote_port_opt for network byte order port
			   skops->local_ip4, skops->remote_ip4, skops->reply, bpf_get_current_pid_tgid());
	#endif

	// We are only interested in established IPv4 TCP connections for redirection
	if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
		return BPF_OK;
	}

	if (skops->family != AF_INET) {
		 #ifdef DEBUG
		 bpf_printk("SOCKOPS: Ignoring non-AF_INET established connection.\n");
		 #endif
		return BPF_OK;
	}

	// Retrieve the socket cookie
	__u64 sock_cookie = bpf_get_socket_cookie(skops);
	if (sock_cookie == 0) {
		 #ifdef DEBUG
		 // Note: Getting cookie might fail early in connection setup, but should work for ACTIVE_ESTABLISHED_CB
		 bpf_printk("SOCKOPS_ERR: Failed to get socket cookie (ACTIVE_ESTABLISHED_CB).\n");
		 #endif
		 return BPF_OK;
	}

	// Look up the connection details saved by the connect4 hook
	struct connection_details_t *details = bpf_map_lookup_elem(&connection_details_map, &sock_cookie);
	if (!details) {
		#ifdef DEBUG
		// This might happen if the connect4 hook didn't run or map entry was evicted
		bpf_printk("SOCKOPS_WARN: Connection details not found in map for cookie %llu (ACTIVE_ESTABLISHED_CB). Not redirecting.\n", sock_cookie);
		#endif
		return BPF_OK; // Cannot proceed without original destination details
	}

	// Check if the original destination port is one we want to proxy
	__u16 orig_dst_port_h = bpf_ntohs(details->orig_dst_port); // Convert to host byte order for map lookup
	__u8 *target_flag = bpf_map_lookup_elem(&target_ports, &orig_dst_port_h);

	if (!target_flag || *target_flag != 1) {
		#ifdef DEBUG
		bpf_printk("SOCKOPS_DEBUG: Original port %u not targeted (cookie %llu, ACTIVE_ESTABLISHED_CB).\n", orig_dst_port_h, sock_cookie);
		#endif
		// Don't remove from connection_details_map here, let LRU handle it or it might be needed by other hooks.
		return BPF_OK; // Port not targeted for proxying
	}

	#ifdef DEBUG
	// Connection is targeted for redirection
	bpf_printk("SOCKOPS: Connection MATCHED original port %u (cookie %llu, ACTIVE_ESTABLISHED_CB): pid=%llu\n",
			   orig_dst_port_h, sock_cookie, details->pid_tgid);
	#endif

	// --- Attempt to add the socket to the sockmap for redirection ---
	int ret = bpf_sock_map_update(skops, &proxy_sock_map, &sock_cookie, BPF_ANY);
	if (ret != 0) {
		// Log the error if the update fails
		bpf_printk("SOCKOPS_ERR: Failed to update proxy_sock_map (sockmap) (cookie %llu, ACTIVE_ESTABLISHED_CB): %d\n", sock_cookie, ret);
		// !!! IMPORTANT FIX: Do not send notification if sockmap update failed !!!
		// Removing from connection_details_map might be considered, but risks races. Let LRU handle it.
		return BPF_OK; // Exit program, cannot proceed with redirection
	}

	// --- Sockmap update succeeded, now send notification to userspace ---
	#ifdef DEBUG
	bpf_printk("SOCKOPS: Socket cookie %llu added to proxy_sock_map for redirection (ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
	#endif

	// Reserve space in the ring buffer for the notification event
	struct notification_tuple_t *event_data = bpf_ringbuf_reserve(&notification_ringbuf, sizeof(struct notification_tuple_t), 0);
	if (!event_data) {
		// Failed to reserve space, log error but connection is already in sockmap
		bpf_printk("SOCKOPS_ERR: Failed to reserve ringbuf space (cookie %llu, ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
		// We don't remove from sockmap here, as it might still work, but userspace won't know.
		// This might lead to a stuck connection if the client relies solely on notification.
	} else {
		// Populate the notification data
		event_data->pid_tgid      = details->pid_tgid;
		event_data->src_ip        = skops->local_ip4;          // Use actual local IP from sock_ops
		event_data->src_port      = skops->local_port_opt;     // Use actual local port (network byte order)
		event_data->orig_dst_ip   = details->orig_dst_ip;      // Original destination IP from connect4 map
		event_data->orig_dst_port = details->orig_dst_port;    // Original destination port from connect4 map
		event_data->protocol      = details->protocol;         // Protocol (TCP)

		// Ensure padding is zeroed (good practice)
		__builtin_memset(event_data->padding, 0, sizeof(event_data->padding));

		// Submit the event to the ring buffer
		bpf_ringbuf_submit(event_data, 0);
		#ifdef DEBUG
		 bpf_printk("SOCKOPS: Sent notification to ringbuf (cookie %llu, ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
		#endif
	}

	// Optionally update statistics for matched connections
	__u32 stats_key_matched = 1; // Assuming key 1 is for matched/redirected connections
	struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &stats_key_matched);
	if (stats) {
		// Atomically increment the packet count (representing a connection here)
		__sync_fetch_and_add(&stats->packets, 1);
		// We don't have byte counts at this stage
	}

	// Remove the entry from the connection details map now that we've processed it?
	// bpf_map_delete_elem(&connection_details_map, &sock_cookie); // Consider implications (races, map pressure vs LRU)
	// For now, rely on LRU eviction.

	return BPF_OK; // Indicate success
}

char _license[] SEC("license") = "GPL";