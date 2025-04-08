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
			   skops->family, op, (__u16)skops->local_port, (__u16)skops->remote_port,
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

	struct connection_details_t *details = bpf_map_lookup_elem(&connection_details_map, &sock_cookie);
	if (!details) {
		#ifdef DEBUG
		bpf_printk("SOCKOPS_WARN: Connection details not found in map for cookie %llu (ACTIVE_ESTABLISHED_CB). Not redirecting.\n", sock_cookie);
		#endif
		return BPF_OK;
	}

	__u16 orig_dst_port_h = bpf_ntohs(details->orig_dst_port);
	__u8 *target_flag = bpf_map_lookup_elem(&target_ports, &orig_dst_port_h);

	if (!target_flag || *target_flag != 1) {
		#ifdef DEBUG
		bpf_printk("SOCKOPS_DEBUG: Original port %u not targeted (cookie %llu, ACTIVE_ESTABLISHED_CB).\n", orig_dst_port_h, sock_cookie);
		#endif
		return BPF_OK;
	}

	#ifdef DEBUG
	bpf_printk("SOCKOPS: Connection MATCHED original port %u (cookie %llu, ACTIVE_ESTABLISHED_CB): pid=%llu\n",
			   orig_dst_port_h, sock_cookie, details->pid_tgid);
	#endif

	int ret = bpf_sock_map_update(skops, &proxy_sock_map, &sock_cookie, BPF_ANY);
	if (ret != 0) {
		bpf_printk("SOCKOPS_ERR: Failed to update proxy_sock_map (sockmap) (cookie %llu, ACTIVE_ESTABLISHED_CB): %d\n", sock_cookie, ret);
	} else {
		 #ifdef DEBUG
		 bpf_printk("SOCKOPS: Socket cookie %llu added to proxy_sock_map for redirection (ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
		 #endif
	}

	struct notification_tuple_t *event_data = bpf_ringbuf_reserve(&notification_ringbuf, sizeof(struct notification_tuple_t), 0);
	if (!event_data) {
		bpf_printk("SOCKOPS_ERR: Failed to reserve ringbuf space (cookie %llu, ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
	} else {
		event_data->pid_tgid      = details->pid_tgid;
		event_data->src_ip        = skops->local_ip4;
		event_data->src_port      = bpf_htons((__u16)skops->local_port);
		event_data->orig_dst_ip   = details->orig_dst_ip;
		event_data->orig_dst_port = details->orig_dst_port;
		event_data->protocol      = details->protocol;

		__builtin_memset(event_data->padding, 0, sizeof(event_data->padding));

		bpf_ringbuf_submit(event_data, 0);
		#ifdef DEBUG
		 bpf_printk("SOCKOPS: Sent notification to ringbuf (cookie %llu, ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
		#endif
	}

	__u32 stats_key_matched = 1;
	struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &stats_key_matched);
	if (stats) {
		__sync_fetch_and_add(&stats->packets, 1);
	}

	return BPF_OK;
}

char _license[] SEC("license") = "GPL";