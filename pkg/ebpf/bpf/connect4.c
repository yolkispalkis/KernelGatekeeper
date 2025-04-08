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

SEC("cgroup/connect4")
int kernelgatekeeper_connect4(struct bpf_sock_addr *ctx) {
	if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP) {
		return 1;
	}

	__u64 cookie = bpf_get_socket_cookie(ctx);
	if (cookie == 0) {
		#ifdef DEBUG
		bpf_printk("CONNECT4_ERR: Failed to get socket cookie.\n");
		#endif
		return 1;
	}

	struct connection_details_t details = {};
	details.pid_tgid = bpf_get_current_pid_tgid();
	details.orig_dst_ip = ctx->user_ip4;
	details.orig_dst_port = ctx->user_port;
	details.protocol = ctx->protocol;

	int ret = bpf_map_update_elem(&connection_details_map, &cookie, &details, BPF_ANY);
	if (ret != 0) {
		#ifdef DEBUG
		bpf_printk("CONNECT4_ERR: Failed to update connection_details_map (cookie %llu): %d\n", cookie, ret);
		#endif
	} else {
		 #ifdef DEBUG
		 bpf_printk("CONNECT4: Stored details cookie %llu (orig_dst=%x:%u pid=%llu)\n",
					cookie, details.orig_dst_ip, bpf_ntohs(details.orig_dst_port), details.pid_tgid);
		 #endif
	}

	return 1;
}

char _license[] SEC("license") = "GPL";