//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_shared.h"

SEC("sk_msg")
int kernelgatekeeper_skmsg(struct sk_msg_md *msg) {

	#ifdef DEBUG
	#endif

	int ret = bpf_msg_redirect_map(msg, &proxy_sock_map, 0, BPF_F_INGRESS);

	if (ret == SK_DROP) {
		#ifdef DEBUG
		 bpf_printk("SKMSG: Dropped message, peer likely closed or map error: %d\n", ret);
		#endif
	} else if (ret == SK_PASS) {
		#ifdef DEBUG
		 bpf_printk("SKMSG: Passed message (no redirect target?) ret: %d\n", ret);
		#endif
	}

	return ret;
}

char _license[] SEC("license") = "GPL";