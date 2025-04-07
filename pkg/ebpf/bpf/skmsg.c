#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_shared.h"

SEC("sk_msg")
int kernelgatekeeper_skmsg(struct sk_msg_md *msg) {
    __u32 sock_cookie = bpf_get_socket_cookie(msg->sk);
     if (sock_cookie == 0) {
         #ifdef DEBUG
         bpf_printk("SKMSG: Failed to get socket cookie for msg->sk\n");
         #endif
         return SK_DROP;
     }

    #ifdef DEBUG
    // bpf_printk("SKMSG: Triggered on sock cookie %u, size %u\n", sock_cookie, msg->size);
    #endif

    int ret = bpf_msg_redirect_map(msg, &proxy_sock_map, sock_cookie, BPF_F_INGRESS);

    if (ret == SK_DROP) {
        #ifdef DEBUG
         bpf_printk("SKMSG: Dropped message for cookie %u, peer likely closed or map error: %d\n", sock_cookie, ret);
        #endif
    } else if (ret == SK_PASS) {
        #ifdef DEBUG
         bpf_printk("SKMSG: Passed message (no redirect target?) for cookie %u: %d\n", sock_cookie, ret);
        #endif
    } else {
        #ifdef DEBUG
         bpf_printk("SKMSG: Unexpected return code from redirect_map for cookie %u: %d\n", sock_cookie, ret);
        #endif
    }

    return ret;
}

char _license[] SEC("license") = "GPL";