#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_shared.h"

// Remove the custom bpf_printk definition block entirely
/*
#ifdef DEBUG
#define bpf_printk(fmt, ...)                                   \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#else
#define bpf_printk(fmt, ...)
#endif
*/


SEC("sk_msg")
int kernelgatekeeper_skmsg(struct sk_msg_md *msg) {
    // Use standard bpf_printk if needed for debugging
    // bpf_printk("SKMSG: Triggered on sock cookie %u, size %u\n", msg->sk->cookie, msg->size); // sk->cookie might not be reliable

    // Get socket cookie using helper
    __u32 sock_cookie = bpf_get_socket_cookie(msg->sk);
     if (sock_cookie == 0) {
         // Use standard bpf_printk
         bpf_printk("SKMSG: Failed to get socket cookie for msg->sk\n");
         return SK_DROP; // Cannot redirect without cookie
     }
     // bpf_printk("SKMSG: Triggered on sock cookie %u, size %u\n", sock_cookie, msg->size);

    // Use helper to redirect based on cookie key, pass pointer to map definition
    int ret = bpf_msg_redirect_hash(msg, &proxy_sock_map, &sock_cookie, BPF_F_INGRESS);

    if (ret == SK_DROP) {
         // Use standard bpf_printk
         bpf_printk("SKMSG: Dropped message for cookie %u, peer likely closed or map error: %d\n", sock_cookie, ret);
    } else if (ret == SK_PASS) {
        // bpf_printk("SKMSG: Message passed to peer socket for cookie %u\n", sock_cookie);
    } else {
         // Use standard bpf_printk
         bpf_printk("SKMSG: Unexpected return code from redirect for cookie %u: %d\n", sock_cookie, ret);
    }

    return ret;
}

char _license[] SEC("license") = "GPL";