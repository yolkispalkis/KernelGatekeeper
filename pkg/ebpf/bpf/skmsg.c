#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_shared.h"

SEC("sk_msg")
int kernelgatekeeper_skmsg(struct sk_msg_md *msg) {
    /*
     * We don't need (and cannot) call bpf_get_socket_cookie() here.
     * The bpf_msg_redirect_map() helper, when used with a BPF_MAP_TYPE_SOCKHASH map,
     * implicitly uses the cookie of the socket associated with 'msg' (msg->sk)
     * as the key to find the peer socket in the map.
     * The 'key' argument (3rd arg) is ignored in this case and should be 0.
     */

    #ifdef DEBUG
    // Retrieve the cookie only for logging if absolutely necessary (and if allowed in future kernels?)
    // For now, rely on the implicit behavior.
    // bpf_printk("SKMSG: Triggered on implicit socket cookie, size %u\n", msg->size);
    #endif

    int ret = bpf_msg_redirect_map(msg, &proxy_sock_map, 0, BPF_F_INGRESS);

    // Existing logging for the return code is fine
    if (ret == SK_DROP) {
        #ifdef DEBUG
         bpf_printk("SKMSG: Dropped message, peer likely closed or map error: %d\n", ret);
        #endif
    } else if (ret == SK_PASS) {
        #ifdef DEBUG
         // Pass usually means the socket wasn't found in the map for redirection
         bpf_printk("SKMSG: Passed message (no redirect target?) ret: %d\n", ret);
        #endif
    }
    // Removed redundant else/debug printk from original code for unexpected codes

    return ret;
}

char _license[] SEC("license") = "GPL";