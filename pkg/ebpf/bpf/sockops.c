#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/socket.h>
#include <linux/in.h>


#include "bpf_shared.h"

#ifndef AF_INET
#define AF_INET 2
#endif

// Defined op codes if not available in older headers
#ifndef BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 1
#endif

static __always_inline int extract_tuple(struct bpf_sock_ops *skops, struct connection_tuple_t *tuple) {
    if (skops->family != AF_INET) {
        return -1;
    }

    // Use bpf_ntohl on skops fields as they are network byte order
    tuple->src_ip = skops->local_ip4;
    tuple->dst_ip = skops->remote_ip4;

    // skops->[local|remote]_port is host byte order, need conversion using bpf_htons
    tuple->src_port = bpf_htons((__u16)skops->local_port);
    tuple->dst_port = bpf_htons((__u16)skops->remote_port);

    // Check for zero destination port *after* potential extraction
    if (skops->remote_port == 0) {
         bpf_printk("SOCKOPS_ERR: Zero remote_port detected in extract_tuple (L:%u, R:%u). Cannot create valid tuple.\n",
                   skops->local_port, skops->remote_port);
        return -1;
    }
     if (skops->local_port == 0) {
         bpf_printk("SOCKOPS_ERR: Zero local_port detected in extract_tuple (L:%u, R:%u).\n",
                   skops->local_port, skops->remote_port);
        // Allow local port 0 for some cases? Or fail? Let's fail for now.
        return -1;
    }

    if (tuple->src_ip == 0 || tuple->dst_ip == 0) {
        bpf_printk("SOCKOPS_ERR: Zero IP address detected in extract_tuple (src=%x, dst=%x).\n", tuple->src_ip, tuple->dst_ip);
        return -1;
    }


    tuple->protocol = IPPROTO_TCP;
    tuple->padding[0] = 0; tuple->padding[1] = 0; tuple->padding[2] = 0;


    #ifdef DEBUG
    // Print IPs in readable format after conversion
    bpf_printk("SOCKOPS: Extracted tuple OK (from skops): %x:%u -> %x:%u\n",
               bpf_ntohl(tuple->src_ip), bpf_ntohs(tuple->src_port),
               bpf_ntohl(tuple->dst_ip), bpf_ntohs(tuple->dst_port));
    #endif

    return 0;
}

SEC("sockops")
int kernelgatekeeper_sockops(struct bpf_sock_ops *skops) {

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u16 op = skops->op;

    #ifdef DEBUG
    bpf_printk("SOCKOPS_DEBUG: family=%u op=%u lport_skops=%u rport_skops=%u lip4=%x rip4=%x reply=%u pid=%llu\n",
               skops->family, op, (__u16)skops->local_port, (__u16)skops->remote_port, skops->local_ip4, skops->remote_ip4, skops->reply, pid_tgid);
    #endif

    // --- MODIFIED: Check for ACTIVE_ESTABLISHED_CB instead ---
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK; // Ignore other operations
    }
    // --- END MODIFICATION ---

    bpf_printk("SOCKOPS: ACTIVE_ESTABLISHED_CB triggered: pid_tgid=%llu\n", pid_tgid);

    if (pid_tgid == 0) {
        bpf_printk("SOCKOPS_WARN: Skipping ACTIVE_ESTABLISHED_CB due to pid_tgid=0.\n");
        return BPF_OK;
    }

    struct connection_tuple_t tuple = {};

    // --- MODIFIED: Updated log message ---
    if (extract_tuple(skops, &tuple) != 0) {
        bpf_printk("SOCKOPS_ERR: Failed to extract tuple in ACTIVE_ESTABLISHED_CB using skops, skipping.\n");
        return BPF_OK;
    }
    // --- END MODIFICATION ---

    // Destination port is already in network byte order in the tuple struct
    // But for map lookup, we need host byte order key
    __u16 dst_port_h = bpf_ntohs(tuple.dst_port);
    __u8 *target = bpf_map_lookup_elem(&target_ports, &dst_port_h);
    if (!target || *target != 1) {
        #ifdef DEBUG
        // --- MODIFIED: Updated log message ---
        bpf_printk("SOCKOPS_DEBUG: Port %u not targeted (ACTIVE_ESTABLISHED_CB).\n", dst_port_h);
        // --- END MODIFICATION ---
        #endif
        return BPF_OK;
    }

    // --- MODIFIED: Updated log message ---
    bpf_printk("SOCKOPS: Connection MATCHED (ACTIVE_ESTABLISHED_CB): pid=%llu port=%u\n", pid_tgid, dst_port_h);
    // --- END MODIFICATION ---

    struct connection_state_t new_state = { .pid_tgid = pid_tgid };
    int ret = bpf_map_update_elem(&connection_map, &tuple, &new_state, BPF_ANY);
    if (ret != 0) {
        // --- MODIFIED: Updated log message ---
        bpf_printk("SOCKOPS_ERR: Failed to update connection_map (ACTIVE_ESTABLISHED_CB): %d\n", ret);
        // --- END MODIFICATION ---
    }

    __u32 sock_cookie = bpf_get_socket_cookie(skops);
    if (sock_cookie == 0) {
         // --- MODIFIED: Updated log message ---
         bpf_printk("SOCKOPS_ERR: Failed to get socket cookie (ACTIVE_ESTABLISHED_CB).\n");
         // --- END MODIFICATION ---
         return BPF_OK;
    }

    ret = bpf_sock_map_update(skops, &proxy_sock_map, &sock_cookie, BPF_ANY);
    if (ret != 0) {
        // --- MODIFIED: Updated log message ---
        bpf_printk("SOCKOPS_ERR: Failed to update proxy_sock_map (sockmap) (ACTIVE_ESTABLISHED_CB): %d\n", ret);
        // --- END MODIFICATION ---
        return BPF_OK;
    }
     // --- MODIFIED: Updated log message ---
    bpf_printk("SOCKOPS: Socket cookie %u added to proxy_sock_map (ACTIVE_ESTABLISHED_CB)\n", sock_cookie);
    // --- END MODIFICATION ---

    struct connection_tuple_t *event_data = bpf_ringbuf_reserve(&notification_ringbuf, sizeof(struct connection_tuple_t), 0);
    if (!event_data) {
        // --- MODIFIED: Updated log message ---
        bpf_printk("SOCKOPS_ERR: Failed to reserve ringbuf space (ACTIVE_ESTABLISHED_CB)\n");
        // --- END MODIFICATION ---
    } else {
        __builtin_memcpy(event_data, &tuple, sizeof(struct connection_tuple_t));
        bpf_ringbuf_submit(event_data, 0);
        // --- MODIFIED: Updated log message ---
        bpf_printk("SOCKOPS: Sent notification to ringbuf (ACTIVE_ESTABLISHED_CB)\n");
        // --- END MODIFICATION ---
    }

     __u32 stats_key_matched = 1;
     struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &stats_key_matched);
     if (stats) {
         __sync_fetch_and_add(&stats->packets, 1);
     }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";