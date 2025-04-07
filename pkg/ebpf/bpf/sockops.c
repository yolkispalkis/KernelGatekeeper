#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/socket.h>
#include <linux/in.h>

#include "bpf_shared.h"

#ifndef AF_INET
#define AF_INET 2
#endif

static __always_inline int extract_tuple(struct bpf_sock_ops *skops, struct connection_tuple_t *tuple) {
    if (skops->family != AF_INET) {
        return -1;
    }

    if (skops->local_port == 0 || skops->remote_port == 0) {
        bpf_printk("SOCKOPS_ERR: Zero port detected in skops struct before assignment: src=%u dst=%u. Cannot create valid tuple.\n",
                   (__u16)skops->local_port, (__u16)skops->remote_port);
        return -1;
    }

    tuple->src_ip = skops->local_ip4;
    tuple->dst_ip = skops->remote_ip4;
    tuple->src_port = bpf_htons(skops->local_port);
    tuple->dst_port = bpf_htons(skops->remote_port);
    tuple->protocol = IPPROTO_TCP;
    tuple->padding[0] = 0; tuple->padding[1] = 0; tuple->padding[2] = 0;

    bpf_printk("SOCKOPS: Extracted tuple OK: %x:%u -> %x:%u\n",
               bpf_ntohl(tuple->src_ip), bpf_ntohs(tuple->src_port),
               bpf_ntohl(tuple->dst_ip), bpf_ntohs(tuple->dst_port));

    return 0;
}

SEC("sockops")
int kernelgatekeeper_sockops(struct bpf_sock_ops *skops) {

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u16 op = skops->op;

    #ifdef DEBUG
    bpf_printk("SOCKOPS_DEBUG: family=%u op=%u local_port=%u remote_port=%u local_ip4=%x remote_ip4=%x reply=%u pid_tgid=%llu\n",
               skops->family, op, (__u16)skops->local_port, (__u16)skops->remote_port, skops->local_ip4, skops->remote_ip4, skops->reply, pid_tgid);
    #endif

    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    bpf_printk("SOCKOPS: ACTIVE_ESTABLISHED_CB triggered: pid_tgid=%llu local_port=%u remote_port=%u\n",
               pid_tgid, (__u16)skops->local_port, (__u16)skops->remote_port);

    if (pid_tgid == 0) {
        bpf_printk("SOCKOPS_WARN: Skipping ACTIVE_ESTABLISHED_CB due to pid_tgid=0 (invalid context).\n");
        return BPF_OK;
    }

    struct connection_tuple_t tuple = {};
    if (extract_tuple(skops, &tuple) != 0) {
        bpf_printk("SOCKOPS: Failed to extract tuple, skipping further processing for this connection.\n");
        return BPF_OK;
    }

    __u16 dst_port_h = bpf_ntohs(tuple.dst_port);
    __u8 *target = bpf_map_lookup_elem(&target_ports, &dst_port_h);
    if (!target || *target != 1) {
        #ifdef DEBUG
        bpf_printk("SOCKOPS: Port %u not targeted for proxying.\n", dst_port_h);
        #endif
        return BPF_OK;
    }

    bpf_printk("SOCKOPS: Connection MATCHED for proxying: pid=%llu port=%u\n", pid_tgid, dst_port_h);

    struct connection_state_t new_state = {
        .pid_tgid = pid_tgid,
    };
    int ret = bpf_map_update_elem(&connection_map, &tuple, &new_state, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS_ERR: Failed to update connection_map: %d\n", ret);
    }

    __u32 sock_cookie = bpf_get_socket_cookie(skops);
    if (sock_cookie == 0) {
         bpf_printk("SOCKOPS_ERR: Failed to get socket cookie for established connection.\n");
         bpf_map_delete_elem(&connection_map, &tuple);
         return BPF_OK;
    }

    ret = bpf_sock_map_update(skops, &proxy_sock_map, &sock_cookie, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS_ERR: Failed to update proxy_sock_map (sockmap): %d\n", ret);
        bpf_map_delete_elem(&connection_map, &tuple);
        return BPF_OK;
    }
    bpf_printk("SOCKOPS: Socket cookie %u added to proxy_sock_map (sockmap)\n", sock_cookie);

    struct connection_tuple_t *event_data = bpf_ringbuf_reserve(&notification_ringbuf, sizeof(struct connection_tuple_t), 0);
    if (!event_data) {
        bpf_printk("SOCKOPS_ERR: Failed to reserve space in ringbuf for notification\n");
    } else {
        __builtin_memcpy(event_data, &tuple, sizeof(struct connection_tuple_t));
        bpf_ringbuf_submit(event_data, 0);
        bpf_printk("SOCKOPS: Sent notification for matched connection to ringbuf\n");
    }

     __u32 stats_key_matched = 1;
     struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &stats_key_matched);
     if (stats) {
         __sync_fetch_and_add(&stats->packets, 1);
     }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";