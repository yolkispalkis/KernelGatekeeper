#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/socket.h>
#include <linux/in.h>
// Не используем стандартные библиотеки C в eBPF программах

#include "bpf_shared.h"

// Explicit definition of socket constants that might not be properly included
#ifndef AF_INET
#define AF_INET 2
#endif

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

static __always_inline int extract_tuple(struct bpf_sock_ops *skops, struct connection_tuple_t *tuple) {
    // AF_INET is now defined via <linux/socket.h>
    if (skops->family != AF_INET) {
        return -1;
    }

    tuple->src_ip = skops->local_ip4;
    tuple->dst_ip = skops->remote_ip4;
    // bpf_htons is fine
    tuple->src_port = bpf_htons(skops->local_port);
    tuple->dst_port = bpf_htons(skops->remote_port);
    // IPPROTO_TCP is now defined via <linux/in.h>
    tuple->protocol = IPPROTO_TCP; // Sockops for TCP only
    tuple->padding[0] = 0; tuple->padding[1] = 0; tuple->padding[2] = 0;

    if (tuple->src_port == 0 || tuple->dst_port == 0) {
         // Use the standard bpf_printk helper now
         bpf_printk("SOCKOPS: Zero port detected src=%u dst=%u\n", bpf_ntohs(tuple->src_port), bpf_ntohs(tuple->dst_port));
        return -1;
    }

    bpf_printk("SOCKOPS: Extracted tuple: %x:%u -> %x:%u\n",
               bpf_ntohl(tuple->src_ip), bpf_ntohs(tuple->src_port),
               bpf_ntohl(tuple->dst_ip), bpf_ntohs(tuple->dst_port));

    return 0;
}

SEC("sockops")
int kernelgatekeeper_sockops(struct bpf_sock_ops *skops) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u16 op = skops->op;

    // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB is defined in <linux/bpf.h>
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    bpf_printk("SOCKOPS: ACTIVE_ESTABLISHED_CB triggered pid=%u uid=%u\n", (__u32)pid_tgid, uid);

    struct client_process_info_t *client_info;
    client_info = bpf_map_lookup_elem(&process_map, &uid);
    if (!client_info) {
        // bpf_printk("SOCKOPS: UID %u not in process_map\n", uid); // Optional debug
        return BPF_OK;
    }
    // bpf_printk("SOCKOPS: Found client info for UID %u\n", uid); // Optional debug

    struct connection_tuple_t tuple = {};
    if (extract_tuple(skops, &tuple) != 0) {
        bpf_printk("SOCKOPS: Failed to extract tuple\n");
        return BPF_OK;
    }

    __u16 dst_port_h = skops->remote_port; // Host byte order for map lookup
    __u8 *target = bpf_map_lookup_elem(&target_ports, &dst_port_h);
    if (!target || *target != 1) {
        // bpf_printk("SOCKOPS: Port %u not targeted\n", dst_port_h); // Optional debug
        return BPF_OK;
    }

    // TODO: Add check to prevent proxying connections to the proxy itself or local network

    bpf_printk("SOCKOPS: Connection MATCHED for proxying pid=%u port=%u\n", (__u32)pid_tgid, dst_port_h);

    struct connection_state_t new_state = {
        .pid_tgid = pid_tgid,
        .uid_gid = uid_gid,
    };
    int ret = bpf_map_update_elem(&connection_map, &tuple, &new_state, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS: Failed to update connection_map: %d\n", ret);
        return BPF_OK;
    }

    __u32 sock_cookie = bpf_get_socket_cookie(skops);
    if (sock_cookie == 0) {
         bpf_printk("SOCKOPS: Failed to get socket cookie\n");
         bpf_map_delete_elem(&connection_map, &tuple);
         return BPF_OK;
    }

    // Pass pointer to sock map definition
    ret = bpf_sock_map_update(skops, &proxy_sock_map, &sock_cookie, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS: Failed to update proxy_sock_map: %d\n", ret);
        bpf_map_delete_elem(&connection_map, &tuple);
        return BPF_OK;
    }
    bpf_printk("SOCKOPS: Socket %u added to proxy_sock_map\n", sock_cookie);

    // Fix the typo and use '&' for the map pointer
    struct connection_tuple_t *event_data = bpf_ringbuf_reserve(&notification_ringbuf, sizeof(struct connection_tuple_t), 0);
    if (!event_data) {
        bpf_printk("SOCKOPS: Failed to reserve space in ringbuf\n");
        // Difficult to revert proxy_sock_map update. Log and continue.
        bpf_map_delete_elem(&connection_map, &tuple); // At least remove state marker
    } else {
        // Используем встроенную функцию компилятора вместо bpf_memcpy
        __builtin_memcpy(event_data, &tuple, sizeof(struct connection_tuple_t));
        bpf_ringbuf_submit(event_data, 0);
        bpf_printk("SOCKOPS: Sent notification for tuple to ringbuf\n");
    }

     __u32 stats_key_matched = 1;
     struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &stats_key_matched);
     if (stats) {
         // Use bpf_spin_lock if contention is possible, otherwise direct add is often fine for per-cpu stats
         __sync_fetch_and_add(&stats->packets, 1);
         // Note: Cannot easily get packet size here in sockops, maybe increment bytes later if needed
     }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";