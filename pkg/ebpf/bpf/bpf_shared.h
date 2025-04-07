#ifndef BPF_SHARED_H
#define BPF_SHARED_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct connection_tuple_t {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 padding[3];
};

struct connection_state_t {
    __u64 pid_tgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} target_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct connection_tuple_t);
    __type(value, struct connection_state_t);
} connection_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u32); 
} proxy_sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} notification_ringbuf SEC(".maps");

struct global_stats_t {
    __u64 packets;
    __u64 bytes;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct global_stats_t);
} global_stats SEC(".maps");

#endif