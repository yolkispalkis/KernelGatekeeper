// FILE: pkg/ebpf/bpf/bpf_shared.h
#ifndef BPF_SHARED_H
#define BPF_SHARED_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SO_ORIGINAL_DST 80

struct original_dest_t {
    __be32 dst_ip;
    __be16 dst_port;
    __u32  pid;
    __u32  uid;
};

struct kg_config_t {
    __u32 listener_ip;
    __u16 listener_port;
     __u16 padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct original_dest_t);
} kg_orig_dest SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u16);
    __type(value, __u64);
} kg_port_to_cookie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} target_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} kg_client_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kg_config_t);
} kg_config SEC(".maps");

struct global_stats_t {
    __u64 packets;
    __u64 bytes;
    __u64 redirected;
    __u64 getsockopt_ok;
    __u64 getsockopt_fail;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats_t);
} kg_stats SEC(".maps");

// Ring buffer for sending connection details to userspace service
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer size
} kg_notif_rb SEC(".maps");

// Struct sent via ring buffer
struct notification_tuple_t {
    __u64 pid_tgid;      // PID and TGID of the process initiating connection
    __be32 src_ip;       // Source IP address
    __be32 orig_dst_ip;  // Original Destination IP address (before redirection)
    __be16 src_port;     // Source Port (network byte order)
    __be16 orig_dst_port;// Original Destination Port (before redirection, network byte order)
    __u8   protocol;     // L4 protocol (e.g., IPPROTO_TCP)
};

#endif // BPF_SHARED_H