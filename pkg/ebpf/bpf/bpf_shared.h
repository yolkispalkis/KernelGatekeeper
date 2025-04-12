// FILE: pkg/ebpf/bpf/bpf_shared.h
#ifndef BPF_SHARED_H
#define BPF_SHARED_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SO_ORIGINAL_DST 80

// --- Struct definitions remain the same ---
struct dev_inode_key {
    __u64 dev_id;
    __u64 inode_id;
};

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

struct global_stats_t {
    __u64 packets;
    __u64 bytes;
    __u64 redirected;
    __u64 getsockopt_ok;
    __u64 getsockopt_fail;
};

struct notification_tuple_t {
    __u64 pid_tgid;
    __be32 src_ip;
    __be32 orig_dst_ip;
    __be16 src_port;
    __be16 orig_dst_port;
    __u8   protocol;
};


// --- Map definitions remain the same ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Make sure max_entries is appropriate
    __type(key, struct dev_inode_key);
    __type(value, __u8);
} excluded_dev_inodes SEC(".maps");

// ... (other map definitions) ...

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats_t);
} kg_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // Default size, adjust if needed
} kg_notif_rb SEC(".maps");


// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// ADD the stats helper function definition here
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// field 0: packets (connect4)
// field 1: redirected (connect4)
// field 2: getsockopt_ok (getsockopt)
// field 3: getsockopt_fail (getsockopt)
static __always_inline void kg_stats_inc(int field) {
    __u32 key = 0;
    struct global_stats_t *stats = bpf_map_lookup_elem(&kg_stats, &key);
    if (stats) {
        if (field == 0) __sync_fetch_and_add(&stats->packets, 1);
        else if (field == 1) __sync_fetch_and_add(&stats->redirected, 1);
        else if (field == 2) __sync_fetch_and_add(&stats->getsockopt_ok, 1);
        else if (field == 3) __sync_fetch_and_add(&stats->getsockopt_fail, 1);
        // field 4 for bytes could be added if needed
    }
}

#endif // BPF_SHARED_H