// FILE: pkg/ebpf/bpf/bpf_shared.h
#ifndef BPF_SHARED_H
#define BPF_SHARED_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SO_ORIGINAL_DST 80

// --- Struct definitions ---
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
    __u16 padding; // Убедимся, что структура выровнена до 8 байт для BPF
};

// Добавляем поля для статистики sockops, если нужно
struct global_stats_t {
    __u64 packets;          // connect4: attempts
    __u64 bytes;            // (unused for now)
    __u64 redirected;       // connect4: successful redirects
    __u64 getsockopt_ok;    // getsockopt: successful lookups
    __u64 getsockopt_fail;  // getsockopt: failed lookups/writes
    __u64 sockops_pass_ok;  // sockops: successfully passed info
    __u64 sockops_pass_fail;// sockops: failed to pass info
};

struct notification_tuple_t {
    __u64 pid_tgid;
    __be32 src_ip;
    __be32 orig_dst_ip;
    __be16 src_port;
    __be16 orig_dst_port;
    __u8   protocol;
    // Добавим выравнивание, если нужно
    __u8   padding[3];
};

// --- Map definitions ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Размер карты исключений по dev/inode
    __type(key, struct dev_inode_key);
    __type(value, __u8); // Value is just a flag (1 = excluded)
} excluded_dev_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Max tracked client PIDs
    __type(key, __u32); // PID
    __type(value, __u8); // Value is just a flag (1 = client PID)
} kg_client_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536); // Can track all possible ports
    __type(key, __u16); // Port number (Host Byte Order)
    __type(value, __u8); // Value is just a flag (1 = target port)
} target_ports SEC(".maps");

// Map to temporarily store original destination keyed by socket cookie (connect4 -> sockops)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192); // Configurable via OrigDestMapSize
    __type(key, __u64); // Socket cookie
    __type(value, struct original_dest_t);
} kg_orig_dest SEC(".maps");

// Map to pass original destination from sockops to getsockopt, keyed by the redirected source port
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192); // Configurable via RedirSportMapSize
    __type(key, __u16); // Redirected source port (Host Byte Order)
    __type(value, struct original_dest_t);
} kg_redir_sport_to_orig SEC(".maps");

// Configuration map (listener IP/Port)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); // Key is always 0
    __type(value, struct kg_config_t);
} kg_config SEC(".maps");

// Global statistics map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); // Key is always 0
    __type(value, struct global_stats_t);
} kg_stats SEC(".maps");

// Ring buffer for notifications (sockops -> userspace) - optional now?
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // Default size, adjust if needed
} kg_notif_rb SEC(".maps");

// Stats helper function
// field 0: packets (connect4)
// field 1: redirected (connect4)
// field 2: getsockopt_ok (getsockopt)
// field 3: getsockopt_fail (getsockopt)
// field 4: sockops_pass_ok (sockops)
// field 5: sockops_pass_fail (sockops)
static __always_inline void kg_stats_inc(int field) {
    __u32 key = 0;
    struct global_stats_t *stats = bpf_map_lookup_elem(&kg_stats, &key);
    if (stats) {
        if (field == 0) __sync_fetch_and_add(&stats->packets, 1);
        else if (field == 1) __sync_fetch_and_add(&stats->redirected, 1);
        else if (field == 2) __sync_fetch_and_add(&stats->getsockopt_ok, 1);
        else if (field == 3) __sync_fetch_and_add(&stats->getsockopt_fail, 1);
        else if (field == 4) __sync_fetch_and_add(&stats->sockops_pass_ok, 1);
        else if (field == 5) __sync_fetch_and_add(&stats->sockops_pass_fail, 1);
        // field 6 for bytes could be added if needed
    }
}

#endif // BPF_SHARED_H