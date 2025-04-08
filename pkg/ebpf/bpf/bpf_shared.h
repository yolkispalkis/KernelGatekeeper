#ifndef BPF_SHARED_H
#define BPF_SHARED_H

#include <linux/bpf.h>
#include <linux/types.h> // Ensure basic types like __u8, __u16, __u32, __u64 are defined
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // Include for byte swapping helpers

// Structure to store connection details including original destination and PID
// Keyed by socket cookie in the map.
struct connection_details_t {
    __u64  pid_tgid;      // PID/TGID of the initiating process
    __be32 orig_dst_ip;   // Original Destination IP (Network Byte Order)
    __be16 orig_dst_port; // Original Destination Port (Network Byte Order)
    __u8   protocol;      // Protocol (e.g., IPPROTO_TCP) - Added for completeness
    __u8   padding[5];    // Padding to ensure structure size/alignment if needed
};

// Map to store connection details, keyed by socket cookie (u64)
// Populated by connect4 hook, read by sockops hook.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU helps clean up stale entries
    __uint(max_entries, 8192);           // Adjust size as needed
    __type(key, __u64);                  // Socket cookie
    __type(value, struct connection_details_t);
} connection_details_map SEC(".maps");

// Map to store target ports for redirection (Key: Port in Host Byte Order)
// Populated by userspace service based on config.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256); // Max target ports
    __type(key, __u16);       // Port (Host Byte Order)
    __type(value, __u8);      // Value 1 indicates port is targeted
} target_ports SEC(".maps");

// Sockmap for redirecting matched connections to the userspace client listener
// Updated by sockops hook, used by sk_msg hook.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 8192); // Should ideally match connection_details_map size
    __type(key, __u32);        // Key type for sockmap should be u32 (index/hash)
    __type(value, __u32);      // Value type for sockmap should be u32 (socket FD/ref)
} proxy_sock_map SEC(".maps");

// Ring buffer for sending notifications (connection tuples) to the userspace service
// Written to by sockops hook.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024); // 1MB buffer size
} notification_ringbuf SEC(".maps");

// Structure defining the data sent via the ring buffer notification
// Contains original destination info and PID.
struct notification_tuple_t {
    __u64  pid_tgid;      // PID/TGID of the process initiating connection
    __be32 src_ip;        // Source IP (Network Byte Order) of the connection
    __be32 orig_dst_ip;   // Original Destination IP (Network Byte Order)
    __be16 src_port;      // Source Port (Network Byte Order) of the connection
    __be16 orig_dst_port; // Original Destination Port (Network Byte Order)
    __u8   protocol;      // IP Protocol (e.g., IPPROTO_TCP)
    __u8   padding[5];    // Padding to ensure consistent struct size/alignment
};

// Optional: Map for global statistics (e.g., total matched connections)
// Updated by sockops hook.
struct global_stats_t {
    __u64 packets; // Represents matched connections in this context
    __u64 bytes;   // Currently unused
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2); // Index 1 for matched count
    __type(key, __u32);
    __type(value, struct global_stats_t);
} global_stats SEC(".maps");

#endif // BPF_SHARED_H