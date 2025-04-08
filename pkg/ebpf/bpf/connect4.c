//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>         // For AF_INET, IPPROTO_TCP
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_shared.h"     // Include the updated shared definitions

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

// Attach to the cgroup connect4 hook to capture original destination details
SEC("cgroup/connect4")
int kernelgatekeeper_connect4(struct bpf_sock_addr *ctx) {
    // Only intercept outgoing TCP connections for IPv4
    if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP) {
        return 1; // Allow non-TCP/IPv4 connections to proceed normally
    }

    // --- Optional: Add check to ignore connections from the proxy client/service itself ---
    // This requires passing the proxy client's PID/TGID or UID via a config map.
    // Example (needs a config map named 'proxy_config_map' with proxy PID/UID):
    /*
    struct proxy_config { __u64 proxy_pid_tgid; };
    struct { ... } proxy_config_map SEC(".maps"); // Define map in bpf_shared.h

    __u32 config_key = 0;
    struct proxy_config *cfg = bpf_map_lookup_elem(&proxy_config_map, &config_key);
    if (cfg && (bpf_get_current_pid_tgid() == cfg->proxy_pid_tgid)) {
        #ifdef DEBUG
        bpf_printk("CONNECT4: Skipping connection from proxy itself (pid=%llu)\n", cfg->proxy_pid_tgid);
        #endif
        return 1; // Allow proxy's own connections
    }
    */
    // --- End Optional Proxy Check ---


    // Get the socket cookie, which uniquely identifies this connection attempt
    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 0) {
        // This is unexpected, but we should probably allow the connection anyway.
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to get socket cookie.\n");
        #endif
        return 1;
    }

    // Prepare the details structure to store in the map
    struct connection_details_t details = {};
    details.pid_tgid = bpf_get_current_pid_tgid();
    details.orig_dst_ip = ctx->user_ip4;   // Capture original destination IP (Network Byte Order)
    details.orig_dst_port = ctx->user_port; // Capture original destination Port (Network Byte Order)
    details.protocol = ctx->protocol;       // Store the protocol

    // Update the map with the connection details, keyed by the socket cookie
    int ret = bpf_map_update_elem(&connection_details_map, &cookie, &details, BPF_ANY);
    if (ret != 0) {
        // Log the error, but allow the connection attempt to proceed.
        // If the map is full, we might miss redirecting this connection later.
        #ifdef DEBUG
        bpf_printk("CONNECT4_ERR: Failed to update connection_details_map (cookie %llu): %d\n", cookie, ret);
        #endif
    } else {
         #ifdef DEBUG
         // Log the stored details for debugging. Convert port to host order for printing.
         bpf_printk("CONNECT4: Stored details cookie %llu (orig_dst=%x:%u pid=%llu)\n",
                    cookie, details.orig_dst_ip, bpf_ntohs(details.orig_dst_port), details.pid_tgid);
         #endif
    }

    // Crucially, return 1 here to allow the connection attempt to proceed.
    // The sockops hook will later decide whether to redirect based on these stored details.
    return 1;
}

// Define the license for the BPF program
char _license[] SEC("license") = "GPL";