// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_shared.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

// Define sockaddr_in locally if not included, matching kernel definition
#ifndef _LINUX_SOCKET_H
struct in_addr {
    unsigned int s_addr;
};
struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};
#endif


static __always_inline void kg_stats_inc(int field) {
    __u32 key = 0;
    struct global_stats_t *stats = bpf_map_lookup_elem(&kg_stats, &key);
    if (stats) {
        if (field == 2) __sync_fetch_and_add(&stats->getsockopt_ok, 1);
        else if (field == 3) __sync_fetch_and_add(&stats->getsockopt_fail, 1);
    }
}

SEC("cgroup/getsockopt")
int kernelgatekeeper_getsockopt(struct bpf_sockopt *ctx) {

    // Only interested in SO_ORIGINAL_DST for IP level
    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1; // Pass to next hook
    }

    // Check if it's an IPv4 TCP socket (via the bpf_sock struct)
    // Accessing ctx->sk requires kernel 5.3+ with CO-RE BPF sock struct support.
    if (ctx->sk == NULL || ctx->sk->family != AF_INET || ctx->sk->protocol != IPPROTO_TCP) {
         #ifdef DEBUG
         bpf_printk("GETSOCKOPT: Ignoring non-IPv4/TCP getsockopt or NULL sk.\n");
         #endif
        return 1; // Pass to next hook
    }

    // Get the source port (local port in sockops context) to find the cookie
    // Note: ctx->sk->src_port exists in some contexts, but might not be reliable here.
    // Using the peer port (ctx->sk->dst_port) as the key to find the cookie stored by sockops.
    __u16 peer_port_h = bpf_ntohs(ctx->sk->dst_port); // Destination port of the socket struct == source port of the original connection
    if (peer_port_h == 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Peer port is 0, cannot lookup cookie.\n");
        #endif
        kg_stats_inc(3); // Increment failure count
        return 1; // Pass to next hook
    }


    // Lookup the original connection cookie using the source port
    __u64 *cookie_ptr = bpf_map_lookup_elem(&kg_port_to_cookie, &peer_port_h);
    if (!cookie_ptr) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Cookie not found for peer port %u.\n", peer_port_h);
        #endif
        kg_stats_inc(3); // Increment failure count
        return 1; // Pass to next hook
    }
    __u64 cookie = *cookie_ptr;

    // Lookup the original destination details using the cookie
    struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_orig_dest, &cookie);
    if (!orig_dest) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Original destination not found for cookie %llu (port %u).\n", cookie, peer_port_h);
        #endif
        // Clean up the port->cookie mapping if the destination is gone
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3); // Increment failure count
        return 1; // Pass to next hook
    }

    // Check if the userspace buffer (optval) is valid and large enough
    if (ctx->optval == NULL || ctx->optval_end == NULL ||
        (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for cookie %llu (port %u).\n", cookie, peer_port_h);
        #endif
        // Clean up maps if the buffer is invalid
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3); // Increment failure count
        return 1; // Pass to next hook
    }

    // Fill the userspace buffer (ctx->optval) with the original destination
    struct sockaddr_in *sa = (struct sockaddr_in *)ctx->optval;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = orig_dest->dst_ip; // Already in network byte order from connect4
    sa->sin_port = orig_dest->dst_port;     // Already in network byte order from connect4

    // Explicitly assign the size as s32 to potentially help the compiler/verifier
    __s32 sockaddr_size = sizeof(struct sockaddr_in);
    ctx->optlen = sockaddr_size; // Set the output length

    // Set the return value of the getsockopt syscall to 0 (success)
    ctx->retval = 0;

    // Clean up the maps now that the original destination has been retrieved
    bpf_map_delete_elem(&kg_orig_dest, &cookie);
    bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
    kg_stats_inc(2); // Increment success count

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT: Successfully returned original dest %x:%u for cookie %llu (port %u).\n",
               orig_dest->dst_ip, bpf_ntohs(orig_dest->dst_port), cookie, peer_port_h);
    #endif

    // Return 1 to allow the modified getsockopt result to be passed to userspace.
    // Returning 0 would mean BPF handled it and the syscall should return -EPERM.
    return 1;
}

char _license[] SEC("license") = "GPL";