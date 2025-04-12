// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_shared.h" // Includes definition for kg_orig_dest map

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOL_IP
#define SOL_IP 0 // IPPROTO_IP is usually 0 for getsockopt level
#endif
// SO_ORIGINAL_DST is defined in bpf_shared.h

SEC("cgroup/getsockopt")
int kernelgatekeeper_getsockopt(struct bpf_sockopt *ctx) {
    // Only interested in SOL_IP level and SO_ORIGINAL_DST option
    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1; // Allow other getsockopt calls
    }

    // Check if the socket pointer in the context is valid (CO-RE read for safety)
    // Note: ctx->sk might not be directly available or safe without CO-RE checks
    // depending on kernel version. bpf_get_socket_cookie might work directly with ctx.
    // Let's try bpf_get_socket_cookie directly first, as it often takes the context struct.
    // If that fails compilation/verification, we might need to access ctx->sk carefully.

    // __u64 sock_cookie = bpf_get_socket_cookie(ctx->sk); // Requires access to ctx->sk
    __u64 sock_cookie = bpf_get_socket_cookie(ctx); // Try passing ctx directly
    if (sock_cookie == 0) {
        #ifdef DEBUG
        // Getting the cookie failed, increment fail stat but allow syscall to proceed (maybe?)
        // Or maybe block it? Let's increment fail stat and allow kernel's default handling.
        bpf_printk("GETSOCKOPT_ERR: Failed to get socket cookie for getsockopt.\n");
        #endif
        kg_stats_inc(3); // Increment getsockopt_fail
        return 1; // Allow kernel default handling
    }

    // Lookup the original destination details using the current socket's cookie
    struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_orig_dest, &sock_cookie);
    if (!orig_dest) {
        // Original destination not found for this cookie.
        // This might happen if the entry was already consumed or never created.
        // Allow the getsockopt call to proceed to the kernel's default handler.
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: No original destination found for cookie %llu.\n", sock_cookie);
        #endif
        // Do NOT increment fail counter here, as it's not necessarily an *error*
        // in the BPF program's logic, just missing data.
        return 1;
    }

    // Check if the user buffer is valid and sufficiently large
    if (!ctx->optval || !ctx->optval_end ||
        (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for cookie %llu. optval=%p optval_end=%p needed=%d\n",
                  sock_cookie, ctx->optval, ctx->optval_end, sizeof(struct sockaddr_in));
        #endif
        // Clean up the map entry as it cannot be delivered
        bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
        kg_stats_inc(3); // Increment getsockopt_fail
        // What should we return? Let's return EFAULT like the kernel might.
        ctx->retval = -14; // -EFAULT
        return 0; // Tell kernel we handled it (with an error)
    }

    // Prepare the sockaddr_in structure to write back to userspace
    struct sockaddr_in sa_out = {};
    sa_out.sin_family = AF_INET;
    // Use bpf_core_read for safety when accessing map value fields
    bpf_core_read(&sa_out.sin_addr.s_addr, sizeof(sa_out.sin_addr.s_addr), &orig_dest->dst_ip);
    bpf_core_read(&sa_out.sin_port, sizeof(sa_out.sin_port), &orig_dest->dst_port);

    // Write the original destination address back to the user buffer
    long ret = bpf_probe_write_user(ctx->optval, &sa_out, sizeof(sa_out));
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: bpf_probe_write_user failed for cookie %llu: %ld\n", sock_cookie, ret);
        #endif
        // Clean up the map entry
        bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
        kg_stats_inc(3); // Increment getsockopt_fail
        ctx->retval = ret; // Return the error code from probe_write_user
        return 0; // Tell kernel we handled it (with an error)
    }

    // Successfully wrote the data. Set return value and length.
    ctx->retval = 0; // Success
    ctx->optlen = sizeof(struct sockaddr_in);
    kg_stats_inc(2); // Increment getsockopt_ok

    // IMPORTANT: Clean up the map entry now that it has been successfully used.
    bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
    // Note: No need to interact with kg_port_to_cookie here.

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT_OK: Provided original dest %x:%u for cookie %llu\n",
              sa_out.sin_addr.s_addr, bpf_ntohs(sa_out.sin_port), sock_cookie);
    #endif

    // Tell the kernel we have successfully handled the getsockopt call.
    // Returning 0 prevents the kernel's default handler from running.
    return 0;
}

char _license[] SEC("license") = "GPL";