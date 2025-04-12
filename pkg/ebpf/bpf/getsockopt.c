// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_shared.h" // Includes definition for kg_redir_sport_to_orig map

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOL_IP
#define SOL_IP 0 // IPPROTO_IP
#endif
// SO_ORIGINAL_DST is defined in bpf_shared.h

SEC("cgroup/getsockopt")
int kernelgatekeeper_getsockopt(struct bpf_sockopt *ctx) {
    // Only interested in SOL_IP level and SO_ORIGINAL_DST option
    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1; // Allow other getsockopt calls
    }

    // Read the source port of the current (redirected) socket from the context
    // ctx->local_port seems to be available and in host byte order
    __u32 local_port_u32;
    if (bpf_core_read(&local_port_u32, sizeof(local_port_u32), &ctx->local_port)) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Failed to read ctx->local_port.\n");
        #endif
        kg_stats_inc(3); // Increment getsockopt_fail
        ctx->retval = -1; // Indicate error, e.g., -EPERM
        return 0; // Handled with error
    }
    __u16 local_port_h = (__u16)local_port_u32; // Host byte order

    // Lookup the original destination details using the redirected source port
    struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_redir_sport_to_orig, &local_port_h);
    if (!orig_dest) {
        // Original destination not found for this port.
        // This might happen if sockops didn't run or entry was already consumed.
        // Allow the getsockopt call to proceed to the kernel's default handler.
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: No original destination found for redir_src_port %u.\n", local_port_h);
        #endif
        // Do NOT increment fail counter here.
        return 1; // Let kernel handle it
    }

    // Check if the user buffer is valid and sufficiently large
    if (!ctx->optval || !ctx->optval_end ||
        (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for redir_src_port %u. optval=%p optval_end=%p needed=%d\n",
                  local_port_h, ctx->optval, ctx->optval_end, sizeof(struct sockaddr_in));
        #endif
        // Clean up the map entry as it cannot be delivered
        bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);
        kg_stats_inc(3); // Increment getsockopt_fail
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
        bpf_printk("GETSOCKOPT_ERR: bpf_probe_write_user failed for redir_src_port %u: %ld\n", local_port_h, ret);
        #endif
        // Clean up the map entry
        bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);
        kg_stats_inc(3); // Increment getsockopt_fail
        ctx->retval = ret; // Return the error code from probe_write_user
        return 0; // Tell kernel we handled it (with an error)
    }

    // Successfully wrote the data. Set return value and length.
    ctx->retval = 0; // Success
    ctx->optlen = sizeof(struct sockaddr_in);
    kg_stats_inc(2); // Increment getsockopt_ok

    // IMPORTANT: Clean up the map entry now that it has been successfully used.
    bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT_OK: Provided original dest %x:%u for redir_src_port %u\n",
              sa_out.sin_addr.s_addr, bpf_ntohs(sa_out.sin_port), local_port_h);
    #endif

    // Tell the kernel we have successfully handled the getsockopt call.
    // Returning 0 prevents the kernel's default handler from running.
    return 0;
}

char _license[] SEC("license") = "GPL";