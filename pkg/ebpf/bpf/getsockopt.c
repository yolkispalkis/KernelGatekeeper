// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
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

SEC("cgroup/getsockopt")
int kernelgatekeeper_getsockopt(struct bpf_sockopt *ctx) {
    // Проверяем, интересует ли нас данный вызов
    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1;
    }

    // Проверка на NULL-указатель
    if (!ctx->sk) {
        return 1;
    }

    // Получаем порт с помощью bpf_socket_lookup_peer
    // Эта часть требует другого подхода, так как у нас нет доступа к полям сокета
    
    // Используем hash-map или динамические переменные для получения peer_port_h
    
    // Для демонстрации и отладки мы можем использовать принудительный поиск по всем известным портам
    // (Это не эффективно, но поможет нам отладить проблему)
    
    for (__u16 port = 1024; port < 65535; port++) {
        __u64 *cookie_ptr = bpf_map_lookup_elem(&kg_port_to_cookie, &port);
        if (cookie_ptr) {
            __u64 cookie = *cookie_ptr;
            
            // Проверяем, есть ли для этого cookie оригинальный адрес назначения
            struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_orig_dest, &cookie);
            if (orig_dest) {
                // Проверка буфера
                if (!ctx->optval || !ctx->optval_end || 
                    (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
                    #ifdef DEBUG
                    bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for cookie %llu (port %u).\n", 
                              cookie, port);
                    #endif
                    bpf_map_delete_elem(&kg_orig_dest, &cookie);
                    bpf_map_delete_elem(&kg_port_to_cookie, &port);
                    kg_stats_inc(3);
                    continue;
                }

                // Создаем и заполняем структуру sockaddr_in
                struct sockaddr_in sa_out = {};
                sa_out.sin_family = AF_INET;
                sa_out.sin_addr.s_addr = orig_dest->dst_ip;
                sa_out.sin_port = orig_dest->dst_port;

                // Копируем данные в буфер пользователя
                long ret = bpf_probe_write_user(ctx->optval, &sa_out, sizeof(sa_out));
                if (ret != 0) {
                    #ifdef DEBUG
                    bpf_printk("GETSOCKOPT_ERR: bpf_probe_write_user failed: %ld\n", ret);
                    #endif
                    bpf_map_delete_elem(&kg_orig_dest, &cookie);
                    bpf_map_delete_elem(&kg_port_to_cookie, &port);
                    kg_stats_inc(3);
                    continue;
                }

                // Устанавливаем результат и очищаем карты
                ctx->optlen = sizeof(struct sockaddr_in);
                ctx->retval = 0;

                bpf_map_delete_elem(&kg_orig_dest, &cookie);
                bpf_map_delete_elem(&kg_port_to_cookie, &port);
                kg_stats_inc(2);

                #ifdef DEBUG
                bpf_printk("GETSOCKOPT: OK orig dest %x:%u cookie %llu port %u\n",
                          orig_dest->dst_ip, bpf_ntohs(orig_dest->dst_port), cookie, port);
                #endif

                return 1;
            }
        }
    }

    // Если мы дошли до этой точки, значит, не нашли соответствия
    kg_stats_inc(3);
    #ifdef DEBUG
    bpf_printk("GETSOCKOPT_WARN: Failed to find matching entry in cookie map.\n");
    #endif
    return 1;
}

char _license[] SEC("license") = "GPL";