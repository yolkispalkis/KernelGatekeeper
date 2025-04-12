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
    // Объявляем все переменные в начале функции
    __u16 family;
    __u8 protocol;
    __be16 peer_port_n;
    __u16 peer_port_h;
    __u64 *cookie_ptr;
    __u64 cookie;
    struct original_dest_t *orig_dest;
    struct sockaddr_in sa_out = {};
    long ret;

    // Проверяем, интересует ли нас данный вызов
    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1;
    }

    // Проверка на NULL-указатель
    if (!ctx->sk) {
        return 1;
    }

    // Используем поля, доступные непосредственно в структуре bpf_sock
    if (bpf_core_read(&family, sizeof(family), &ctx->sk->family)) {
        return 1;
    }
    
    if (bpf_core_read(&protocol, sizeof(protocol), &ctx->sk->protocol)) {
        return 1;
    }

    if (family != AF_INET || protocol != IPPROTO_TCP) {
        return 1;
    }

    // Получаем порт назначения напрямую из структуры (используем dst_port)
    if (bpf_core_read(&peer_port_n, sizeof(peer_port_n), &ctx->sk->dst_port)) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Failed to read dst_port\n");
        #endif
        kg_stats_inc(3);
        return 1;
    }

    peer_port_h = bpf_ntohs(peer_port_n);

    if (peer_port_h == 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Peer port is 0, cannot lookup cookie.\n");
        #endif
        kg_stats_inc(3);
        return 1;
    }

    // Поиск cookie по порту
    cookie_ptr = bpf_map_lookup_elem(&kg_port_to_cookie, &peer_port_h);
    if (!cookie_ptr) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Cookie not found for peer port %u.\n", peer_port_h);
        #endif
        kg_stats_inc(3);
        return 1;
    }
    cookie = *cookie_ptr;

    // Поиск оригинального адреса назначения
    orig_dest = bpf_map_lookup_elem(&kg_orig_dest, &cookie);
    if (!orig_dest) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Original destination not found for cookie %llu (port %u).\n", 
                  cookie, peer_port_h);
        #endif
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3);
        return 1;
    }

    // Проверка буфера
    if (!ctx->optval || !ctx->optval_end || 
        (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for cookie %llu (port %u).\n", 
                  cookie, peer_port_h);
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3);
        return 1;
    }

    // Создаем и заполняем структуру sockaddr_in
    sa_out.sin_family = AF_INET;
    sa_out.sin_addr.s_addr = orig_dest->dst_ip;
    sa_out.sin_port = orig_dest->dst_port;

    // Копируем данные в буфер пользователя
    ret = bpf_probe_write_user(ctx->optval, &sa_out, sizeof(sa_out));
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: bpf_probe_write_user failed: %ld\n", ret);
        #endif
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3);
        return 1;
    }

    // Устанавливаем результат и очищаем карты
    ctx->optlen = sizeof(struct sockaddr_in);
    ctx->retval = 0;

    bpf_map_delete_elem(&kg_orig_dest, &cookie);
    bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
    kg_stats_inc(2);

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT: OK orig dest %x:%u cookie %llu port %u\n",
              orig_dest->dst_ip, bpf_ntohs(orig_dest->dst_port), cookie, peer_port_h);
    #endif

    return 1;
}

char _license[] SEC("license") = "GPL";