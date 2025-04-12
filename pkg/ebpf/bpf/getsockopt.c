// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include "vmlinux.h" // Все еще нужен для структур (sockaddr_in, bpf_sockopt) и констант
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include <bpf/bpf_core_read.h> // Больше не используем bpf_core_read
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

// sockaddr_in должен быть определен в vmlinux.h

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

    // Интересуют только SO_ORIGINAL_DST для IP уровня
    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1; // Передать следующему хуку
    }

    // Сначала проверка на NULL sk
    if (ctx->sk == NULL) {
         return 1; // Передать следующему хуку
    }

    // --- Используем bpf_probe_read_kernel для чтения полей ---
    __u16 family;
    __u8 protocol;
    __u16 peer_port_n; // В сетевом порядке байт
    long err;

    // Читаем family
    // ПРИМЕЧАНИЕ: Мы предполагаем, что структура bpf_sock доступна через ctx->sk.
    // Смещение поля family может зависеть от версии ядра, но для стандартных полей оно обычно стабильно.
    // Если это не сработает, потребуется более сложный подход с BTF или хардкодом смещений (не рекомендуется).
    err = bpf_probe_read_kernel(&family, sizeof(family), &ctx->sk->family);
    if (err != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT: probe_read_kernel(family) failed: %ld\n", err);
        #endif
        return 1; // Ошибка чтения, передать дальше
    }

    // Читаем protocol
    err = bpf_probe_read_kernel(&protocol, sizeof(protocol), &ctx->sk->protocol);
    if (err != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT: probe_read_kernel(protocol) failed: %ld\n", err);
        #endif
        return 1; // Ошибка чтения, передать дальше
    }

    // Проверяем family и protocol
    if (family != AF_INET || protocol != IPPROTO_TCP) {
         #ifdef DEBUG
         // bpf_printk("GETSOCKOPT: Not AF_INET/TCP (Family: %u, Proto: %u)\n", family, protocol);
         #endif
        return 1; // Не то, что нам нужно
    }

    // Читаем dst_port (peer port)
    err = bpf_probe_read_kernel(&peer_port_n, sizeof(peer_port_n), &ctx->sk->dst_port);
    if (err != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT: probe_read_kernel(dst_port) failed: %ld\n", err);
        #endif
        return 1; // Ошибка чтения, передать дальше
    }
    // --- Конец чтения через bpf_probe_read_kernel ---

    __u16 peer_port_h = bpf_ntohs(peer_port_n); // Конвертируем в host byte order для ключа карты

    if (peer_port_h == 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Peer port is 0, cannot lookup cookie.\n");
        #endif
        kg_stats_inc(3); // Увеличить счетчик неудач
        return 1; // Передать следующему хуку
    }

    // Ищем куку оригинального соединения по исходному порту (host byte order)
    __u64 *cookie_ptr = bpf_map_lookup_elem(&kg_port_to_cookie, &peer_port_h);
    if (!cookie_ptr) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Cookie not found for peer port %u.\n", peer_port_h);
        #endif
        kg_stats_inc(3); // Увеличить счетчик неудач
        return 1; // Передать следующему хуку
    }
    __u64 cookie = *cookie_ptr;

    // Ищем оригинальные данные назначения по куке
    struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_orig_dest, &cookie);
    if (!orig_dest) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Original destination not found for cookie %llu (port %u).\n", cookie, peer_port_h);
        #endif
        // Очистить маппинг порт->кука, если назначение исчезло
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3); // Увеличить счетчик неудач
        return 1; // Передать следующему хуку
    }

    // Проверяем валидность буфера пользователя (optval) и достаточен ли его размер
    if (ctx->optval == NULL || ctx->optval_end == NULL ||
        (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for cookie %llu (port %u).\n", cookie, peer_port_h);
        #endif
        // Очистить карты, если буфер невалиден
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3); // Увеличить счетчик неудач
        return 1; // Передать следующему хуку
    }

    // --- Используем bpf_probe_write_user для записи в буфер пользователя ---
    struct sockaddr_in sa_out = {}; // Инициализируем нулями
    sa_out.sin_family = AF_INET;
    sa_out.sin_addr.s_addr = orig_dest->dst_ip; // Уже в network byte order
    sa_out.sin_port = orig_dest->dst_port;     // Уже в network byte order

    long ret = bpf_probe_write_user(ctx->optval, &sa_out, sizeof(sa_out));
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: bpf_probe_write_user failed: %ld\n", ret);
        #endif
        // Очистить карты при ошибке записи
        bpf_map_delete_elem(&kg_orig_dest, &cookie);
        bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
        kg_stats_inc(3);
        return 1; // Передать дальше, пусть syscall завершится с ошибкой
    }
    // --- Конец использования bpf_probe_write_user ---

    // Устанавливаем выходную длину ПОСЛЕ успешной записи
    ctx->optlen = sizeof(struct sockaddr_in);

    // Устанавливаем возвращаемое значение системного вызова ПОСЛЕ успешной записи
    ctx->retval = 0;

    // Очищаем карты
    bpf_map_delete_elem(&kg_orig_dest, &cookie);
    bpf_map_delete_elem(&kg_port_to_cookie, &peer_port_h);
    kg_stats_inc(2); // Увеличить счетчик успехов

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT: OK orig dest %x:%u cookie %llu port %u\n",
               orig_dest->dst_ip, bpf_ntohs(orig_dest->dst_port), cookie, peer_port_h);
    #endif

    return 1; // Позволить результату передаться в userspace
}

char _license[] SEC("license") = "GPL";