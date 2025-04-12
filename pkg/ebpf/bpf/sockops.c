// FILE: pkg/ebpf/bpf/sockops.c
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
#ifndef BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 1
#endif
#ifndef BPF_OK
#define BPF_OK 0
#endif

// Определение структуры skops для CO-RE
struct bpf_sock_ops_kern {
    __u32 op;
    __u32 family;
    __u32 local_ip4;
    __u32 remote_ip4;
    __u16 local_port;
    __u16 remote_port;
    __u32 reply;
} __attribute__((preserve_access_index));

SEC("sockops")
int kernelgatekeeper_sockops(struct bpf_sock_ops *skops) {
    // Безопасное чтение полей структуры skops
    __u16 op;
    __u16 family;
    __u16 local_port;
    __be16 remote_port_n;
    __u32 local_ip4;
    __u32 remote_ip4;
    
    if (bpf_core_read(&op, sizeof(op), &skops->op)) {
        return BPF_OK;
    }
    
    #ifdef DEBUG
    // bpf_printk("SOCKOPS_DEBUG: Read op=%u\n", op);
    #endif

    // Интересуют только установленные соединения, инициированные клиентом
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    if (bpf_core_read(&family, sizeof(family), &skops->family)) {
        return BPF_OK;
    }
    
    // Обрабатываем только IPv4
    if (family != AF_INET) {
        return BPF_OK;
    }

    // Получаем cookie сокета
    __u64 sock_cookie = bpf_get_socket_cookie(skops);
    if (sock_cookie == 0) {
        #ifdef DEBUG
        bpf_printk("SOCKOPS_ERR: Failed to get socket cookie (ACTIVE_ESTABLISHED_CB).\n");
        #endif
        return BPF_OK;
    }

    // Ищем оригинальный адрес назначения, сохраненный connect4
    struct original_dest_t *details = bpf_map_lookup_elem(&kg_orig_dest, &sock_cookie);
    if (!details) {
        // Это соединение не было перенаправлено connect4 или данные были очищены
        return BPF_OK;
    }

    #ifdef DEBUG
    bpf_printk("SOCKOPS_READ: Read details for Cookie=%llu, PID in details=%u\n", 
              sock_cookie, details->pid);
    #endif

    // Проверяем, что PID не равен 0
    if (details->pid == 0) {
        bpf_printk("SOCKOPS_WARN: PID read from kg_orig_dest map is 0 for Cookie=%llu. Skipping notification.\n", 
                  sock_cookie);
        return BPF_OK;
    }

    // Получаем порт источника
    if (bpf_core_read(&local_port, sizeof(local_port), &skops->local_port)) {
        #ifdef DEBUG
        bpf_printk("SOCKOPS_ERR: Failed to read skops->local_port for cookie %llu\n", sock_cookie);
        #endif
        return BPF_OK;
    }
    
    __u16 src_port_h = (__u16)local_port; // Порт источника (в сетевом порядке байт)

    // Сохраняем отображение порт_источника -> cookie
    int ret = bpf_map_update_elem(&kg_port_to_cookie, &src_port_h, &sock_cookie, BPF_ANY);
    if (ret != 0) {
        bpf_printk("SOCKOPS_ERR: Failed to update kg_port_to_cookie (port %u, cookie %llu): %d\n", 
                  src_port_h, sock_cookie, ret);
        // Очищаем запись оригинального адреса назначения, если отображение порта не удалось
        bpf_map_delete_elem(&kg_orig_dest, &sock_cookie);
    } else {
        #ifdef DEBUG
        // bpf_printk("SOCKOPS: Stored port->cookie mapping (%u -> %llu)\n", src_port_h, sock_cookie);
        #endif

        // Получаем локальный IP для уведомления
        if (bpf_core_read(&local_ip4, sizeof(local_ip4), &skops->local_ip4)) {
            #ifdef DEBUG
            bpf_printk("SOCKOPS_ERR: Failed to read skops->local_ip4 for cookie %llu\n", sock_cookie);
            #endif
            local_ip4 = 0; // Установим значение по умолчанию
        }

        // Отправляем уведомление в userspace через кольцевой буфер
        struct notification_tuple_t *notif;
        notif = bpf_ringbuf_reserve(&kg_notif_rb, sizeof(*notif), 0);
        if (!notif) {
            bpf_printk("SOCKOPS_ERR: Failed to reserve space in ring buffer for notification.\n");
        } else {
            // Логируем PID перед отправкой
            #ifdef DEBUG
            bpf_printk("SOCKOPS_SUBMIT: Submitting notification for PID=%u (from details), Cookie=%llu\n", 
                      details->pid, sock_cookie);
            #endif

            notif->pid_tgid = (__u64)details->pid;    // Используем PID из details
            notif->src_ip = local_ip4;                // IP источника (локальный IP приложения)
            notif->orig_dst_ip = details->dst_ip;     // Оригинальный IP назначения из connect4
            notif->src_port = bpf_htons(src_port_h);  // Порт источника (сетевой порядок байт)
            notif->orig_dst_port = details->dst_port; // Оригинальный порт назначения из connect4
            notif->protocol = IPPROTO_TCP;            // Предполагаем TCP

            bpf_ringbuf_submit(notif, 0);
        }
    }

    // Соединение должно продолжиться нормально (к клиентскому слушателю)
    return BPF_OK;
}

char _license[] SEC("license") = "GPL";