// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include "vmlinux.h" // Содержит struct sock, bpf_sock, sock_common и т.д.
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // Нужен для bpf_ntohs на порте назначения
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_shared.h" // Включает определение карты kg_redir_sport_to_orig

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOL_IP
#define SOL_IP 0 // IPPROTO_IP
#endif
// SO_ORIGINAL_DST определен в bpf_shared.h

SEC("cgroup/getsockopt")
int kernelgatekeeper_getsockopt(struct bpf_sockopt *ctx) {
    // Интересует только SOL_IP уровень и опция SO_ORIGINAL_DST
    if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
        return 1; // Разрешаем другие вызовы getsockopt
    }

    // --- Получаем полный указатель на struct sock ---
    struct bpf_sock *bpf_sk;
    struct sock *sk;

    bpf_sk = ctx->sk;
    if (!bpf_sk) {
         #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: ctx->sk (bpf_sock) is NULL.\n");
        #endif
        kg_stats_inc(3);
        ctx->retval = -1; // EPERM
        return 0;
    }

    if (bpf_sk->protocol != IPPROTO_TCP) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: Socket is not TCP (protocol: %u).\n", bpf_sk->protocol);
        #endif
        kg_stats_inc(3);
        ctx->retval = -95; // -EOPNOTSUPP
        return 0;
    }
    sk = (struct sock *)bpf_sk;
    if (!sk) {
         #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Conversion from bpf_sock to sock resulted in NULL.\n");
        #endif
        kg_stats_inc(3);
        ctx->retval = -1; // EPERM
        return 0;
    }

    // --- Читаем порт источника из структуры сокета ---
    __u16 local_port_h; // Порт источника в хостовом порядке байт
    // Путь: sk -> __sk_common -> skc_num
    if (BPF_CORE_READ_INTO(&local_port_h, sk, __sk_common.skc_num)) { // <- ОКОНЧАТЕЛЬНЫЙ ПУТЬ
         #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Failed to read __sk_common.skc_num.\n");
        #endif
        kg_stats_inc(3);
        ctx->retval = -1; // EPERM или другая ошибка
        return 0;
    }
    // --- Конец получения порта источника ---

    // Ищем оригинальный адрес назначения, используя порт источника перенаправленного сокета.
    struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_redir_sport_to_orig, &local_port_h);
    if (!orig_dest) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: No original destination found for redir_src_port %u.\n", local_port_h);
        #endif
        return 1; // Позволяем ядру обработать
    }

    // Проверяем валидность и размер буфера пользователя.
    if (!ctx->optval || !ctx->optval_end ||
        (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for redir_src_port %u.\n", local_port_h);
        #endif
        bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);
        kg_stats_inc(3);
        ctx->retval = -14; // -EFAULT
        return 0;
    }

    // Подготавливаем структуру sockaddr_in для записи пользователю.
    struct sockaddr_in sa_out = {};
    sa_out.sin_family = AF_INET;
    bpf_core_read(&sa_out.sin_addr.s_addr, sizeof(sa_out.sin_addr.s_addr), &orig_dest->dst_ip);
    bpf_core_read(&sa_out.sin_port, sizeof(sa_out.sin_port), &orig_dest->dst_port); // dst_port в карте хранится в сетевом порядке

    // Записываем оригинальный адрес назначения в буфер пользователя.
    long ret = bpf_probe_write_user(ctx->optval, &sa_out, sizeof(sa_out));
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: bpf_probe_write_user failed for redir_src_port %u: %ld\n", local_port_h, ret);
        #endif
        bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);
        kg_stats_inc(3);
        ctx->retval = ret;
        return 0;
    }

    // Успешно записали данные. Устанавливаем возвращаемое значение и длину.
    ctx->retval = 0; // Успех
    ctx->optlen = sizeof(struct sockaddr_in);
    kg_stats_inc(2); // Увеличиваем getsockopt_ok

    // ВАЖНО: Очищаем запись в карте теперь, когда она успешно использована.
    bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT_OK: Provided original dest %x:%u (network order %u) for redir_src_port %u\n",
              sa_out.sin_addr.s_addr, bpf_ntohs(sa_out.sin_port), sa_out.sin_port, local_port_h);
    #endif

    return 0; // Говорим ядру, что мы успешно обработали вызов getsockopt.
}

char _license[] SEC("license") = "GPL";