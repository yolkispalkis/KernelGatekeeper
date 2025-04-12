// FILE: pkg/ebpf/bpf/getsockopt.c
//go:build ignore

#include "vmlinux.h" // Должен содержать определения struct sock, inet_sock и т.д. из BTF
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
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

    // --- Получаем порт источника из структуры сокета ---
    struct sock *sk;
    // Читаем указатель на сокет безопасно из контекста.
    // Прямой доступ ctx->sk обычно разрешен в этом хуке.
    sk = ctx->sk;
    if (!sk) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: ctx->sk is NULL.\n");
        #endif
        kg_stats_inc(3); // Увеличиваем getsockopt_fail
        ctx->retval = -1; // Возвращаем ошибку, например, EPERM
        return 0; // Обработали с ошибкой
    }

    // Читаем порт источника (inet_sport) с помощью CO-RE.
    // Требуется, чтобы BTF предоставлял определение inet_sock.
    __be16 sport_n; // Порт источника в сетевом порядке байт
    // Используем BPF_CORE_READ_INTO для безопасного доступа через указатели (inet_sock вложен в sock).
    if (BPF_CORE_READ_INTO(&sport_n, sk, inet_sport)) {
         #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Failed to read sk->inet_sport.\n");
        #endif
        kg_stats_inc(3);
        ctx->retval = -1; // EPERM или другая ошибка
        return 0; // Обработали с ошибкой
    }

    // Преобразуем порт источника в хостовый порядок байт для поиска в карте.
    __u16 local_port_h = bpf_ntohs(sport_n);
    // --- Конец получения порта источника ---


    // Ищем оригинальный адрес назначения, используя порт источника перенаправленного сокета.
    struct original_dest_t *orig_dest = bpf_map_lookup_elem(&kg_redir_sport_to_orig, &local_port_h);
    if (!orig_dest) {
        // Оригинальный адрес не найден для этого порта.
        // Это может случиться, если sockops не сработал или запись уже использована.
        // Позволяем ядру обработать getsockopt по умолчанию.
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_WARN: No original destination found for redir_src_port %u.\n", local_port_h);
        #endif
        // НЕ увеличиваем счетчик ошибок здесь.
        return 1; // Позволяем ядру обработать
    }

    // Проверяем валидность и размер буфера пользователя.
    if (!ctx->optval || !ctx->optval_end ||
        (void *)(ctx->optval + sizeof(struct sockaddr_in)) > ctx->optval_end) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: Invalid optval buffer for redir_src_port %u. optval=%p optval_end=%p needed=%d\n",
                  local_port_h, ctx->optval, ctx->optval_end, sizeof(struct sockaddr_in));
        #endif
        // Очищаем запись в карте, так как не можем ее доставить.
        bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);
        kg_stats_inc(3); // Увеличиваем getsockopt_fail
        ctx->retval = -14; // -EFAULT
        return 0; // Говорим ядру, что мы обработали (с ошибкой).
    }

    // Подготавливаем структуру sockaddr_in для записи пользователю.
    struct sockaddr_in sa_out = {};
    sa_out.sin_family = AF_INET;
    // Используем bpf_core_read для безопасного доступа к полям значения карты.
    bpf_core_read(&sa_out.sin_addr.s_addr, sizeof(sa_out.sin_addr.s_addr), &orig_dest->dst_ip);
    bpf_core_read(&sa_out.sin_port, sizeof(sa_out.sin_port), &orig_dest->dst_port);

    // Записываем оригинальный адрес назначения в буфер пользователя.
    long ret = bpf_probe_write_user(ctx->optval, &sa_out, sizeof(sa_out));
    if (ret != 0) {
        #ifdef DEBUG
        bpf_printk("GETSOCKOPT_ERR: bpf_probe_write_user failed for redir_src_port %u: %ld\n", local_port_h, ret);
        #endif
        // Очищаем запись в карте.
        bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);
        kg_stats_inc(3); // Увеличиваем getsockopt_fail
        ctx->retval = ret; // Возвращаем код ошибки от probe_write_user.
        return 0; // Говорим ядру, что мы обработали (с ошибкой).
    }

    // Успешно записали данные. Устанавливаем возвращаемое значение и длину.
    ctx->retval = 0; // Успех
    ctx->optlen = sizeof(struct sockaddr_in);
    kg_stats_inc(2); // Увеличиваем getsockopt_ok

    // ВАЖНО: Очищаем запись в карте теперь, когда она успешно использована.
    bpf_map_delete_elem(&kg_redir_sport_to_orig, &local_port_h);

    #ifdef DEBUG
    bpf_printk("GETSOCKOPT_OK: Provided original dest %x:%u for redir_src_port %u\n",
              sa_out.sin_addr.s_addr, bpf_ntohs(sa_out.sin_port), local_port_h);
    #endif

    // Говорим ядру, что мы успешно обработали вызов getsockopt.
    // Возврат 0 предотвращает запуск стандартного обработчика ядра.
    return 0;
}

char _license[] SEC("license") = "GPL";