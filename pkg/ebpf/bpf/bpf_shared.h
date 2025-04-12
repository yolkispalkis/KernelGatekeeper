// FILE: pkg/ebpf/bpf/bpf_shared.h
#ifndef BPF_SHARED_H
#define BPF_SHARED_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SO_ORIGINAL_DST 80

// --- Новая структура для ключа карты исключений ---
struct dev_inode_key {
    __u64 dev_id;   // Идентификатор устройства (dev_t как u64)
    __u64 inode_id; // Номер inode
};

// --- Существующие структуры ---
struct original_dest_t {
    __be32 dst_ip;
    __be16 dst_port;
    __u32  pid;
    __u32  uid;
};

struct kg_config_t {
    __u32 listener_ip;
    __u16 listener_port;
     __u16 padding;
};

struct global_stats_t {
    __u64 packets;
    __u64 bytes;
    __u64 redirected;
    __u64 getsockopt_ok;
    __u64 getsockopt_fail;
};

struct notification_tuple_t {
    __u64 pid_tgid;
    __be32 src_ip;
    __be32 orig_dst_ip;
    __be16 src_port;
    __be16 orig_dst_port;
    __u8   protocol;
};

// --- Карты (Maps) ---

// --- Новая карта для исключенных исполняемых файлов ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Настройте размер по необходимости
    __type(key, struct dev_inode_key);
    __type(value, __u8); // Значение 1 означает "исключено"
} excluded_dev_inodes SEC(".maps");

// --- Существующие карты ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192); // Используйте значение из конфига
    __type(key, __u64); // socket cookie
    __type(value, struct original_dest_t);
} kg_orig_dest SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192); // Используйте значение из конфига
    __type(key, __u16); // source port (host byte order)
    __type(value, __u64); // socket cookie
} kg_port_to_cookie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256); // Можно сделать настраиваемым
    __type(key, __u16); // target port (host byte order)
    __type(value, __u8); // 1 = target
} target_ports SEC(".maps");

// Карта PID'ов клиентских процессов для исключения (больше НЕ используется для исполняемых файлов)
// Оставляем на случай, если пригодится для исключения *самих* клиентских процессов
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // PID
    __type(value, __u8); // 1 = excluded
} kg_client_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kg_config_t);
} kg_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats_t);
} kg_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} kg_notif_rb SEC(".maps");


#endif // BPF_SHARED_H