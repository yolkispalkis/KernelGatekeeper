# KernelGatekeeper (SockOps Model)

KernelGatekeeper - это решение для прозрачного проксирования сетевого трафика с использованием eBPF `sockops`/`sockmap` и аутентификацией Kerberos от имени пользователя.

**Архитектура (Модель SockOps):**

1.  **Системный Сервис (`kernelgatekeeper-service`, root):**
    *   Загружает BPF программы (`sock_ops`, `sk_msg`) и карты (`target_ports`, `process_map`, `connection_map`, `proxy_sock_map`, `notification_ringbuf`).
    *   Прикрепляет `sock_ops` к cgroup v2 для перехвата операций с сокетами процессов.
    *   Прикрепляет `sk_msg` к `proxy_sock_map` для перенаправления данных.
    *   Управляет картой `process_map`, регистрируя активные клиентские процессы (по UID).
    *   Читает уведомления о новых соединениях для проксирования из BPF (`notification_ringbuf`).
    *   Передает уведомления (`notify_accept`) авторизованному клиентскому процессу через IPC (Unix-сокет).
    *   Предоставляет IPC для получения конфигурации и управления BPF (порты).
    *   Собирает и логирует статистику BPF.

2.  **Клиентское Приложение (`kernelgatekeeper-client`, user):**
    *   Запускается как **пользовательский сервис** (`systemd --user`).
    *   Подключается к системному сервису (`kernelgatekeeper-service`) через IPC.
    *   **Регистрируется** у сервиса, сообщая свой PID (UID берется сервисом).
    *   Получает конфигурацию (настройки прокси, Kerberos) от сервиса.
    *   Инициализирует Kerberos, используя **кэш билетов текущего пользователя (ccache)**.
    *   Запускает **локальный TCP-сервер** (напр., `127.0.0.1:3129`).
    *   **Слушает IPC-уведомления (`notify_accept`)** от сервиса.
    *   При получении уведомления:
        *   Принимает (`accept()`) входящее соединение на локальном сервере (это соединение, перенаправленное ядром через `sockmap`).
        *   Использует данные из уведомления (оригинальный адрес назначения).
        *   Устанавливает **новое соединение с реальным прокси-сервером**.
        *   Выполняет **CONNECT** запрос к прокси, используя `KerberosClient` для добавления `Proxy-Authorization`.
        *   Если CONNECT успешен, **проксирует данные** дуплексно между принятым соединением (от sockmap) и соединением к реальному прокси.
    *   **Не** устанавливает переменные окружения `http_proxy`.

**Преимущества:**

*   **Прозрачность:** Приложения пользователя не требуют настройки прокси.
*   **Аутентификация Пользователя:** Используется Kerberos-билет конкретного пользователя.
*   **Без iptables:** Перенаправление выполняется через eBPF `sockmap`/`sk_msg`.

**Недостатки и Сложности:**

*   **Требования к Ядру:** Необходима поддержка BPF `sock_ops`, `sockmap`, `sk_msg`, cgroup v2 (ядра ~5.6+).
*   **Сложность BPF:** Программы `sock_ops` и `sk_msg` сложны в написании и отладке.
*   **Координация:** Надежное взаимодействие BPF <-> Service (ringbuf) <-> Client (IPC) критично.
*   **Производительность:** Дополнительный хоп через userspace клиентский прокси вносит задержки.
*   **Безопасность:** Требуется проверка UID при регистрации клиента в сервисе.

## Зависимости

*   Linux kernel >= 5.6 (с поддержкой sockops, sockmap, sk_msg, cgroup v2, ringbuf)
*   Go >= 1.21
*   LLVM/Clang >= 10
*   libelf-dev, libbpf-dev
*   Заголовки ядра
*   Включенная и смонтированная cgroup v2 (`/sys/fs/cgroup`)

## Установка

```bash
# Установка зависимостей (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r) make golang git

# Проверка cgroup v2
mount | grep cgroup2 # Должен показать /sys/fs/cgroup type cgroup2 ...

# Клонирование и сборка
git clone https://github.com/yolki/kernelgatekeeper.git
cd kernelgatekeeper
make generate # Важно для компиляции BPF
make all

# Установка
sudo make install
```
**После установки:**
1.  **Проверьте конфигурацию:** `/etc/kernelgatekeeper/config.yaml`
2.  **Включите системный сервис:**
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable --now kernelgatekeeper.service
    ```
3.  **Включите пользовательский сервис (от имени нужного пользователя):**
    ```bash
    systemctl --user daemon-reload
    systemctl --user enable --now kernelgatekeeper-client.service
    ```

## Конфигурация (`/etc/kernelgatekeeper/config.yaml`)

```yaml
proxy: # Используется клиентом
  type: http # http, https, wpad, none
  url: "http://proxy.example.com:3128"
  wpad_url: "http://wpad.example.com/wpad.dat"
  connection_timeout: 10 # сек
  request_timeout: 30 # сек
  max_retries: 3

kerberos: # Подсказки для клиента (использует ccache)
  realm: "EXAMPLE.COM"
  enable_cache: true # Всегда true для этой модели

ebpf: # Используется сервисом
  interface: "eth0" # Информационно, sockops привязан к cgroup
  target_ports: [80, 443] # Порты для перенаправления BPF
  load_mode: "sockops" # Информационно
  allow_dynamic_ports: true # Разрешить обновление портов через IPC
  stats_interval: 15 # сек

# Настройки сервиса
log_level: "info" # debug, info, warn, error
log_path: "/var/log/kernelgatekeeper.log"
shutdown_timeout: 30 # сек
socket_path: "/var/run/kernelgatekeeper.sock" # IPC
```

## Использование

*   **Сервис:** Управляется через `sudo systemctl (start|stop|status|restart) kernelgatekeeper.service`. Логи: `sudo journalctl -u kernelgatekeeper.service -f` или `/var/log/kernelgatekeeper.log`. Перезагрузка конфига: `sudo systemctl kill -s SIGHUP kernelgatekeeper.service`.
*   **Клиент:** Управляется через `systemctl --user (start|stop|status|restart) kernelgatekeeper-client.service`. Логи: `journalctl --user -u kernelgatekeeper-client.service -f`.
*   **Проверка:** Попробуйте использовать сетевые приложения (curl, браузер) **без** установленных `http_proxy` переменных. Трафик на целевые порты должен автоматически проксироваться.

## Отладка BPF

*   `sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E 'SOCKOPS|SKMSG'`
*   `sudo bpftool prog list`
*   `sudo bpftool map dump name process_map`
*   `sudo bpftool map dump name connection_map`
*   `sudo bpftool map dump name proxy_sock_map`
*   `sudo bpftool cgroup tree /sys/fs/cgroup` (искать прикрепленные `sock_ops`)

## Разработка

```bash
make generate # Обязательно после изменений BPF C кода
make all      # Сборка Go + BPF (через generate)
make test     # Запуск тестов Go
make install  # Установка
make run-service # Запуск сервиса для отладки (требует sudo)
make run-client  # Запуск клиента для отладки
```