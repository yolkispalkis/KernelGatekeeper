# KernelGatekeeper (Модель SockOps)

KernelGatekeeper - это решение для прозрачного проксирования сетевого трафика с использованием eBPF (`connect4`/`sock_ops`/`sk_msg`) и аутентификацией Kerberos от имени пользователя.

## Архитектура (Модель SockOps)

1.  **Системный Сервис (`kernelgatekeeper-service`, root):**
    *   Загружает BPF программы (`connect4`, `sock_ops`, `sk_msg`) и карты (`target_ports`, `connection_details_map`, `proxy_sock_map`, `notification_ringbuf`, `global_stats`).
    *   Прикрепляет `connect4` и `sock_ops` к корневой cgroup v2 для перехвата операций с сокетами всех процессов.
        *   `connect4`: Сохраняет информацию об *оригинальном* адресе назначения перед фактическим соединением.
        *   `sock_ops`: При установке соединения проверяет, совпадает ли *оригинальный* порт назначения с `target_ports`. Если да, добавляет сокет в `proxy_sock_map` и отправляет уведомление в `notification_ringbuf`.
    *   Прикрепляет `sk_msg` к `proxy_sock_map` для перенаправления данных для сокетов, добавленных `sock_ops`.
    *   Читает уведомления о новых соединениях для проксирования из BPF (`notification_ringbuf`).
    *   Передает уведомления (`notify_accept`), содержащие *оригинальный* адрес назначения, авторизованному клиентскому процессу через IPC (Unix-сокет).
    *   Предоставляет IPC для получения конфигурации и управления BPF (например, обновления `target_ports`, если разрешено).
    *   Собирает и логирует статистику BPF (счетчик совпавших соединений).

2.  **Клиентское Приложение (`kernelgatekeeper-client`, user):**
    *   Запускается как **пользовательский сервис** (`systemd --user`).
    *   Подключается к системному сервису (`kernelgatekeeper-service`) через IPC.
    *   **Регистрируется** у сервиса, сообщая свой PID (сервис получает реальный UID клиента из учетных данных сокета).
    *   Получает конфигурацию (настройки прокси, Kerberos) от сервиса.
    *   Инициализирует Kerberos, используя **кэш билетов текущего пользователя (ccache)**.
    *   Запускает **локальный TCP-сервер** (например, `127.0.0.1:3129`). Этот сервер принимает соединения, перенаправленные ядром через `sockmap`.
    *   **Слушает IPC-уведомления (`notify_accept`)** от сервиса.
    *   При получении уведомления:
        *   Принимает (`accept()`) входящее соединение на локальном сервере (это соединение от BPF sockmap).
        *   Использует данные из уведомления (**оригинальный** адрес и порт назначения), чтобы узнать, куда на самом деле хотело подключиться приложение.
        *   Устанавливает **новое соединение с реальным прокси-сервером**, указанным в конфигурации (или полученным через WPAD/PAC).
        *   Выполняет **HTTP CONNECT** запрос к прокси, используя `KerberosClient` для добавления `Proxy-Authorization: Negotiate ...`.
        *   Если CONNECT успешен, **проксирует данные** дуплексно между принятым соединением (от sockmap) и соединением к реальному прокси.

## Преимущества

*   **Прозрачность:** Приложения пользователя не требуют ручной настройки прокси.
*   **Аутентификация Пользователя:** Используется Kerberos-билет конкретного пользователя, от имени которого запущено приложение.
*   **Без iptables:** Перенаправление выполняется через eBPF (`sockmap`/`sk_msg`), что потенциально эффективнее.

## Требования

*   **Linux kernel >= 5.6:** Требуется стабильная поддержка BPF `sock_ops`, `sockmap`, `sk_msg`, `ringbuf` и прикрепления BPF к cgroup.
*   **cgroup v2:** Система должна использовать cgroup v2, смонтированную в `/sys/fs/cgroup`. Проверьте командой `mount | grep cgroup2`.
*   **Go >= 1.21** (см. `go.mod`)
*   **LLVM/Clang >= 10** (для компиляции BPF C кода)
*   **libelf-dev, libbpf-dev**
*   **Заголовки ядра:** Обычно пакет `linux-headers-$(uname -r)`
*   **Build essentials:** `make`, `git`

## Установка

```bash
# Установка зависимостей (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r) make golang git adduser

# Проверка cgroup v2 (должна быть строка с type cgroup2)
mount | grep cgroup2
if [ $? -ne 0 ]; then
    echo "Ошибка: cgroup v2 не найдена. KernelGatekeeper требует cgroup v2."
    # Инструкции по включению cgroup v2 зависят от дистрибутива
    exit 1
fi

# Клонирование и сборка
git clone https://github.com/yolki/kernelgatekeeper.git
cd kernelgatekeeper
make generate # Важно: Компилирует BPF C код и генерирует Go обертки
make all      # Собирает сервис и клиент

# Установка (или используйте `make deb` для сборки пакета)
sudo make install
```

**После установки (`make install`):**

1.  **(Опционально)** Проверьте и адаптируйте конфигурацию: `/etc/kernelgatekeeper/config.yaml`
2.  Перезагрузите демоны systemd:
    ```bash
    sudo systemctl daemon-reload
    systemctl --user daemon-reload # От имени целевого пользователя!
    ```
3.  Включите и запустите **системный** сервис:
    ```bash
    sudo systemctl enable --now kernelgatekeeper.service
    ```
4.  Включите и запустите **пользовательский** сервис (от имени целевого пользователя):
    ```bash
    systemctl --user enable --now kernelgatekeeper-client.service
    ```

**Установка через DEB пакет:**

1.  Соберите пакет: `make deb`
2.  Установите пакет: `sudo dpkg -i kernelgatekeeper_*.deb`
3.  При установке пакета postinst скрипт попытается включить и запустить системный сервис. Пользовательский сервис потребует ручного включения (см. шаг 4 выше) или автоматически включится при следующем входе пользователя в систему (через `profile.d` скрипт).

## Конфигурация (`/etc/kernelgatekeeper/config.yaml`)

Конфигурация используется как сервисом, так и клиентом (клиент получает её от сервиса по IPC).

```yaml
# config.yaml
proxy: # Параметры, используемые клиентом kernelgatekeeper-client
  type: http # Тип прокси: http, https, wpad, none. Определяет, как клиент находит прокси.
  url: "http://proxy.example.com:3128" # URL прокси, если type=http/https
  wpad_url: "http://wpad.example.com/wpad.dat" # URL для WPAD, если type=wpad
  connection_timeout: 10 # Таймаут подключения клиента к прокси (секунды)
  request_timeout: 30 # Таймаут HTTP CONNECT запроса к прокси (секунды)
  max_retries: 3 # Попытки переподключения клиента к прокси
  pac_charset: "" # Опционально: Кодировка PAC файла (напр., "windows-1251"). По умолчанию UTF-8/автоопределение.
  pac_execution_timeout: 5 # Макс. время выполнения PAC скрипта (секунды)

kerberos: # Подсказки для клиента (использует кэш билетов пользователя ccache)
  realm: "EXAMPLE.COM" # Опционально: Указывает realm по умолчанию. Если пусто, используется системный default_realm.
  enable_cache: true # Всегда true для этой модели, клиент работает с ccache.
  # Остальные параметры (kdc_host, principal, keytab_path, ticket_lifetime, cache_path) - информационные, не используются клиентом напрямую.

ebpf: # Параметры, используемые сервисом kernelgatekeeper-service для управления BPF
  # interface: "eth0" # Не используется в SockOps модели (привязка к cgroup), оставлено для информации/статистики.
  target_ports: [80, 443, 8080] # Порты назначения, трафик на которые будет перехвачен BPF sock_ops.
  allow_dynamic_ports: true # Разрешить сервису обновлять BPF карту target_ports через IPC команду от клиента.
  stats_interval: 15 # Интервал логирования статистики BPF сервисом (секунды).
  notification_channel_size: 4096 # Размер буфера канала между BPF ringbuf reader и обработчиком уведомлений в сервисе.

# Настройки логирования сервиса
log_level: "info" # Уровни: debug, info, warn, error
log_path: "/var/log/kernelgatekeeper.log" # Путь к лог-файлу сервиса. Если пусто, вывод в stderr (journald).

# Общие настройки сервиса
shutdown_timeout: 30 # Таймаут корректного завершения работы сервиса (секунды).
socket_path: "/var/run/kernelgatekeeper.sock" # Путь к Unix-сокету для IPC между сервисом и клиентами.
```

## Использование

*   **Сервис (системный):** Управляется через `sudo systemctl (start|stop|status|restart) kernelgatekeeper.service`.
    *   Логи: `sudo journalctl -u kernelgatekeeper.service -f` или `sudo tail -f /var/log/kernelgatekeeper.log`.
    *   Перезагрузка конфигурации (применяет `log_level`, `log_path`, `target_ports`, `shutdown_timeout` без перезапуска): `sudo systemctl kill -s SIGHUP kernelgatekeeper.service`.
*   **Клиент (пользовательский):** Управляется через `systemctl --user (start|stop|status|restart) kernelgatekeeper-client.service` (от имени пользователя).
    *   Логи: `journalctl --user -u kernelgatekeeper-client.service -f`.
*   **Проверка:** Убедитесь, что у пользователя есть действительный Kerberos TGT (`klist`). Запустите сетевое приложение (например, `curl http://example.com`, где example.com настроен на перехват в `target_ports`). Трафик должен автоматически проксироваться через прокси, указанный в конфигурации, с использованием Kerberos аутентификации пользователя. Переменные окружения `http_proxy`/`https_proxy` **не должны** быть установлены.

## Отладка BPF

Для отладки проблем с eBPF программами и картами:

*   **Просмотр вывода `bpf_printk` из BPF программ (если `DEBUG` включен при компиляции):**
    ```bash
    sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E 'CONNECT4|SOCKOPS|SKMSG'
    ```
*   **Список загруженных BPF программ:**
    ```bash
    sudo bpftool prog list
    ```
*   **Просмотр содержимого BPF карт:**
    ```bash
    sudo bpftool map list # Найти ID нужных карт
    sudo bpftool map dump name connection_details_map # Карта данных от connect4
    sudo bpftool map dump name target_ports           # Целевые порты
    sudo bpftool map dump name proxy_sock_map         # Карта для перенаправления сокетов
    sudo bpftool map dump name global_stats           # Статистика
    ```
*   **Проверка прикрепления BPF программ к cgroup:**
    ```bash
    sudo bpftool cgroup tree /sys/fs/cgroup # Искать программы connect4 и sock_ops
    ```
*   **Проверка прикрепления `sk_msg` к `proxy_sock_map`:** Вывод `bpftool prog list` покажет `map_ids` для `sk_msg` программы.

## Разработка

Используйте `Makefile` для стандартных задач:

*   `make generate`: Компиляция BPF C кода и генерация Go оберток (`*_bpf*.go`). **Необходимо запускать после изменений в `pkg/ebpf/bpf/*.c` или `pkg/ebpf/bpf/bpf_shared.h`**.
*   `make all`: Форматирование, линтинг, тесты, генерация BPF, сборка Go бинарников (`bin/kernelgatekeeper-service`, `bin/kernelgatekeeper-client`).
*   `make build`: Только сборка Go бинарников (предполагает, что BPF код уже сгенерирован).
*   `make test`: Запуск Go тестов.
*   `make fmt`: Форматирование Go кода.
*   `make lint`: Запуск `golangci-lint` (если установлен).
*   `make clean`: Удаление бинарников, сгенерированных файлов BPF и артефактов сборки DEB.
*   `make install`: Локальная установка для разработки (копирует бинарники, конфиг, systemd юниты).
*   `make deb`: Сборка Debian пакета.
*   `make run-service`: Запуск сервиса локально (требует `sudo`).
*   `make run-client`: Запуск клиента локально.

## Лицензия

MIT
