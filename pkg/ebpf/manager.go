// FILE: pkg/ebpf/manager.go
package ebpf

//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_connect4 ./bpf/connect4.c -- -I./bpf -D__TARGET_ARCH_x86
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_sockops ./bpf/sockops.c -- -I./bpf -D__TARGET_ARCH_x86
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_getsockopt ./bpf/getsockopt.c -- -I./bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath" // Добавлено для Clean
	"sync"
	"syscall" // Добавлено для Stat_t
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

const (
	StatsRedirectedIndex     uint32 = 1
	StatsGetsockoptOkIndex   uint32 = 2
	StatsGetsockoptFailIndex uint32 = 3
	DefaultCgroupPath               = "/sys/fs/cgroup"
	ExcludedMapMaxEntries           = 1024 // Соответствует bpf_shared.h
)

// --- Существующие типы ---
type GlobalStats struct {
	Packets        uint64
	Bytes          uint64
	Redirected     uint64
	GetsockoptOk   uint64
	GetsockoptFail uint64
}

type OriginalDestT = bpf_connect4OriginalDestT
type BpfGlobalStatsT = bpf_connect4GlobalStatsT
type BpfKgConfigT = bpf_connect4KgConfigT
type BpfDevInodeKey = bpf_connect4DevInodeKey // Тип ключа для новой карты

type bpfObjects struct {
	bpf_connect4Objects // Включает и программы, и карты из connect4.c
	bpf_sockopsObjects
	bpf_getsockoptObjects

	// --- Явные указатели на программы (для attach) ---
	KernelgatekeeperConnect4   *ebpf.Program `ebpf:"kernelgatekeeper_connect4"`
	KernelgatekeeperSockops    *ebpf.Program `ebpf:"kernelgatekeeper_sockops"`
	KernelgatekeeperGetsockopt *ebpf.Program `ebpf:"kernelgatekeeper_getsockopt"`

	// --- Явные указатели на карты (для доступа и обновлений) ---
	// Карты, определенные в connect4.c (bpf2go положит их в bpf_connect4Objects)
	ExcludedDevInodes *ebpf.Map `ebpf:"excluded_dev_inodes"` // <<< Новая карта
	KgOrigDest        *ebpf.Map `ebpf:"kg_orig_dest"`
	KgPortToCookie    *ebpf.Map `ebpf:"kg_port_to_cookie"`
	TargetPorts       *ebpf.Map `ebpf:"target_ports"`
	KgClientPids      *ebpf.Map `ebpf:"kg_client_pids"`
	KgConfig          *ebpf.Map `ebpf:"kg_config"`
	KgStats           *ebpf.Map `ebpf:"kg_stats"`
	KgNotifRb         *ebpf.Map `ebpf:"kg_notif_rb"`
}

// Close закрывает все объекты BPF.
func (o *bpfObjects) Close() error {
	closers := []io.Closer{
		// Закрываем объекты коллекций, они должны закрыть свои программы и карты
		&o.bpf_connect4Objects,
		&o.bpf_sockopsObjects,
		&o.bpf_getsockoptObjects,
	}
	var errs []error
	for _, closer := range closers {
		if c, ok := closer.(interface{ Close() error }); ok && c != nil {
			// Проверка на nil перед вызовом Close
			if closer != nil { // Дополнительная проверка, т.к. bpf_xxObjects могут быть nil если load не удался
				if err := c.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, ebpf.ErrObjectClosed) {
					errs = append(errs, err)
				}
			}
		}
	}

	// Явное закрытие программ и карт не требуется, если они являются частью коллекций.
	// Но для надежности можно добавить, если есть сомнения.

	if len(errs) > 0 {
		finalErr := errors.New("errors closing BPF objects")
		for _, err := range errs {
			finalErr = fmt.Errorf("%w; %w", finalErr, err)
		}
		return finalErr
	}
	return nil
}

type BPFManager struct {
	cfg                 *config.EBPFConfig
	objs                bpfObjects
	connect4Link        link.Link
	sockopsLink         link.Link
	getsockoptLink      link.Link
	stopOnce            sync.Once
	stopChan            chan struct{}
	statsCache          StatsCache
	mu                  sync.Mutex // Защищает доступ к картам и ссылкам из Go
	notificationReader  *ringbuf.Reader
	notificationChannel chan NotificationTuple
	currentExcluded     map[BpfDevInodeKey]string // Кэш текущих исключенных dev/inode и путей (для очистки)
}

func NewBPFManager(cfg *config.EBPFConfig, listenerIP net.IP, listenerPort uint16) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "connect4/sockops/getsockopt")
	if err := rlimit.RemoveMemlock(); err != nil {
		// Часто это не критично, но логируем как Warn
		slog.Warn("Failed to remove memlock rlimit, BPF loading might fail if limits are low", "error", err)
		// return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	var objs bpfObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// PinPath: "/sys/fs/bpf/kernelgatekeeper", // Опционально, если нужно пинить
		},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction, // Более детально для отладки
			LogSize:  ebpf.DefaultVerifierLogSize * 8,
		},
	}

	// 1. Загружаем первую коллекцию (connect4), которая определяет все основные карты
	specConnect4, err := loadBpf_connect4()
	if err != nil {
		return nil, fmt.Errorf("failed to load connect4 BPF spec: %w", err)
	}

	// Задаем размеры карт перед первой загрузкой, если они отличаются от дефолтных в C коде
	// Важно: имена должны точно совпадать с именами карт в C коде
	adjustMapSpec := func(spec *ebpf.MapSpec, name string, maxEntries uint32) {
		if spec != nil && spec.Name == name && maxEntries > 0 {
			spec.MaxEntries = maxEntries
			slog.Debug("Adjusting map spec size", "map", name, "new_max_entries", maxEntries)
		}
	}
	if maps := specConnect4.Maps; maps != nil {
		adjustMapSpec(maps["kg_orig_dest"], "kg_orig_dest", uint32(cfg.OrigDestMapSize))
		adjustMapSpec(maps["kg_port_to_cookie"], "kg_port_to_cookie", uint32(cfg.PortMapSize))
		adjustMapSpec(maps["excluded_dev_inodes"], "excluded_dev_inodes", ExcludedMapMaxEntries) // Размер новой карты
		// target_ports, kg_client_pids и другие можно настроить аналогично, если нужно
	}

	// Загружаем connect4 и его карты
	if err := specConnect4.LoadAndAssign(&objs.bpf_connect4Objects, opts); err != nil {
		handleVerifierError("connect4", err)
		return nil, fmt.Errorf("failed to load eBPF connect4 objects: %w", err)
	}
	slog.Debug("eBPF connect4 objects loaded successfully.")

	// Присваиваем явные указатели на карты ИЗ УЖЕ ЗАГРУЖЕННЫХ объектов connect4
	objs.ExcludedDevInodes = objs.bpf_connect4Objects.ExcludedDevInodes
	objs.KgOrigDest = objs.bpf_connect4Objects.KgOrigDest
	objs.KgPortToCookie = objs.bpf_connect4Objects.KgPortToCookie
	objs.TargetPorts = objs.bpf_connect4Objects.TargetPorts
	objs.KgClientPids = objs.bpf_connect4Objects.KgClientPids
	objs.KgConfig = objs.bpf_connect4Objects.KgConfig
	objs.KgStats = objs.bpf_connect4Objects.KgStats
	objs.KgNotifRb = objs.bpf_connect4Objects.KgNotifRb

	// 2. Загружаем sockops, ЗАМЕНЯЯ карты ссылками на уже загруженные
	specSockops, err := loadBpf_sockops()
	if err != nil {
		objs.bpf_connect4Objects.Close() // Очистка
		return nil, fmt.Errorf("failed to load sockops BPF spec: %w", err)
	}
	opts.MapReplacements = map[string]*ebpf.Map{
		"kg_orig_dest":      objs.KgOrigDest,
		"kg_port_to_cookie": objs.KgPortToCookie,
		"kg_notif_rb":       objs.KgNotifRb,
		// sockops не использует target_ports, kg_client_pids, kg_config, kg_stats, excluded_dev_inodes
	}
	if err := specSockops.LoadAndAssign(&objs.bpf_sockopsObjects, opts); err != nil {
		handleVerifierError("sockops", err)
		objs.bpf_connect4Objects.Close()
		return nil, fmt.Errorf("failed to load eBPF sockops objects: %w", err)
	}
	slog.Debug("eBPF sockops objects loaded successfully.")

	// 3. Загружаем getsockopt, ЗАМЕНЯЯ карты ссылками на уже загруженные
	specGetsockopt, err := loadBpf_getsockopt()
	if err != nil {
		objs.bpf_connect4Objects.Close()
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load getsockopt BPF spec: %w", err)
	}
	opts.MapReplacements = map[string]*ebpf.Map{
		"kg_orig_dest":      objs.KgOrigDest,
		"kg_port_to_cookie": objs.KgPortToCookie,
		"kg_stats":          objs.KgStats,
		// getsockopt не использует target_ports, kg_client_pids, kg_config, kg_notif_rb, excluded_dev_inodes
	}
	if err := specGetsockopt.LoadAndAssign(&objs.bpf_getsockoptObjects, opts); err != nil {
		handleVerifierError("getsockopt", err)
		objs.bpf_connect4Objects.Close()
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load eBPF getsockopt objects: %w", err)
	}
	slog.Debug("eBPF getsockopt objects loaded successfully.")

	// Присваиваем явные указатели на ПРОГРАММЫ
	objs.KernelgatekeeperConnect4 = objs.bpf_connect4Objects.KernelgatekeeperConnect4
	objs.KernelgatekeeperSockops = objs.bpf_sockopsObjects.KernelgatekeeperSockops
	objs.KernelgatekeeperGetsockopt = objs.bpf_getsockoptObjects.KernelgatekeeperGetsockopt

	// --- Проверка что все нужные объекты загружены ---
	if objs.KernelgatekeeperConnect4 == nil || objs.KernelgatekeeperSockops == nil || objs.KernelgatekeeperGetsockopt == nil ||
		objs.KgOrigDest == nil || objs.KgPortToCookie == nil || objs.TargetPorts == nil || objs.KgClientPids == nil || objs.KgNotifRb == nil ||
		objs.KgConfig == nil || objs.KgStats == nil || objs.ExcludedDevInodes == nil { // <<< Проверка новой карты
		manager := &BPFManager{objs: objs} // Создаем временный менеджер для корректной очистки
		manager.Close()
		return nil, errors.New("one or more required BPF programs or maps failed to load or assign")
	}

	// --- Инициализация менеджера ---
	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs,
		stopChan:            make(chan struct{}),
		notificationChannel: make(chan NotificationTuple, cfg.NotificationChannelSize),
		currentExcluded:     make(map[BpfDevInodeKey]string), // Инициализация кэша исключений
	}
	manager.statsCache.lastStatsTime = time.Now()

	// --- Инициализация читателя Ring Buffer ---
	rd, err := ringbuf.NewReader(objs.KgNotifRb)
	if err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	manager.notificationReader = rd
	slog.Info("BPF ring buffer reader initialized.")

	// --- Первоначальное заполнение карт из конфига ---
	if err := manager.UpdateConfigMap(listenerIP, listenerPort); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial BPF config map: %w", err)
	}
	if err := manager.UpdateTargetPorts(cfg.TargetPorts); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial target ports in BPF map: %w", err)
	}
	// <<< Заполняем карту исключений >>>
	if err := manager.UpdateExcludedExecutables(cfg.Excluded); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial excluded executables in BPF map: %w", err)
	}

	// --- Аттачим программы к cgroup ---
	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close()
		return nil, err // Ошибка уже содержит детали
	}

	slog.Info("BPF Manager initialized and programs attached successfully.")
	return manager, nil
}

// --- Остальные методы (attachPrograms, Start, Close, GetNotificationChannel) остаются почти без изменений ---
// --- Добавляем функцию UpdateExcludedExecutables ---

// getDevInodeFromFile получает dev_t и inode для заданного пути файла.
// Возвращает BpfDevInodeKey и ошибку.
func getDevInodeFromFile(filePath string) (BpfDevInodeKey, error) {
	var key BpfDevInodeKey
	// Очищаем путь для канонического представления
	cleanedPath := filepath.Clean(filePath)
	fileInfo, err := os.Stat(cleanedPath)
	if err != nil {
		return key, fmt.Errorf("failed to stat file %s: %w", cleanedPath, err)
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		// Это не должно происходить на Linux. Добавим проверку на всякий случай.
		return key, fmt.Errorf("failed to convert FileInfo.Sys() to syscall.Stat_t for %s (unexpected OS or type?)", cleanedPath)
	}

	// ВАЖНО: syscall.Stat_t.Dev имеет тип uint64 на Linux (начиная с ~2.6 ядер),
	// который соответствует dev_t ядра. Проблем с 32-битными dev_t быть не должно
	// при использовании syscall.Stat_t на современных системах.
	key.DevId = stat.Dev   // Прямое присваивание uint64 -> __u64
	key.InodeId = stat.Ino // Прямое присваивание uint64 -> __u64

	// Дополнительная проверка на нулевые значения (маловероятно для существующих файлов)
	if key.DevId == 0 || key.InodeId == 0 {
		slog.Warn("Stat returned zero dev or inode for existing file, this is unusual", "path", cleanedPath, "dev", key.DevId, "inode", key.InodeId)
	}

	return key, nil
}

// UpdateExcludedExecutables обновляет BPF карту excluded_dev_inodes на основе списка путей.
func (m *BPFManager) UpdateExcludedExecutables(paths []string) error {
	m.mu.Lock() // Используем мьютекс BPFManager для защиты карты и кэша
	defer m.mu.Unlock()

	excludeMap := m.objs.ExcludedDevInodes
	if excludeMap == nil {
		return errors.New("BPF excluded_dev_inodes map not initialized")
	}

	slog.Debug("Updating BPF excluded executables map...", "requested_paths_count", len(paths))

	// 1. Определить новый желаемый набор dev/inode
	desiredExcluded := make(map[BpfDevInodeKey]string) // Карта dev/inode -> путь (для логирования)
	var errorsList []error
	for _, p := range paths {
		if p == "" {
			continue
		}
		key, err := getDevInodeFromFile(p)
		if err != nil {
			// Логируем ошибку, но продолжаем с остальными путями
			slog.Error("Failed to get dev/inode for excluded path, skipping", "path", p, "error", err)
			errorsList = append(errorsList, fmt.Errorf("path '%s': %w", p, err))
			continue
		}
		desiredExcluded[key] = p // Сохраняем путь для информации
	}

	// 2. Определить, что нужно удалить из BPF карты (ключи есть в кэше, но нет в desired)
	keysToDelete := make([]BpfDevInodeKey, 0)
	for cachedKey, cachedPath := range m.currentExcluded {
		if _, exists := desiredExcluded[cachedKey]; !exists {
			keysToDelete = append(keysToDelete, cachedKey)
			slog.Debug("Marking for deletion from BPF exclude map", "dev", cachedKey.DevId, "inode", cachedKey.InodeId, "path", cachedPath)
		}
	}

	// 3. Определить, что нужно добавить/обновить в BPF карте (ключи есть в desired, но нет в кэше)
	keysToAdd := make(map[BpfDevInodeKey]string)
	for desiredKey, desiredPath := range desiredExcluded {
		if _, exists := m.currentExcluded[desiredKey]; !exists {
			keysToAdd[desiredKey] = desiredPath
			slog.Debug("Marking for addition to BPF exclude map", "dev", desiredKey.DevId, "inode", desiredKey.InodeId, "path", desiredPath)
		}
	}

	// 4. Выполнить удаление из BPF карты
	var deleteErrors []error
	var valueOne uint8 = 1 // Значение для добавления
	for _, key := range keysToDelete {
		if err := excludeMap.Delete(key); err != nil {
			// Игнорируем ошибку "ключ не найден", но логируем другие
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("Failed to delete key from BPF exclude map", "dev", key.DevId, "inode", key.InodeId, "error", err)
				deleteErrors = append(deleteErrors, err)
			}
		} else {
			// Успешно удалено из BPF, удаляем из кэша
			delete(m.currentExcluded, key)
		}
	}

	// 5. Выполнить добавление в BPF карту
	var addErrors []error
	for key, path := range keysToAdd {
		if err := excludeMap.Put(key, valueOne); err != nil {
			slog.Error("Failed to add key to BPF exclude map", "dev", key.DevId, "inode", key.InodeId, "path", path, "error", err)
			addErrors = append(addErrors, err)
		} else {
			// Успешно добавлено в BPF, добавляем в кэш
			m.currentExcluded[key] = path
		}
	}

	// 6. Обработка ошибок
	finalError := ""
	if len(errorsList) > 0 {
		finalError += fmt.Sprintf("Stat errors: %v. ", errorsList)
	}
	if len(deleteErrors) > 0 {
		finalError += fmt.Sprintf("Delete errors: %v. ", deleteErrors)
	}
	if len(addErrors) > 0 {
		finalError += fmt.Sprintf("Add errors: %v.", addErrors)
	}

	if finalError != "" {
		slog.Error("Errors occurred during BPF excluded executables update", "details", finalError)
		return errors.New("failed to fully update BPF excluded executables map: " + finalError)
	}

	slog.Info("BPF excluded executables map updated successfully", "current_excluded_count", len(m.currentExcluded))
	// Обновляем конфиг в памяти менеджера (если нужно)
	if m.cfg != nil {
		m.cfg.Excluded = paths // Сохраняем исходный список путей
	}
	return nil
}

// --- Вспомогательные функции и остальной код manager.go ---
// handleVerifierError, attachPrograms, Start, Close, GetNotificationChannel, etc.
// Они остаются в основном без изменений, но нужно убедиться, что
// Close() корректно обрабатывает все объекты, включая новую карту,
// хотя она и должна закрываться через bpf_connect4Objects.Close().

// ... (остальной код manager.go без изменений) ...

// Добавим реализацию для handleVerifierError, attachPrograms, Start, Close, GetNotificationChannel, если они не были скопированы ранее

func handleVerifierError(objType string, err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		slog.Error(fmt.Sprintf("eBPF Verifier error (loading %s objects)", objType), "log", fmt.Sprintf("%+v", verr))
		// Печать лога верификатора может быть очень большой, возможно стоит обрезать
		logOutput := fmt.Sprintf("%+v", verr)
		maxLen := 2048
		if len(logOutput) > maxLen {
			logOutput = logOutput[:maxLen] + "..."
		}
		slog.Debug("eBPF Verifier Log (truncated)", "log_output", logOutput)
	}
}

func (m *BPFManager) attachPrograms(cgroupPath string) error {
	connect4Prog := m.objs.KernelgatekeeperConnect4
	sockopsProg := m.objs.KernelgatekeeperSockops
	getsockoptProg := m.objs.KernelgatekeeperGetsockopt

	if connect4Prog == nil || sockopsProg == nil || getsockoptProg == nil {
		return errors.New("internal error: one or more required BPF programs are nil during attach phase")
	}

	// Проверка пути cgroup v2
	fi, err := os.Stat(cgroupPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Попытка создать директорию cgroup v2, если ее нет
			// Это может не сработать в зависимости от прав и структуры cgroup
			slog.Warn("Cgroup v2 path does not exist, attempting to create", "path", cgroupPath)
			// if err := os.MkdirAll(cgroupPath, 0755); err != nil {
			// 	return fmt.Errorf("cgroup v2 path '%s' does not exist and could not be created: %w", cgroupPath, err)
			// }
			// fi, err = os.Stat(cgroupPath) // Повторно статаем
			// if err != nil {
			return fmt.Errorf("cgroup v2 path '%s' does not exist: %w", cgroupPath, err) // Ошибка, если стат все еще не удался
			// }
		} else {
			return fmt.Errorf("failed to stat cgroup v2 path '%s': %w", cgroupPath, err)
		}
	}
	if !fi.IsDir() {
		return fmt.Errorf("cgroup v2 path '%s' is not a directory", cgroupPath)
	}

	// Аттачим программы
	var linkErr error
	m.connect4Link, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: connect4Prog, Attach: ebpf.AttachCGroupInet4Connect})
	if linkErr != nil {
		return fmt.Errorf("failed to attach connect4 program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF connect4 program attached to cgroup", "path", cgroupPath)

	m.sockopsLink, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: sockopsProg, Attach: ebpf.AttachCGroupSockOps})
	if linkErr != nil {
		m.connect4Link.Close() // Откатываем предыдущий аттач
		return fmt.Errorf("failed to attach sock_ops program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF sock_ops program attached to cgroup", "path", cgroupPath)

	m.getsockoptLink, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: getsockoptProg, Attach: ebpf.AttachCGroupGetsockopt})
	if linkErr != nil {
		m.sockopsLink.Close() // Откатываем предыдущие аттачи
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach getsockopt program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF getsockopt program attached to cgroup", "path", cgroupPath)

	return nil
}

func (m *BPFManager) Start(ctx context.Context, wg *sync.WaitGroup) error {
	// m.mu.Lock() // Блокировка не нужна здесь, т.к. Start вызывается один раз
	// defer m.mu.Unlock()

	slog.Info("Starting BPF Manager background tasks...")

	// Запускаем обновление статистики
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.statsUpdater(ctx) // Использует внутренний ticker
	}()

	// Запускаем чтение уведомлений из ring buffer
	if m.notificationReader != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.readNotifications(ctx)
		}()
	} else {
		slog.Warn("BPF notification reader task not started (reader not initialized).")
	}

	return nil
}

func (m *BPFManager) Close() error {
	// m.mu.Lock() // Блокировка не нужна здесь, т.к. Close вызывается один раз при остановке
	// defer m.mu.Unlock()
	var firstErr error
	m.stopOnce.Do(func() {
		slog.Info("Closing BPF Manager...")

		// 1. Сигнализируем об остановке фоновым задачам
		select {
		case <-m.stopChan: // Уже закрыт?
		default:
			close(m.stopChan)
		}

		// 2. Закрываем читатель ring buffer
		if m.notificationReader != nil {
			slog.Debug("Closing BPF ring buffer reader...")
			if err := m.notificationReader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				slog.Error("Error closing BPF ring buffer reader", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("ring buffer reader close: %w", err)
				}
			}
			m.notificationReader = nil
		}

		// 3. Отсоединяем программы (линки)
		// Важно отсоединять в обратном порядке или просто все
		links := []link.Link{m.getsockoptLink, m.sockopsLink, m.connect4Link}
		linkNames := []string{"getsockopt", "sockops", "connect4"}
		for i, l := range links {
			if l != nil {
				slog.Debug(fmt.Sprintf("Closing BPF %s link...", linkNames[i]))
				if err := l.Close(); err != nil && !errors.Is(err, link.ErrNotAttached) {
					slog.Error(fmt.Sprintf("Error closing BPF %s link", linkNames[i]), "error", err)
					if firstErr == nil {
						firstErr = fmt.Errorf("%s link close: %w", linkNames[i], err)
					}
				}
			}
		}
		m.getsockoptLink, m.sockopsLink, m.connect4Link = nil, nil, nil

		// 4. Закрываем все объекты BPF (коллекции программ и карт)
		slog.Debug("Closing all BPF objects (programs and maps)...")
		if err := m.objs.Close(); err != nil {
			slog.Error("Error closing BPF objects", "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("bpf objects close: %w", err)
			} else {
				firstErr = fmt.Errorf("%w; bpf objects close: %w", firstErr, err)
			}
		}

		// 5. Закрываем канал уведомлений
		if m.notificationChannel != nil {
			// Убедимся, что читатель завершился перед закрытием канала
			// (Хотя закрытие reader'а должно было это обеспечить)
			close(m.notificationChannel)
			m.notificationChannel = nil
		}

		slog.Info("BPF Manager closed.")
	})
	return firstErr
}

// GetNotificationChannel returns the channel for receiving BPF notifications.
func (m *BPFManager) GetNotificationChannel() <-chan NotificationTuple { // Use local NotificationTuple
	return m.notificationChannel
}

// --- Остальные методы UpdateTargetPorts, UpdateConfigMap, Add/RemoveExcludedPID ---
// UpdateTargetPorts, UpdateConfigMap остаются как есть.
// Add/RemoveExcludedPID теперь НЕ используются для исполняемых файлов,
// но могут использоваться для исключения PID'ов самих клиентских процессов.

// (Методы UpdateTargetPorts, UpdateConfigMap, AddExcludedPID, RemoveExcludedPID, statsUpdater, readGlobalStats, GetStats - без изменений)

// --- Заглушки или измененные функции ---
// Map manipulation functions (TargetPorts, ConfigMap, ClientPIDs) remain similar
// Stat collection (statsUpdater, readGlobalStats, GetStats) remain the same
// Ring buffer reading (readNotifications) remains the same

// UpdateTargetPorts обновляет карту целевых портов в BPF.
func (m *BPFManager) UpdateTargetPorts(ports []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	targetPortsMap := m.objs.TargetPorts
	if targetPortsMap == nil {
		return errors.New("BPF target_ports map not initialized (was it loaded?)")
	}

	// --- Логика очистки и заполнения карты ---
	// (Остается без изменений, как в предыдущей версии)
	// 1. Читаем текущие порты из карты
	currentPortsMap := make(map[uint16]bool)
	var mapKey uint16
	var mapValue uint8
	iter := targetPortsMap.Iterate()
	for iter.Next(&mapKey, &mapValue) {
		if mapValue == 1 {
			currentPortsMap[mapKey] = true
		}
	}
	if err := iter.Err(); err != nil {
		slog.Warn("Failed to iterate existing BPF target_ports map, clearing before update", "error", err)
		// Очищаем карту BPF перед заполнением новыми значениями
		for portToClear := range currentPortsMap {
			if errDel := targetPortsMap.Delete(portToClear); errDel != nil && !errors.Is(errDel, ebpf.ErrKeyNotExist) {
				slog.Error("Failed to delete old port during map clear", "port", portToClear, "error", errDel)
			}
		}
		currentPortsMap = make(map[uint16]bool) // Очищаем и локальный кэш
	}

	// 2. Формируем желаемый набор портов
	desiredPortsSet := make(map[uint16]bool)
	validNewPortsList := make([]int, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			portKey := uint16(p)
			desiredPortsSet[portKey] = true
			validNewPortsList = append(validNewPortsList, p)
		} else {
			slog.Warn("Invalid port number ignored in UpdateTargetPorts", "port", p)
		}
	}

	// 3. Удаляем ненужные порты
	deletedCount := 0
	for portKey := range currentPortsMap {
		if !desiredPortsSet[portKey] {
			if err := targetPortsMap.Delete(portKey); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					slog.Error("Failed to delete target port from BPF map", "port", portKey, "error", err)
				}
			} else {
				slog.Debug("Deleted target port from BPF map", "port", portKey)
				deletedCount++
			}
		}
	}

	// 4. Добавляем новые порты
	addedCount := 0
	var mapValueOne uint8 = 1
	for portKey := range desiredPortsSet {
		// Добавляем только если его не было ИЛИ если мы очищали карту выше
		if !currentPortsMap[portKey] || iter == nil || iter.Err() != nil {
			if err := targetPortsMap.Put(portKey, mapValueOne); err != nil {
				slog.Error("Failed to add target port to BPF map", "port", portKey, "error", err)
			} else {
				slog.Debug("Added target port to BPF map", "port", portKey)
				addedCount++
			}
		}
	}

	if addedCount > 0 || deletedCount > 0 {
		slog.Info("BPF target ports map updated", "added", addedCount, "deleted", deletedCount, "final_list", validNewPortsList)
	} else {
		slog.Debug("BPF target ports map remains unchanged", "current_list", validNewPortsList)
	}

	// Обновляем конфиг в памяти менеджера (если нужно)
	if m.cfg != nil {
		m.cfg.TargetPorts = validNewPortsList
	}
	return nil
}

// UpdateConfigMap обновляет карту конфигурации BPF (IP/порт слушателя).
func (m *BPFManager) UpdateConfigMap(listenerIP net.IP, listenerPort uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	configMap := m.objs.KgConfig
	if configMap == nil {
		return errors.New("BPF kg_config map not initialized")
	}

	// --- Логика обновления карты ---
	// (Остается без изменений)
	ipv4 := listenerIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("listener IP is not IPv4: %s", listenerIP.String())
	}
	listenerIPInt := binary.BigEndian.Uint32(ipv4)

	cfgValue := BpfKgConfigT{
		ListenerIp:   listenerIPInt,
		ListenerPort: listenerPort,
		Padding:      0, // Явно обнуляем padding
	}

	var mapKey uint32 = 0 // Карта типа ARRAY, ключ всегда 0
	if err := configMap.Update(mapKey, cfgValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update kg_config BPF map: %w", err)
	}

	slog.Info("BPF config map updated", "listener_ip", listenerIP, "listener_port", listenerPort)
	return nil

}

// AddExcludedPID добавляет PID клиентского процесса в карту исключений kg_client_pids.
// Используется, чтобы сам клиент не перенаправлялся.
func (m *BPFManager) AddExcludedPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clientPidsMap := m.objs.KgClientPids
	if clientPidsMap == nil {
		return errors.New("BPF kg_client_pids map not initialized")
	}

	var mapValue uint8 = 1
	if err := clientPidsMap.Put(pid, mapValue); err != nil {
		return fmt.Errorf("failed to add excluded client PID %d to BPF map: %w", pid, err)
	}
	slog.Debug("Added excluded client PID to BPF map", "pid", pid)
	return nil
}

// RemoveExcludedPID удаляет PID клиентского процесса из карты исключений kg_client_pids.
func (m *BPFManager) RemoveExcludedPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clientPidsMap := m.objs.KgClientPids
	if clientPidsMap == nil {
		// Можно не возвращать ошибку, если карта не инициализирована (например, при закрытии)
		slog.Warn("Attempted to remove excluded client PID, but kg_client_pids map is nil")
		return nil
		// return errors.New("BPF kg_client_pids map not initialized")
	}

	if err := clientPidsMap.Delete(pid); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Debug("Attempted to remove non-existent excluded client PID from BPF map", "pid", pid)
			return nil // Не ошибка, если ключа и так нет
		}
		// Возвращаем ошибку при других проблемах удаления
		return fmt.Errorf("failed to delete excluded client PID %d from BPF map: %w", pid, err)
	}
	slog.Debug("Removed excluded client PID from BPF map", "pid", pid)
	return nil
}

// statsUpdater, readGlobalStats, GetStats - без изменений

func (m *BPFManager) statsUpdater(ctx context.Context) {
	if m.cfg == nil || m.cfg.StatsInterval <= 0 {
		slog.Info("BPF statistics collection disabled (stats_interval <= 0 or config missing).")
		return
	}
	interval := time.Duration(m.cfg.StatsInterval) * time.Second
	if interval <= 1*time.Second { // Защита от слишком частого обновления
		interval = 15 * time.Second
		slog.Warn("Invalid or too frequent ebpf.stats_interval configured, using default.", "default", interval)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("BPF statistics updater started", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF statistics updater due to context cancellation.")
			return
		case <-m.stopChan: // Используем канал менеджера
			slog.Info("Stopping BPF statistics updater due to stop signal.")
			return
		case <-ticker.C:
			// Вызываем обновление внутри цикла
			if err := m.updateAndLogStats(); err != nil {
				slog.Error("Failed to update BPF statistics", "error", err)
				// Не выходим из цикла при ошибке чтения статистики
			}
		}
	}
}

// updateAndLogStats читает статистику и логирует ее. Вызывается из statsUpdater.
// Не экспортируется.
func (m *BPFManager) updateAndLogStats() error {
	m.statsCache.Lock()
	defer m.statsCache.Unlock()

	now := time.Now()
	duration := now.Sub(m.statsCache.lastStatsTime).Seconds()
	// Избегаем деления на ноль или слишком малый интервал
	if duration < 0.1 {
		slog.Debug("Skipping stats update, interval too short", "duration_sec", duration)
		return nil
	}

	currentStats, err := m.readGlobalStatsInternal() // Используем внутреннюю версию без блокировки
	if err != nil {
		return fmt.Errorf("failed to read BPF stats: %w", err)
	}

	// Функция для расчета скорости
	calculateRate := func(current, last uint64, dur float64) float64 {
		if dur <= 0 {
			return 0.0
		}
		// Обработка переполнения счетчика (если current < last)
		var delta uint64
		if current >= last {
			delta = current - last
		} else {
			// Предполагаем переполнение 64-битного счетчика
			delta = (uint64(1<<64-1) - last) + current + 1
			slog.Warn("BPF counter overflow detected", "last", last, "current", current)
		}
		return float64(delta) / dur
	}

	redirectRate := calculateRate(currentStats.Redirected, m.statsCache.lastTotalStats.Redirected, duration)
	getsockoptOkRate := calculateRate(currentStats.GetsockoptOk, m.statsCache.lastTotalStats.GetsockoptOk, duration)
	getsockoptFailRate := calculateRate(currentStats.GetsockoptFail, m.statsCache.lastTotalStats.GetsockoptFail, duration)

	slog.Info("eBPF Statistics",
		"total_pkts", currentStats.Packets,
		"total_redirected", currentStats.Redirected,
		"redirect_rate_pps", fmt.Sprintf("%.2f", redirectRate),
		"total_getsockopt_ok", currentStats.GetsockoptOk,
		"getsockopt_ok_rate_pps", fmt.Sprintf("%.2f", getsockoptOkRate),
		"total_getsockopt_fail", currentStats.GetsockoptFail,
		"getsockopt_fail_rate_pps", fmt.Sprintf("%.2f", getsockoptFailRate),
		"interval_sec", fmt.Sprintf("%.2f", duration),
	)

	// Обновляем кэш
	m.statsCache.lastTotalStats = currentStats
	m.statsCache.lastStatsTime = now

	return nil
}

// readGlobalStatsInternal читает статистику BPF без блокировки мьютекса statsCache.
// Должна вызываться только из методов, которые уже держат блокировку.
func (m *BPFManager) readGlobalStatsInternal() (GlobalStats, error) {
	var aggregate GlobalStats
	globalStatsMap := m.objs.KgStats
	if globalStatsMap == nil {
		// Не возвращаем ошибку, если карта nil, т.к. Close() мог быть вызван
		slog.Warn("BPF kg_stats map is nil during stats read")
		return aggregate, nil // Возвращаем нулевую структуру
		// return aggregate, errors.New("BPF kg_stats map is nil (was it loaded?)")
	}

	var perCPUValues []BpfGlobalStatsT
	var mapKey uint32 = 0 // Ключ для MAP_TYPE_PERCPU_ARRAY

	// LookupPerCPU выполняет Lookup + агрегацию
	err := globalStatsMap.Lookup(mapKey, &perCPUValues) // Lookup читает значения для всех CPU
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Debug("Stats key not found in BPF kg_stats map, returning zero stats.", "key", mapKey)
			return aggregate, nil // Не ошибка, если ключ не найден (хотя для percpu_array это странно)
		}
		// Возвращаем ошибку для других проблем чтения карты
		return aggregate, fmt.Errorf("failed lookup stats key %d in BPF kg_stats map: %w", mapKey, err)
	}

	// Суммируем значения со всех CPU
	for _, cpuStat := range perCPUValues {
		aggregate.Packets += cpuStat.Packets
		aggregate.Bytes += cpuStat.Bytes // Суммируем байты, если они есть в структуре
		aggregate.Redirected += cpuStat.Redirected
		aggregate.GetsockoptOk += cpuStat.GetsockoptOk
		aggregate.GetsockoptFail += cpuStat.GetsockoptFail
	}

	return aggregate, nil
}

// GetStats возвращает последнюю прочитанную статистику из кэша.
func (m *BPFManager) GetStats() (GlobalStats, error) {
	m.statsCache.RLock() // Блокировка на чтение
	defer m.statsCache.RUnlock()
	// Возвращаем копию из кэша
	// Ошибка здесь не возвращается, т.к. читаем из кэша.
	// Если нужно принудительно обновить перед возвратом:
	// currentStats, err := m.readGlobalStatsInternal()
	// if err != nil { return GlobalStats{}, err }
	// m.statsCache.lastTotalStats = currentStats // Обновление кэша потребует Lock() вместо RLock()
	return m.statsCache.lastTotalStats, nil
}

// readNotifications - без изменений

func (m *BPFManager) readNotifications(ctx context.Context) {
	slog.Info("BPF ring buffer notification reader task started.")
	defer slog.Info("BPF ring buffer notification reader task stopped.")

	var bpfTuple BpfNotificationTupleT // Используем тип из types.go
	tupleSize := binary.Size(bpfTuple)
	if tupleSize <= 0 {
		slog.Error("Could not determine size of BpfNotificationTupleT", "size", tupleSize)
		return
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader due to context cancellation.")
			return
		case <-m.stopChan: // Используем канал менеджера
			slog.Info("Stopping BPF ring buffer reader due to stop signal.")
			return
		default:
		}

		record, err := m.notificationReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				slog.Info("BPF ring buffer reader closed.")
				return // Нормальное завершение
			}
			if errors.Is(err, context.Canceled) {
				slog.Info("BPF ring buffer reading cancelled by context.")
				return // Нормальное завершение
			}
			// Логируем другие ошибки и продолжаем
			slog.Error("Error reading from BPF ring buffer", "error", err)
			// Небольшая пауза перед повторной попыткой
			select {
			case <-time.After(100 * time.Millisecond):
				continue
			case <-ctx.Done():
				return
			case <-m.stopChan:
				return
			}
		}

		// Обработка записи
		if len(record.RawSample) < tupleSize {
			slog.Warn("Received BPF ring buffer event with unexpected size, skipping.", "expected_min", tupleSize, "received", len(record.RawSample))
			continue
		}

		// Декодируем в структуру BPF
		// Используем NativeEndian, т.к. BPF работает в нативной архитектуре
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, NativeEndian, &bpfTuple); err != nil {
			slog.Error("Failed to decode BPF ring buffer event data into BpfNotificationTupleT", "error", err)
			continue
		}

		// Конвертируем в структуру Go приложения
		event := NotificationTuple{
			PidTgid:     bpfTuple.PidTgid,
			SrcIP:       bpfutil.IpFromInt(bpfTuple.SrcIp),     // BigEndian IP -> net.IP
			OrigDstIP:   bpfutil.IpFromInt(bpfTuple.OrigDstIp), // BigEndian IP -> net.IP
			SrcPort:     bpfutil.Ntohs(bpfTuple.SrcPort),       // Network short -> Host short
			OrigDstPort: bpfutil.Ntohs(bpfTuple.OrigDstPort),   // Network short -> Host short
			Protocol:    bpfTuple.Protocol,
		}

		// Отправляем в канал Go
		select {
		case m.notificationChannel <- event:
			slog.Debug("Sent BPF connection notification to service processor",
				"pid_tgid", event.PidTgid, "src", fmt.Sprintf("%s:%d", event.SrcIP, event.SrcPort),
				"orig_dst", fmt.Sprintf("%s:%d", event.OrigDstIP, event.OrigDstPort))
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader while sending notification (context cancelled).")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF ring buffer reader while sending notification (stop signal).")
			return
		default:
			// Канал переполнен, событие теряется
			slog.Warn("BPF notification channel is full, dropping event.", "channel_cap", cap(m.notificationChannel), "channel_len", len(m.notificationChannel))
		}
	}
}
