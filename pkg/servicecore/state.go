// FILE: pkg/servicecore/state.go
package servicecore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"reflect" // Добавлено для DeepEqual
	"sync"
	"sync/atomic"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common" // Import common
	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf" // Import ebpf
	"github.com/yolkispalkis/kernelgatekeeper/pkg/logging"
)

// StateManager управляет состоянием сервиса.
type StateManager struct {
	configPath    string
	config        atomic.Pointer[config.Config]
	bpfManager    *ebpf.BPFManager
	clientManager *ClientManager
	ipcListener   net.Listener
	wg            sync.WaitGroup
	startTime     time.Time
	stopOnce      sync.Once
	fatalErrChan  chan error
	// statsLoggerRunning atomic.Bool // Removed, handled internally by goroutine state
}

// NewStateManager создает новый StateManager.
func NewStateManager(configPath string, initialCfg *config.Config) (*StateManager, error) {
	if initialCfg == nil {
		return nil, errors.New("initial configuration cannot be nil")
	}

	sm := &StateManager{
		configPath:   configPath,
		startTime:    time.Now(),
		fatalErrChan: make(chan error, 5),
	}
	sm.config.Store(initialCfg)

	// Инициализация BPF Manager
	// FIX: Use common constant for listener IP
	listenerIP := net.ParseIP(common.LocalListenAddr)
	if listenerIP == nil {
		// FIX: Use common constant in error message
		return nil, fmt.Errorf("failed to parse default client listener IP: %s", common.LocalListenAddr)

	}
	listenerPort := initialCfg.ClientListenerPort
	if listenerPort == 0 {
		// FIX: Use common constant for default port
		listenerPort = common.DefaultClientListenerPort
		slog.Warn("Client listener port not set in config, using default", "port", listenerPort)
	}

	var bpfErr error
	sm.bpfManager, bpfErr = ebpf.NewBPFManager(&initialCfg.EBPF, listenerIP, listenerPort)
	if bpfErr != nil {
		// Попытаемся очистить ресурсы, если BPFManager частично создался
		if sm.bpfManager != nil {
			sm.bpfManager.Close()
		}
		return nil, fmt.Errorf("failed to initialize BPF manager: %w", bpfErr)
	}
	slog.Info("BPF Manager initialized successfully.")

	// <<< Вызываем обновление исключений после создания BPF Manager >>>
	if err := sm.bpfManager.UpdateExcludedExecutables(initialCfg.EBPF.Excluded); err != nil {
		slog.Error("Failed to set initial excluded executables in BPF map", "error", err)
		// Продолжаем работу, но логируем ошибку
		// Возможно, стоит вернуть ошибку здесь? Зависит от критичности.
		// sm.bpfManager.Close()
		// return nil, fmt.Errorf("failed to set initial BPF exclusions: %w", err)
	}

	// Инициализация Client Manager
	sm.clientManager = NewClientManager(sm.bpfManager)

	return sm, nil
}

// StartBackgroundTasks запускает фоновые задачи.
func (sm *StateManager) StartBackgroundTasks(ctx context.Context) error {
	slog.Info("Starting service background tasks...")

	if sm.bpfManager == nil {
		errFatal := errors.New("FATAL: BPF Manager is nil, cannot start background tasks")
		sm.fatalErrChan <- errFatal
		close(sm.fatalErrChan) // Close channel after sending fatal error
		return errFatal
	}

	// Запуск внутренних задач BPF Manager (статистика и т.д.)
	if err := sm.bpfManager.Start(ctx, &sm.wg); err != nil {
		errFatal := fmt.Errorf("FATAL: Failed to start BPF manager core tasks: %w", err)
		sm.fatalErrChan <- errFatal
		close(sm.fatalErrChan)
		return errFatal
	}
	slog.Info("BPF Manager core tasks started.")

	// Запуск обработчика уведомлений BPF
	if sm.GetNotificationChannel() != nil {
		bpfProcessor := NewBpfProcessor(sm)
		if bpfProcessor == nil {
			errFatal := errors.New("FATAL: Failed to initialize BPF Processor")
			sm.fatalErrChan <- errFatal
			close(sm.fatalErrChan)
			return errFatal
		}
		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			bpfProcessor.Run(ctx)
		}()
		slog.Info("BPF Notification Processor task started.")
	} else {
		slog.Warn("BPF notification channel not available, processor task not started.")
	}

	// Запуск периодического логгера статистики
	sm.wg.Add(1)
	go sm.logPeriodicStats(ctx) // Используем внутренний метод

	slog.Info("All background tasks successfully initiated.")
	return nil
}

// ReloadConfig перезагружает конфигурацию и применяет изменения.
func (sm *StateManager) ReloadConfig() error {
	slog.Info("Reloading configuration...", "path", sm.configPath)
	newCfgPtr, err := config.LoadConfig(sm.configPath)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	oldCfg := sm.GetConfig() // Получаем копию старой конфигурации

	// Перенастройка логирования
	logging.Setup(newCfgPtr.LogLevel, newCfgPtr.LogPath, os.Stderr)
	slog.Info("Logging reconfigured based on reloaded settings.")

	// --- Применение изменений ---

	// Обновление целевых портов в BPF
	// Используем reflect.DeepEqual для сравнения срезов, т.к. порядок важен для BPFManager.UpdateTargetPorts
	if !reflect.DeepEqual(oldCfg.EBPF.TargetPorts, newCfgPtr.EBPF.TargetPorts) {
		slog.Info("Applying updated target ports...", "ports", newCfgPtr.EBPF.TargetPorts)
		if sm.bpfManager != nil {
			if err := sm.bpfManager.UpdateTargetPorts(newCfgPtr.EBPF.TargetPorts); err != nil {
				slog.Error("Failed to update target ports in BPF map on config reload", "error", err)
				newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts // Восстанавливаем старое значение в объекте конфига
			} else {
				slog.Info("Target ports successfully updated in BPF map.")
			}
		} else {
			slog.Warn("Cannot update target ports: BPF manager not initialized.")
			newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
		}
	}

	// <<< Обновление исключенных исполняемых файлов в BPF >>>
	if !reflect.DeepEqual(oldCfg.EBPF.Excluded, newCfgPtr.EBPF.Excluded) {
		slog.Info("Applying updated excluded executable paths...")
		if sm.bpfManager != nil {
			// Вызываем новый метод BPFManager
			if err := sm.bpfManager.UpdateExcludedExecutables(newCfgPtr.EBPF.Excluded); err != nil {
				slog.Error("Failed to update excluded executables in BPF map on config reload", "error", err)
				newCfgPtr.EBPF.Excluded = oldCfg.EBPF.Excluded // Восстанавливаем старое значение
			} else {
				slog.Info("Excluded executables successfully updated in BPF map.")
			}
		} else {
			slog.Warn("Cannot update excluded executables: BPF manager not initialized.")
			newCfgPtr.EBPF.Excluded = oldCfg.EBPF.Excluded
		}
	}

	// Обновление порта слушателя клиента в BPF
	if oldCfg.ClientListenerPort != newCfgPtr.ClientListenerPort {
		slog.Info("Applying updated client listener port for BPF redirection...", "port", newCfgPtr.ClientListenerPort)
		// FIX: Use common constant
		listenerIP := net.ParseIP(common.LocalListenAddr)
		if listenerIP != nil && sm.bpfManager != nil {
			if err := sm.bpfManager.UpdateConfigMap(listenerIP, newCfgPtr.ClientListenerPort); err != nil {
				slog.Error("Failed to update BPF config map with new listener port during reload", "error", err)
				newCfgPtr.ClientListenerPort = oldCfg.ClientListenerPort
			} else {
				slog.Info("Updated BPF config map with new client listener port.")
			}
		} else {
			slog.Error("Could not update listener port in BPF map", "listenerIP_valid", listenerIP != nil, "bpfManager_valid", sm.bpfManager != nil)
			newCfgPtr.ClientListenerPort = oldCfg.ClientListenerPort
		}
	}

	// Предупреждения о параметрах, требующих перезапуска
	if oldCfg.EBPF.StatsInterval != newCfgPtr.EBPF.StatsInterval {
		slog.Warn("Config reload detected change in 'ebpf.stats_interval', requires service restart for the stats *updater* interval change. BPF internal stats work regardless.")
	}
	if oldCfg.SocketPath != newCfgPtr.SocketPath {
		slog.Warn("Config reload detected change in 'socket_path', requires service restart to take effect.")
	}
	if oldCfg.ShutdownTimeout != newCfgPtr.ShutdownTimeout {
		slog.Info("Shutdown timeout updated.", "old", oldCfg.ShutdownTimeout, "new", newCfgPtr.ShutdownTimeout)
	}

	// Атомарно сохраняем новую конфигурацию
	sm.config.Store(newCfgPtr)
	slog.Info("Configuration reload finished. Stored new configuration.")

	return nil
}

// --- Остальные методы StateManager (GetConfig, GetBpfManager, etc.) ---
// Они остаются без изменений, кроме logPeriodicStats

// logPeriodicStats является оберткой для запуска фоновой задачи логирования.
func (sm *StateManager) logPeriodicStats(ctx context.Context) {
	// sm.statsLoggerRunning.Store(true) // Removed
	defer sm.wg.Done() // Убедимся, что WaitGroup уменьшается при выходе

	slog.Debug("Periodic stats logger goroutine started.") // Изменено на Debug

	cfg := sm.GetConfig() // Получаем актуальный конфиг
	interval := time.Duration(cfg.EBPF.StatsInterval) * time.Second
	if interval <= 1*time.Second { // Используем ту же логику валидации, что и в statsUpdater
		interval = 15 * time.Second
		slog.Warn("Invalid or too frequent ebpf.stats_interval for periodic logging, using default.", "default", interval)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Логируем сразу при старте
	sm.performPeriodicStatsLog()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping periodic service stats logger due to context cancellation.")
			return
		// Канал stopChan не доступен здесь напрямую, используем ctx.Done()
		case <-ticker.C:
			sm.performPeriodicStatsLog()
		}
	}
}

// performPeriodicStatsLog выполняет фактическое логирование статистики.
func (sm *StateManager) performPeriodicStatsLog() {
	if sm == nil {
		slog.Error("Cannot log stats, StateManager is nil")
		return
	}

	bpfMgr := sm.GetBpfManager()
	clientMgr := sm.GetClientManager()

	startTime := sm.GetStartTime()
	uptime := time.Since(startTime).Round(time.Second)

	clientCount := 0
	if clientMgr != nil {
		clientCount = clientMgr.GetClientCount()
	} else {
		slog.Warn("Client Manager not available for stats logging")
	}

	var currentStats ebpf.GlobalStats
	var bpfErr error
	if bpfMgr != nil {
		// FIX: Use the implemented GetStats method
		currentStats, bpfErr = bpfMgr.GetStats()
		if bpfErr != nil {
			// GetStats() из кэша не должна возвращать ошибку,
			// но если она принудительно читает и получает ошибку:
			slog.Warn("Error retrieving BPF stats for logging", "error", bpfErr)
		}
	} else {
		slog.Warn("BPF Manager not available for stats logging")
	}

	slog.Info("Service Status",
		"uptime", uptime.String(),
		"active_clients", clientCount,
		"bpf_total_redirected", currentStats.Redirected,
		"bpf_total_getsockopt_ok", currentStats.GetsockoptOk,
		"bpf_total_getsockopt_fail", currentStats.GetsockoptFail,
	)
}

// GetFatalErrorChannel возвращает канал для фатальных ошибок.
func (sm *StateManager) GetFatalErrorChannel() <-chan error {
	return sm.fatalErrChan
}

// GetNotificationChannel возвращает канал уведомлений от BPF.
// FIX: Use the correct type from ebpf package
func (sm *StateManager) GetNotificationChannel() <-chan ebpf.NotificationTuple {

	if sm.bpfManager == nil {
		return nil
	}
	return sm.bpfManager.GetNotificationChannel()
}

// GetConfig возвращает копию текущей конфигурации.
func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.config.Load()
	if cfg == nil {
		slog.Error("GetConfig called when configuration pointer was nil!")
		// Возвращаем пустую структуру, чтобы избежать паники
		// но это серьезная проблема, если происходит
		return &config.Config{}
	}
	// Создаем копию для безопасности
	newCfg := *cfg
	// Глубокое копирование срезов
	newCfg.EBPF.TargetPorts = append([]int(nil), cfg.EBPF.TargetPorts...)
	newCfg.EBPF.Excluded = append([]string(nil), cfg.EBPF.Excluded...)
	return &newCfg
}

// GetBpfManager возвращает BPFManager.
func (sm *StateManager) GetBpfManager() *ebpf.BPFManager {
	return sm.bpfManager
}

// GetClientManager возвращает ClientManager.
func (sm *StateManager) GetClientManager() *ClientManager {
	return sm.clientManager
}

// GetStartTime возвращает время старта сервиса.
func (sm *StateManager) GetStartTime() time.Time {
	return sm.startTime
}

// AddWaitGroup увеличивает счетчик WaitGroup.
func (sm *StateManager) AddWaitGroup(delta int) {
	sm.wg.Add(delta)
}

// WaitGroupDone уменьшает счетчик WaitGroup.
func (sm *StateManager) WaitGroupDone() {
	sm.wg.Done()
}

// WG возвращает WaitGroup.
func (sm *StateManager) WG() *sync.WaitGroup {
	return &sm.wg
}

// Wait ожидает завершения всех задач в WaitGroup.
func (sm *StateManager) Wait() {
	sm.wg.Wait()
}

// SetIPCListener устанавливает слушатель IPC.
func (sm *StateManager) SetIPCListener(l net.Listener) {
	sm.ipcListener = l
}

// Shutdown выполняет корректное завершение работы.
func (sm *StateManager) Shutdown(ctx context.Context) {
	sm.stopOnce.Do(func() {
		slog.Info("Initiating graceful shutdown...")

		// 1. Остановка приема новых IPC соединений
		if sm.ipcListener != nil {
			slog.Debug("Closing IPC listener...")
			if err := sm.ipcListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				slog.Error("Error closing IPC listener", "error", err)
			} else {
				slog.Debug("IPC listener closed.")
			}
		} else {
			slog.Debug("IPC listener was already nil or not set.")
		}

		// 2. Закрытие существующих IPC клиентов
		if sm.clientManager != nil {
			slog.Debug("Closing active IPC client connections...")
			sm.clientManager.CloseAllClients(ctx) // Передаем контекст
		} else {
			slog.Debug("Client Manager is nil, skipping client closure.")
		}

		// 3. Закрытие BPF manager (отсоединение программ, закрытие карт)
		if sm.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := sm.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager during shutdown", "error", err)
			} else {
				slog.Debug("BPF manager closed.")
			}
		} else {
			slog.Debug("BPF Manager is nil, skipping closure.")
		}

		// 4. Закрытие канала фатальных ошибок
		if sm.fatalErrChan != nil {
			select {
			case <-sm.fatalErrChan:
				// Channel already closed or has pending error
			default:
				// Channel is open and empty, close it
				close(sm.fatalErrChan)
			}
			sm.fatalErrChan = nil
		}

		slog.Info("Shutdown sequence complete. Waiting for remaining tasks via WaitGroup...")
		// Основной цикл вызовет sm.Wait() после этой функции
	})
}
