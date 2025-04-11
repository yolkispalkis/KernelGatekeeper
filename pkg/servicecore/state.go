// FILE: pkg/servicecore/state.go
package servicecore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/clientcore"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/logging"
)

type StateManager struct {
	configPath         string
	config             atomic.Pointer[config.Config]
	bpfManager         *ebpf.BPFManager
	clientManager      *ClientManager
	ipcListener        net.Listener
	wg                 sync.WaitGroup
	startTime          time.Time
	stopOnce           sync.Once
	fatalErrChan       chan error
	statsLoggerRunning atomic.Bool
}

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

	listenerIP := net.ParseIP(clientcore.LocalListenAddr)
	if listenerIP == nil {
		return nil, fmt.Errorf("failed to parse default client listener IP: %s", clientcore.LocalListenAddr)
	}
	listenerPort := initialCfg.ClientListenerPort
	if listenerPort == 0 {
		listenerPort = config.DefaultClientListenerPort
		slog.Warn("Client listener port not set in config, using default", "port", listenerPort)
	}

	var bpfErr error
	sm.bpfManager, bpfErr = ebpf.NewBPFManager(&initialCfg.EBPF, listenerIP, listenerPort)
	if bpfErr != nil {

		return nil, fmt.Errorf("failed to initialize BPF manager: %w", bpfErr)
	}
	slog.Info("BPF Manager initialized successfully.")

	sm.clientManager = NewClientManager(sm.bpfManager)

	return sm, nil
}

func (sm *StateManager) StartBackgroundTasks(ctx context.Context) error {
	slog.Info("Starting service background tasks...")

	if sm.bpfManager != nil {

		if err := sm.bpfManager.Start(ctx, &sm.wg); err != nil {

			errFatal := fmt.Errorf("FATAL: Failed to start BPF manager core tasks: %w", err)
			sm.fatalErrChan <- errFatal
			return errFatal
		}
		slog.Info("BPF Manager core tasks (stats updater) started.")
	} else {
		errFatal := errors.New("FATAL: BPF Manager is nil, cannot start background tasks")
		sm.fatalErrChan <- errFatal
		return errFatal
	}

	sm.wg.Add(1)
	go sm.logPeriodicStats(ctx)
	sm.statsLoggerRunning.Store(true)
	slog.Info("Periodic service stats logger task started.")

	slog.Info("All background tasks successfully initiated.")
	return nil
}

func (sm *StateManager) GetFatalErrorChannel() <-chan error {
	return sm.fatalErrChan
}

func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.config.Load()
	if cfg == nil {
		slog.Error("GetConfig called when configuration pointer was nil!")
		return &config.Config{}
	}

	newCfg := *cfg

	newCfg.EBPF.TargetPorts = append([]int(nil), cfg.EBPF.TargetPorts...)
	newCfg.EBPF.Excluded = append([]string(nil), cfg.EBPF.Excluded...)

	return &newCfg
}

func (sm *StateManager) GetBpfManager() *ebpf.BPFManager {
	return sm.bpfManager
}

func (sm *StateManager) GetClientManager() *ClientManager {
	return sm.clientManager
}

func (sm *StateManager) GetStartTime() time.Time {
	return sm.startTime
}

func (sm *StateManager) AddWaitGroup(delta int) {
	sm.wg.Add(delta)
}

func (sm *StateManager) WaitGroupDone() {
	sm.wg.Done()
}

func (sm *StateManager) WG() *sync.WaitGroup {
	return &sm.wg
}

func (sm *StateManager) Wait() {
	sm.wg.Wait()
}

func (sm *StateManager) SetIPCListener(l net.Listener) {
	sm.ipcListener = l
}

func (sm *StateManager) ReloadConfig() error {
	slog.Info("Reloading configuration...", "path", sm.configPath)
	newCfgPtr, err := config.LoadConfig(sm.configPath)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	oldCfg := sm.GetConfig()

	logging.Setup(newCfgPtr.LogLevel, newCfgPtr.LogPath, os.Stderr)
	slog.Info("Logging reconfigured based on reloaded settings.")

	portsChanged := !bpfutil.EqualIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfgPtr.EBPF.TargetPorts)
	if portsChanged {
		slog.Info("Applying updated target ports from reloaded configuration...", "ports", newCfgPtr.EBPF.TargetPorts)
		if sm.bpfManager != nil {
			if err := sm.bpfManager.UpdateTargetPorts(newCfgPtr.EBPF.TargetPorts); err != nil {
				slog.Error("Failed to update target ports in BPF map on config reload", "error", err)

				newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
			} else {
				slog.Info("Target ports successfully updated in BPF map.")
			}
		} else {
			slog.Warn("Cannot update target ports: BPF manager not initialized.")

			newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
		}
	}

	if oldCfg.EBPF.StatsInterval != newCfgPtr.EBPF.StatsInterval {
		slog.Warn("Config reload detected change in 'ebpf.stats_interval', requires service restart to take effect for BPF internal stats.")

	}
	if oldCfg.SocketPath != newCfgPtr.SocketPath {
		slog.Warn("Config reload detected change in 'socket_path', requires service restart to take effect.")
	}
	if oldCfg.ShutdownTimeout != newCfgPtr.ShutdownTimeout {
		slog.Info("Shutdown timeout updated.", "old", oldCfg.ShutdownTimeout, "new", newCfgPtr.ShutdownTimeout)
	}
	if oldCfg.ClientListenerPort != newCfgPtr.ClientListenerPort {
		slog.Warn("Config reload detected change in 'clientListenerPort', requires service restart to take effect.")
		listenerIP := net.ParseIP(clientcore.LocalListenAddr)
		if listenerIP != nil && sm.bpfManager != nil {
			if err := sm.bpfManager.UpdateConfigMap(listenerIP, newCfgPtr.ClientListenerPort); err != nil {
				slog.Error("Failed to update BPF config map with new listener port during reload", "error", err)
			} else {
				slog.Info("Updated BPF config map with new client listener port.")
			}
		} else {
			slog.Error("Could not update listener port in BPF map", "listenerIP", listenerIP, "bpfManager", sm.bpfManager)
		}
	}

	sm.config.Store(newCfgPtr)
	slog.Info("Configuration reload finished. Stored new configuration.")

	return nil
}

func (sm *StateManager) Shutdown(ctx context.Context) {
	sm.stopOnce.Do(func() {
		slog.Info("Initiating graceful shutdown...")

		if sm.ipcListener != nil {
			slog.Debug("Closing IPC listener...")
			if err := sm.ipcListener.Close(); err != nil {
				slog.Error("Error closing IPC listener", "error", err)
			} else {
				slog.Debug("IPC listener closed.")
			}
		}

		slog.Debug("Closing active IPC client connections...")
		sm.clientManager.CloseAllClients(ctx)

		if sm.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := sm.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager during shutdown", "error", err)
			} else {
				slog.Debug("BPF manager closed.")
			}
		}

		if sm.fatalErrChan != nil {
			close(sm.fatalErrChan)
			sm.fatalErrChan = nil
		}

		slog.Info("Shutdown sequence complete. Waiting for remaining tasks via main WaitGroup...")

	})
}

func (sm *StateManager) logPeriodicStats(ctx context.Context) {
	defer sm.wg.Done()
	defer sm.statsLoggerRunning.Store(false)

	slog.Info("Periodic service stats logger task started.")
	bgTasks := NewBackgroundTasks(sm)
	bgTasks.RunStatsLogger(ctx)
	slog.Info("Periodic service stats logger task stopped.")
}
