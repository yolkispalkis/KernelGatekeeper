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

	"github.com/yolki/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolki/kernelgatekeeper/pkg/config"
	"github.com/yolki/kernelgatekeeper/pkg/ebpf"
	"github.com/yolki/kernelgatekeeper/pkg/logging"
)

const (
	defaultNotificationChanSize = 4096
)

type StateManager struct {
	configPath          string
	config              atomic.Pointer[config.Config]
	bpfManager          *ebpf.BPFManager
	clientManager       *ClientManager
	ipcListener         net.Listener
	notificationChan    chan ebpf.NotificationTuple
	wg                  sync.WaitGroup
	startTime           time.Time
	stopOnce            sync.Once
	fatalErrChan        chan error // Channel to signal fatal errors during init
	bpfProcessorRunning atomic.Bool
}

func NewStateManager(configPath string, initialCfg *config.Config) (*StateManager, error) {
	if initialCfg == nil {
		return nil, errors.New("initial configuration cannot be nil")
	}

	sm := &StateManager{
		configPath:   configPath,
		startTime:    time.Now(),
		fatalErrChan: make(chan error, 5), // Buffered channel for init errors
	}
	sm.config.Store(initialCfg)

	notifChanSize := defaultNotificationChanSize
	if initialCfg.EBPF.NotificationChannelSize > 0 {
		notifChanSize = initialCfg.EBPF.NotificationChannelSize
	} else if initialCfg.EBPF.NotificationChannelSize != 0 {
		slog.Warn("ebpf.notification_channel_size invalid, using default", "configured", initialCfg.EBPF.NotificationChannelSize, "default", defaultNotificationChanSize)
	}
	sm.notificationChan = make(chan ebpf.NotificationTuple, notifChanSize)

	sm.clientManager = NewClientManager()

	// Initialize BPF Manager early
	var bpfErr error
	sm.bpfManager, bpfErr = ebpf.NewBPFManager(&initialCfg.EBPF, sm.notificationChan)
	if bpfErr != nil {
		return nil, fmt.Errorf("failed to initialize BPF manager: %w", bpfErr)
	}
	slog.Info("BPF Manager initialized.")

	return sm, nil
}

// StartBackgroundTasks starts essential tasks after initialization.
// Returns error immediately if any task fails fatally.
func (sm *StateManager) StartBackgroundTasks(ctx context.Context) error {
	slog.Info("Starting service background tasks...")

	// Start BPF Manager tasks (stats updater, ring buffer reader)
	if sm.bpfManager != nil {
		if err := sm.bpfManager.Start(ctx, &sm.wg); err != nil {
			errFatal := fmt.Errorf("FATAL: Failed to start BPF manager tasks: %w", err)
			sm.fatalErrChan <- errFatal
			return errFatal // Return fatal error immediately
		}
	} else {
		errFatal := errors.New("FATAL: BPF Manager is nil, cannot start background tasks")
		sm.fatalErrChan <- errFatal
		return errFatal
	}

	// Start BPF notification processor
	sm.wg.Add(1)
	go sm.processBPFNotifications(ctx) // Assuming processBPFNotifications is now a method on StateManager or BpfProcessor
	sm.bpfProcessorRunning.Store(true)

	// Start periodic stats logger
	sm.wg.Add(1)
	go sm.logPeriodicStats(ctx) // Assuming logPeriodicStats is now a method on StateManager or BackgroundTasks

	slog.Info("Background tasks successfully started.")
	return nil
}

// GetFatalErrorChannel returns a channel that receives fatal initialization errors.
func (sm *StateManager) GetFatalErrorChannel() <-chan error {
	return sm.fatalErrChan
}

func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.config.Load()
	if cfg == nil {
		// Should not happen if initialized correctly
		slog.Error("GetConfig called before configuration was initialized!")
		return &config.Config{}
	}
	// Return a shallow copy
	cfgCopy := *cfg
	// Deep copy slices/maps if they could be mutated elsewhere after returning
	if cfg.EBPF.TargetPorts != nil {
		cfgCopy.EBPF.TargetPorts = make([]int, len(cfg.EBPF.TargetPorts))
		copy(cfgCopy.EBPF.TargetPorts, cfg.EBPF.TargetPorts)
	} else {
		cfgCopy.EBPF.TargetPorts = []int{}
	}
	return &cfgCopy
}

func (sm *StateManager) GetBpfManager() *ebpf.BPFManager {
	return sm.bpfManager
}

func (sm *StateManager) GetClientManager() *ClientManager {
	return sm.clientManager
}

func (sm *StateManager) GetNotificationChannel() chan ebpf.NotificationTuple {
	return sm.notificationChan
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

	// Apply configuration changes
	logging.Setup(newCfgPtr.LogLevel, newCfgPtr.LogPath, os.Stderr) // Re-setup logging
	slog.Info("Logging reconfigured based on reloaded settings.")

	oldCfg := sm.GetConfig() // Get copy of old config

	if newCfgPtr.EBPF.AllowDynamicPorts && !bpfutil.EqualIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfgPtr.EBPF.TargetPorts) {
		slog.Info("Applying updated target ports from reloaded configuration...", "ports", newCfgPtr.EBPF.TargetPorts)
		if sm.bpfManager != nil {
			if err := sm.bpfManager.UpdateTargetPorts(newCfgPtr.EBPF.TargetPorts); err != nil {
				slog.Error("Failed to update target ports on config reload", "error", err)
			} else {
				slog.Info("Target ports successfully updated in BPF map.")
			}
		} else {
			slog.Warn("Cannot update target ports: BPF manager not initialized.")
		}
	} else if !newCfgPtr.EBPF.AllowDynamicPorts && !bpfutil.EqualIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfgPtr.EBPF.TargetPorts) {
		slog.Warn("Target ports changed in config, but dynamic updates are disabled. Ports remain unchanged in BPF.", "config_ports", newCfgPtr.EBPF.TargetPorts)
	}

	// Check for changes requiring restart
	if oldCfg.EBPF.NotificationChannelSize != newCfgPtr.EBPF.NotificationChannelSize {
		slog.Warn("Config reload detected change in 'ebpf.notification_channel_size', requires service restart to take effect.")
	}
	if oldCfg.EBPF.StatsInterval != newCfgPtr.EBPF.StatsInterval {
		slog.Warn("Config reload detected change in 'ebpf.stats_interval', requires service restart to take effect.")
	}
	if oldCfg.SocketPath != newCfgPtr.SocketPath {
		slog.Warn("Config reload detected change in 'socket_path', requires service restart to take effect.")
	}
	if oldCfg.ShutdownTimeout != newCfgPtr.ShutdownTimeout {
		slog.Info("Shutdown timeout updated.", "old", oldCfg.ShutdownTimeout, "new", newCfgPtr.ShutdownTimeout)
	}

	// Update the main config struct atomically
	sm.config.Store(newCfgPtr)

	// Notify clients? (Optional - requires IPC mechanism)
	// sm.clientManager.NotifyAllClients("config_updated", nil)

	slog.Info("Configuration reload finished.")
	return nil
}

func (sm *StateManager) Shutdown(ctx context.Context) {
	sm.stopOnce.Do(func() {
		slog.Info("Initiating graceful shutdown...")

		// 1. Close IPC listener
		if sm.ipcListener != nil {
			slog.Debug("Closing IPC listener...")
			if err := sm.ipcListener.Close(); err != nil {
				slog.Error("Error closing IPC listener", "error", err)
			}
		}

		// 2. Close client connections (managed by ClientManager)
		slog.Debug("Closing active IPC client connections...")
		sm.clientManager.CloseAllClients(ctx) // Pass context for potential timeout

		// 3. Close BPF Manager
		if sm.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := sm.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager during shutdown", "error", err)
			} else {
				slog.Debug("BPF manager closed.")
			}
		}

		// 4. Close notification channel if processor goroutine was started
		if sm.bpfProcessorRunning.Load() && sm.notificationChan != nil {
			slog.Debug("Closing notification channel...")
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Debug("Notification channel already closed or panic during close.", "panic", r)
					}
				}()
				close(sm.notificationChan)
			}()
			sm.notificationChan = nil
		}

		close(sm.fatalErrChan) // Close fatal error channel on shutdown

		slog.Info("Shutdown sequence complete. Waiting for remaining tasks via main WaitGroup...")
	})
}

// processBPFNotifications is likely part of BpfProcessor, called by StartBackgroundTasks
func (sm *StateManager) processBPFNotifications(ctx context.Context) {
	// Placeholder: This logic should be in BpfProcessor.Run()
	// This demonstrates how BpfProcessor would use StateManager resources.
	defer sm.wg.Done()
	slog.Info("Starting BPF notification processor...")
	bpfProcessor := NewBpfProcessor(sm) // Create the processor
	bpfProcessor.Run(ctx)               // Run its loop
	sm.bpfProcessorRunning.Store(false)
	slog.Info("BPF notification processor stopped.")
}

// logPeriodicStats is likely part of BackgroundTasks, called by StartBackgroundTasks
func (sm *StateManager) logPeriodicStats(ctx context.Context) {
	// Placeholder: This logic should be in BackgroundTasks.Run()
	defer sm.wg.Done()
	bgTasks := NewBackgroundTasks(sm) // Create BackgroundTasks runner
	bgTasks.RunStatsLogger(ctx)       // Run its loop
	slog.Info("Periodic stats logger stopped.")
}
