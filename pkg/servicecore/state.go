package servicecore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync" // Correct placement
	"sync/atomic"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/clientcore" // Correct placement
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
	fatalErrChan       chan error  // Channel for critical errors from background tasks
	statsLoggerRunning atomic.Bool // Tracks if the periodic stats logger is active
}

func NewStateManager(configPath string, initialCfg *config.Config) (*StateManager, error) {
	if initialCfg == nil {
		return nil, errors.New("initial configuration cannot be nil")
	}

	sm := &StateManager{
		configPath:   configPath,
		startTime:    time.Now(),
		fatalErrChan: make(chan error, 5), // Buffered channel
	}
	sm.config.Store(initialCfg) // Store initial config

	// Initialize BPF Manager
	// Use the client's listener address/port as the target for BPF redirection
	listenerIP := net.ParseIP(clientcore.LocalListenAddr) // Use exported constant
	if listenerIP == nil {
		return nil, fmt.Errorf("failed to parse default client listener IP: %s", clientcore.LocalListenAddr) // Use exported constant
	}
	listenerPort := initialCfg.ClientListenerPort
	if listenerPort == 0 {
		listenerPort = config.DefaultClientListenerPort // Use default if not set
		slog.Warn("Client listener port not set in config, using default", "port", listenerPort)
	}

	var bpfErr error
	sm.bpfManager, bpfErr = ebpf.NewBPFManager(&initialCfg.EBPF, listenerIP, listenerPort)
	if bpfErr != nil {
		return nil, fmt.Errorf("failed to initialize BPF manager: %w", bpfErr)
	}
	slog.Info("BPF Manager initialized successfully.")

	// Initialize Client Manager
	sm.clientManager = NewClientManager(sm.bpfManager) // Pass BPF manager for PID exclusion

	return sm, nil
}

// StartBackgroundTasks launches long-running tasks like BPF processing and stats logging.
func (sm *StateManager) StartBackgroundTasks(ctx context.Context) error {
	slog.Info("Starting service background tasks...")

	if sm.bpfManager != nil {
		// Start BPF Manager's internal tasks (stats, potentially ring buffer reader)
		if err := sm.bpfManager.Start(ctx, &sm.wg); err != nil {
			errFatal := fmt.Errorf("FATAL: Failed to start BPF manager core tasks: %w", err)
			sm.fatalErrChan <- errFatal // Send fatal error
			return errFatal
		}
		slog.Info("BPF Manager core tasks (stats updater) started.")

		// Start the BPF notification processor if the channel exists
		if sm.GetNotificationChannel() != nil {
			bpfProcessor := NewBpfProcessor(sm)
			if bpfProcessor != nil {
				sm.wg.Add(1)
				go func() {
					defer sm.wg.Done()
					bpfProcessor.Run(ctx)
				}()
				slog.Info("BPF Notification Processor task started.")
			} else {
				errFatal := errors.New("FATAL: Failed to initialize BPF Processor")
				sm.fatalErrChan <- errFatal
				return errFatal
			}
		} else {
			slog.Warn("BPF notification channel not available, processor task not started.")
		}

	} else {
		errFatal := errors.New("FATAL: BPF Manager is nil, cannot start background tasks")
		sm.fatalErrChan <- errFatal // Send fatal error
		return errFatal
	}

	// Start the periodic stats logger
	sm.wg.Add(1)
	go sm.logPeriodicStats(ctx)
	sm.statsLoggerRunning.Store(true)
	slog.Info("Periodic service stats logger task started.")

	slog.Info("All background tasks successfully initiated.")
	return nil
}

// GetFatalErrorChannel returns a read-only channel for critical errors.
func (sm *StateManager) GetFatalErrorChannel() <-chan error {
	return sm.fatalErrChan
}

// GetNotificationChannel returns the channel for receiving BPF notifications.
func (sm *StateManager) GetNotificationChannel() <-chan ebpf.NotificationTuple {
	if sm.bpfManager == nil {
		// Return a closed channel or nil? Returning nil might be safer.
		return nil
	}
	return sm.bpfManager.GetNotificationChannel()
}

// GetConfig returns a deep copy of the current configuration.
func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.config.Load()
	if cfg == nil {
		slog.Error("GetConfig called when configuration pointer was nil!")
		return &config.Config{} // Return empty config to avoid nil pointer dereference
	}
	// Create a shallow copy first
	newCfg := *cfg
	// Deep copy slices to prevent modification through the returned pointer
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

// ReloadConfig loads and applies configuration changes where possible.
func (sm *StateManager) ReloadConfig() error {
	slog.Info("Reloading configuration...", "path", sm.configPath)
	newCfgPtr, err := config.LoadConfig(sm.configPath)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	oldCfg := sm.GetConfig() // Get a copy of the old config

	// Re-setup logging based on new config
	logging.Setup(newCfgPtr.LogLevel, newCfgPtr.LogPath, os.Stderr)
	slog.Info("Logging reconfigured based on reloaded settings.")

	// --- Apply Changes ---

	// Update Target Ports in BPF Map
	portsChanged := !bpfutil.EqualIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfgPtr.EBPF.TargetPorts)
	if portsChanged {
		slog.Info("Applying updated target ports from reloaded configuration...", "ports", newCfgPtr.EBPF.TargetPorts)
		if sm.bpfManager != nil {
			if err := sm.bpfManager.UpdateTargetPorts(newCfgPtr.EBPF.TargetPorts); err != nil {
				slog.Error("Failed to update target ports in BPF map on config reload", "error", err)
				// Revert the ports in the new config object if BPF update failed
				newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
			} else {
				slog.Info("Target ports successfully updated in BPF map.")
			}
		} else {
			slog.Warn("Cannot update target ports: BPF manager not initialized.")
			// Revert ports in the new config object
			newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
		}
	}

	// Update Client Listener Port in BPF Map (affects redirection target)
	if oldCfg.ClientListenerPort != newCfgPtr.ClientListenerPort {
		slog.Info("Applying updated client listener port for BPF redirection...", "port", newCfgPtr.ClientListenerPort)
		listenerIP := net.ParseIP(clientcore.LocalListenAddr) // Use exported constant
		if listenerIP != nil && sm.bpfManager != nil {
			if err := sm.bpfManager.UpdateConfigMap(listenerIP, newCfgPtr.ClientListenerPort); err != nil {
				slog.Error("Failed to update BPF config map with new listener port during reload", "error", err)
				// Revert the port in the new config object
				newCfgPtr.ClientListenerPort = oldCfg.ClientListenerPort
			} else {
				slog.Info("Updated BPF config map with new client listener port.")
			}
		} else {
			slog.Error("Could not update listener port in BPF map", "listenerIP", listenerIP, "bpfManager", sm.bpfManager)
			// Revert the port
			newCfgPtr.ClientListenerPort = oldCfg.ClientListenerPort
		}
	}

	// Note changes requiring restart
	if oldCfg.EBPF.StatsInterval != newCfgPtr.EBPF.StatsInterval {
		slog.Warn("Config reload detected change in 'ebpf.stats_interval', requires service restart to take effect for BPF internal stats.")
	}
	if oldCfg.SocketPath != newCfgPtr.SocketPath {
		slog.Warn("Config reload detected change in 'socket_path', requires service restart to take effect.")
	}
	// Shutdown timeout can be updated dynamically
	if oldCfg.ShutdownTimeout != newCfgPtr.ShutdownTimeout {
		slog.Info("Shutdown timeout updated.", "old", oldCfg.ShutdownTimeout, "new", newCfgPtr.ShutdownTimeout)
	}
	// Excluded paths are handled dynamically by BpfProcessor

	// Atomically store the new configuration
	sm.config.Store(newCfgPtr)
	slog.Info("Configuration reload finished. Stored new configuration.")

	// Note: We don't restart BpfProcessor here. It reads excluded paths periodically.
	// If other BPF parameters change (like map sizes), a restart would be needed.

	return nil
}

// Shutdown performs graceful shutdown of managed components.
func (sm *StateManager) Shutdown(ctx context.Context) {
	sm.stopOnce.Do(func() {
		slog.Info("Initiating graceful shutdown...")

		// 1. Stop accepting new IPC connections
		if sm.ipcListener != nil {
			slog.Debug("Closing IPC listener...")
			if err := sm.ipcListener.Close(); err != nil {
				slog.Error("Error closing IPC listener", "error", err)
			} else {
				slog.Debug("IPC listener closed.")
			}
		}

		// 2. Close existing IPC client connections
		// CloseAllClients now removes PIDs from BPF map as well
		slog.Debug("Closing active IPC client connections...")
		sm.clientManager.CloseAllClients(ctx) // Pass context for potential timeout

		// 3. Close the BPF manager (detaches programs, closes maps)
		if sm.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := sm.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager during shutdown", "error", err)
			} else {
				slog.Debug("BPF manager closed.")
			}
		}

		// 4. Close the fatal error channel
		if sm.fatalErrChan != nil {
			close(sm.fatalErrChan)
			sm.fatalErrChan = nil
		}

		slog.Info("Shutdown sequence complete. Waiting for remaining tasks via main WaitGroup...")
		// The main loop will call sm.Wait() after this.
	})
}

// logPeriodicStats is the target function for the stats logger goroutine.
func (sm *StateManager) logPeriodicStats(ctx context.Context) {
	defer sm.wg.Done()                       // Ensure WaitGroup is decremented on exit
	defer sm.statsLoggerRunning.Store(false) // Mark as not running

	slog.Info("Periodic service stats logger task started.")
	bgTasks := NewBackgroundTasks(sm)
	bgTasks.RunStatsLogger(ctx) // Run the actual logging loop
	slog.Info("Periodic service stats logger task stopped.")
}
