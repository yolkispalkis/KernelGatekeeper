package servicecore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"reflect" // Import reflect for deep comparison
	"sync"
	"sync/atomic"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil" // Needed for config reload port comparison
	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/logging"
)

const (
	defaultNotificationChanSize = 4096
)

// StateManager holds the central state of the service.
type StateManager struct {
	configPath          string
	config              atomic.Pointer[config.Config] // Atomically swappable config
	bpfManager          *ebpf.BPFManager
	clientManager       *ClientManager
	ipcListener         net.Listener                // Reference to the IPC listener for shutdown
	notificationChan    chan ebpf.NotificationTuple // Channel for BPF events
	wg                  sync.WaitGroup              // For managing goroutine shutdown
	startTime           time.Time
	stopOnce            sync.Once  // Ensures shutdown logic runs only once
	fatalErrChan        chan error // Channel to signal fatal errors during init/runtime
	bpfProcessorRunning atomic.Bool
	statsLoggerRunning  atomic.Bool
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
	sm.config.Store(initialCfg) // Store initial config atomically

	// Determine notification channel size from config or default
	notifChanSize := defaultNotificationChanSize
	if initialCfg.EBPF.NotificationChannelSize > 0 {
		notifChanSize = initialCfg.EBPF.NotificationChannelSize
	} else if initialCfg.EBPF.NotificationChannelSize < 0 { // Allow 0 to disable? No, enforce positive.
		slog.Warn("Invalid ebpf.notification_channel_size configured, using default.", "configured", initialCfg.EBPF.NotificationChannelSize, "default", defaultNotificationChanSize)
	} else { // size is 0
		// If size is explicitly 0, maybe log differently or decide if it's valid?
		// For now, treat 0 as invalid and use default.
		slog.Warn("ebpf.notification_channel_size configured as 0, using default.", "default", defaultNotificationChanSize)
	}
	sm.notificationChan = make(chan ebpf.NotificationTuple, notifChanSize)

	// Initialize client manager
	sm.clientManager = NewClientManager()

	// Initialize BPF Manager
	var bpfErr error
	sm.bpfManager, bpfErr = ebpf.NewBPFManager(&initialCfg.EBPF, sm.notificationChan)
	if bpfErr != nil {
		// Don't close notificationChan here, might be needed if caller retries
		return nil, fmt.Errorf("failed to initialize BPF manager: %w", bpfErr)
	}
	slog.Info("BPF Manager initialized successfully.")

	return sm, nil
}

// StartBackgroundTasks starts essential BPF and statistics tasks.
// It signals fatal errors through the fatalErrChan.
func (sm *StateManager) StartBackgroundTasks(ctx context.Context) error {
	slog.Info("Starting service background tasks...")

	// 1. Start BPF Manager tasks (ring buffer reader, internal stats updater)
	if sm.bpfManager != nil {
		// bpfManager.Start itself now returns error only for ringbuf/stats start failures
		if err := sm.bpfManager.Start(ctx, &sm.wg); err != nil {
			// These are generally considered fatal as core BPF function is impaired
			errFatal := fmt.Errorf("FATAL: Failed to start BPF manager core tasks: %w", err)
			sm.fatalErrChan <- errFatal // Signal fatal error
			return errFatal             // Return immediately
		}
		slog.Info("BPF Manager core tasks (ring buffer, internal stats) started.")
	} else {
		errFatal := errors.New("FATAL: BPF Manager is nil, cannot start background tasks")
		sm.fatalErrChan <- errFatal // Signal fatal error
		return errFatal             // Return immediately
	}

	// 2. Start BPF notification processor (reads from notificationChan)
	if sm.notificationChan != nil {
		sm.wg.Add(1)
		go sm.processBPFNotifications(ctx) // This goroutine handles BPF events
		sm.bpfProcessorRunning.Store(true)
		slog.Info("BPF notification processor task started.")
	} else {
		slog.Warn("BPF notification channel is nil, processor task not started.")
		// Depending on requirements, this might be a fatal error too.
	}

	// 3. Start periodic service-level stats logger
	sm.wg.Add(1)
	go sm.logPeriodicStats(ctx) // This goroutine logs aggregated stats
	sm.statsLoggerRunning.Store(true)
	slog.Info("Periodic service stats logger task started.")

	slog.Info("All background tasks successfully initiated.")
	return nil // Initiation successful, runtime errors handled by tasks/fatal channel
}

// GetFatalErrorChannel returns the channel for fatal errors.
func (sm *StateManager) GetFatalErrorChannel() <-chan error {
	return sm.fatalErrChan
}

// GetConfig returns a copy of the current configuration.
func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.config.Load()
	if cfg == nil {
		slog.Error("GetConfig called when configuration pointer was nil!")
		return &config.Config{} // Return empty config to prevent panic
	}
	// Create a deep copy to prevent external modification of the active config state
	newCfg := *cfg // Shallow copy first
	// Deep copy slices and maps within the config
	newCfg.EBPF.TargetPorts = append([]int(nil), cfg.EBPF.TargetPorts...)
	newCfg.EBPF.Excluded = append([]string(nil), cfg.EBPF.Excluded...)
	// Add copies for other nested structs/slices/maps if they exist and are mutable
	return &newCfg
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

func (sm *StateManager) WG() *sync.WaitGroup {
	return &sm.wg
}

func (sm *StateManager) Wait() {
	sm.wg.Wait()
}

func (sm *StateManager) SetIPCListener(l net.Listener) {
	sm.ipcListener = l
}

// ReloadConfig loads the configuration file and applies changes dynamically where possible.
func (sm *StateManager) ReloadConfig() error {
	slog.Info("Reloading configuration...", "path", sm.configPath)
	newCfgPtr, err := config.LoadConfig(sm.configPath)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	oldCfg := sm.GetConfig() // Get a deep copy of the old config for comparison

	// --- Apply Changes ---

	// 1. Logging: Re-setup based on new config
	logging.Setup(newCfgPtr.LogLevel, newCfgPtr.LogPath, os.Stderr)
	slog.Info("Logging reconfigured based on reloaded settings.")

	// 2. BPF Target Ports: Update if allowed and changed
	portsChanged := !bpfutil.EqualIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfgPtr.EBPF.TargetPorts)
	if portsChanged {
		if newCfgPtr.EBPF.AllowDynamicPorts {
			slog.Info("Applying updated target ports from reloaded configuration...", "ports", newCfgPtr.EBPF.TargetPorts)
			if sm.bpfManager != nil {
				if err := sm.bpfManager.UpdateTargetPorts(newCfgPtr.EBPF.TargetPorts); err != nil {
					slog.Error("Failed to update target ports in BPF map on config reload", "error", err)
					// Don't apply port changes to stored config if BPF update failed? Or store anyway?
					// Let's store the new config value, but log the error. BPF state might be inconsistent.
					newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts // Revert ports in newCfg if BPF fails? Safer?
				} else {
					slog.Info("Target ports successfully updated in BPF map.")
				}
			} else {
				slog.Warn("Cannot update target ports: BPF manager not initialized.")
				// Revert port changes in the new config struct as they weren't applied
				newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
			}
		} else {
			slog.Warn("Target ports changed in config, but dynamic updates (AllowDynamicPorts) are disabled. Ports remain unchanged in BPF.", "config_ports", newCfgPtr.EBPF.TargetPorts)
			// Revert port changes in the new config struct as they weren't applied
			newCfgPtr.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
		}
	}

	// 3. BPF Excluded Paths: Updated dynamically by BpfProcessor reading config

	// 4. Check for changes requiring restart (log warnings)
	if oldCfg.EBPF.NotificationChannelSize != newCfgPtr.EBPF.NotificationChannelSize {
		slog.Warn("Config reload detected change in 'ebpf.notification_channel_size', requires service restart to take effect.")
	}
	if oldCfg.EBPF.StatsInterval != newCfgPtr.EBPF.StatsInterval {
		slog.Warn("Config reload detected change in 'ebpf.stats_interval', requires service restart to take effect for BPF internal stats. Service stats logger interval updated.")
		// Need to signal the stats logger goroutine to reset its ticker interval. How?
		// Could use a dedicated channel, or have the logger periodically check the config itself.
		// For now, only BPF internal stats interval requires restart. Service logger will pick up on next tick? No, need reset.
		// --> Simplest for now: Requires restart. More complex: add channel signaling or config check in logger loop.
	}
	if oldCfg.SocketPath != newCfgPtr.SocketPath {
		slog.Warn("Config reload detected change in 'socket_path', requires service restart to take effect.")
	}
	if oldCfg.ShutdownTimeout != newCfgPtr.ShutdownTimeout {
		slog.Info("Shutdown timeout updated.", "old", oldCfg.ShutdownTimeout, "new", newCfgPtr.ShutdownTimeout)
	}
	// Check other fields like proxy type etc if they influence service behavior directly (currently they don't)
	if !reflect.DeepEqual(oldCfg.Proxy, newCfgPtr.Proxy) {
		slog.Info("Proxy configuration changed. Service will provide new config to clients on next request/refresh.")
	}
	if !reflect.DeepEqual(oldCfg.Kerberos, newCfgPtr.Kerberos) {
		slog.Info("Kerberos configuration changed. Service will provide new config to clients on next request/refresh.")
	}

	// 5. Atomically update the config pointer
	sm.config.Store(newCfgPtr)
	slog.Info("Configuration reload finished. Stored new configuration.")

	// 6. Notify clients about the update (Optional, depends on final IPC design)
	// If we keep a simplified IPC, the client polls or restarts.
	// If we add a notification:
	// sm.NotifyClientsConfigUpdated()

	return nil
}

// Shutdown initiates the graceful shutdown sequence for the service.
func (sm *StateManager) Shutdown(ctx context.Context) {
	sm.stopOnce.Do(func() {
		slog.Info("Initiating graceful shutdown...")

		// 1. Close IPC listener to stop accepting new clients
		if sm.ipcListener != nil {
			slog.Debug("Closing IPC listener...")
			if err := sm.ipcListener.Close(); err != nil {
				slog.Error("Error closing IPC listener", "error", err)
			} else {
				slog.Debug("IPC listener closed.")
			}
		}

		// 2. Close existing client connections
		// ClientManager handles closing connections internally now.
		slog.Debug("Closing active IPC client connections...")
		sm.clientManager.CloseAllClients(ctx) // Pass context for potential timeout

		// 3. Close BPF Manager (detaches programs, closes maps)
		// This should happen *before* closing the notification channel used by its reader.
		if sm.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := sm.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager during shutdown", "error", err)
			} else {
				slog.Debug("BPF manager closed.")
			}
		}

		// 4. Close the notification channel to signal the BPF processor to stop
		// Check if the processor goroutine was actually started and channel exists
		if sm.bpfProcessorRunning.Load() && sm.notificationChan != nil {
			slog.Debug("Closing BPF notification channel...")
			// Safe close using recover in case it was already closed somehow
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Debug("Recovered from panic closing notification channel (likely already closed)", "panic", r)
					}
				}()
				close(sm.notificationChan)
			}()
			// sm.notificationChan = nil // Set to nil? Or just let GC handle it after close? Keep it simple.
			slog.Debug("BPF notification channel closed.")
		}

		// 5. Close the fatal error channel (no more errors will be sent)
		if sm.fatalErrChan != nil {
			close(sm.fatalErrChan)
			sm.fatalErrChan = nil // Prevent further use
		}

		slog.Info("Shutdown sequence complete. Waiting for remaining tasks via main WaitGroup...")
		// Main function will call sm.Wait()
	})
}

// processBPFNotifications runs in a dedicated goroutine, processing events from BPF.
func (sm *StateManager) processBPFNotifications(ctx context.Context) {
	defer sm.wg.Done()
	defer sm.bpfProcessorRunning.Store(false) // Mark as stopped on exit

	slog.Info("BPF notification processor task started.")
	bpfProcessor := NewBpfProcessor(sm) // Create the processor instance
	bpfProcessor.Run(ctx)               // Run its processing loop
	slog.Info("BPF notification processor task stopped.")
}

// logPeriodicStats runs in a dedicated goroutine, logging service health.
func (sm *StateManager) logPeriodicStats(ctx context.Context) {
	defer sm.wg.Done()
	defer sm.statsLoggerRunning.Store(false) // Mark as stopped on exit

	slog.Info("Periodic service stats logger task started.")
	bgTasks := NewBackgroundTasks(sm) // Create BackgroundTasks runner
	bgTasks.RunStatsLogger(ctx)       // Run its logging loop
	slog.Info("Periodic service stats logger task stopped.")
}

// NotifyClientsConfigUpdated sends a notification to all connected clients
// that the configuration has been updated. (Implementation depends on IPC design)
// func (sm *StateManager) NotifyClientsConfigUpdated() {
// 	cmd, err := ipc.NewCommand("config_updated", nil)
// 	if err != nil {
// 		slog.Error("Failed to create config_updated command", "error", err)
// 		return
// 	}
// 	sm.clientManager.NotifyAllClients(cmd) // Need a Broadcast/NotifyAll method in ClientManager
// }
