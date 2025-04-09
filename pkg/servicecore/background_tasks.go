package servicecore

import (
	"context"
	"log/slog"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf"
)

// statsLogInterval determines how often aggregated service stats are logged.
// Note: BPF internal stats collection interval is configured via ebpf.statsInterval in config.yaml
const statsLogIntervalDefault = 5 * time.Minute

// BackgroundTasks struct holds dependencies for background operations.
// Currently, only used for periodic stats logging.
type BackgroundTasks struct {
	stateManager *StateManager
}

func NewBackgroundTasks(stateMgr *StateManager) *BackgroundTasks {
	return &BackgroundTasks{
		stateManager: stateMgr,
	}
}

// RunStatsLogger starts the periodic stats logging task.
// It reads the interval from the *current* config. Doesn't dynamically update interval on reload yet.
func (bt *BackgroundTasks) RunStatsLogger(ctx context.Context) {
	sm := bt.stateManager
	if sm == nil {
		slog.Error("BackgroundTasks cannot run stats logger: StateManager is nil")
		// Or return an error / panic depending on desired robustness
		return
	}
	sm.AddWaitGroup(1)                // Increment waitgroup for this goroutine
	sm.statsLoggerRunning.Store(true) // Mark as running
	defer sm.WaitGroupDone()          // Decrement waitgroup when goroutine exits

	// Use service stats interval if defined, otherwise default.
	// Let's assume statsInterval in config is primarily for BPF stats for now.
	// We'll use a constant here, but could make it configurable separately later.
	interval := statsLogIntervalDefault // Use the defined default constant

	slog.Info("Starting periodic service stats logger", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Log stats once immediately
	bt.logPeriodicStats()

	// TODO: Add mechanism to update ticker interval if config changes.
	// Currently requires restart if statsLogIntervalDefault logic changes
	// or if it were tied to a reloadable config value.

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping periodic service stats logger due to context cancellation")
			return
		case <-ticker.C:
			bt.logPeriodicStats()
		}
	}
}

// logPeriodicStats gathers and logs current service statistics.
func (bt *BackgroundTasks) logPeriodicStats() {
	if bt.stateManager == nil {
		slog.Error("Cannot log stats, StateManager is nil")
		return
	}

	// Get necessary components from state manager
	// These operations should be safe as StateManager provides accessors.
	bpfMgr := bt.stateManager.GetBpfManager()
	clientMgr := bt.stateManager.GetClientManager()
	notifChan := bt.stateManager.GetNotificationChannel() // Read-only access to channel

	// --- Gather Stats ---
	startTime := bt.stateManager.GetStartTime()
	uptime := time.Since(startTime).Round(time.Second)
	notifChanLen := 0
	notifChanCap := 0
	clientCount := 0

	if notifChan != nil { // Check if channel exists (it should if init succeeded)
		// Reading len/cap of a channel is safe concurrently.
		notifChanLen = len(notifChan)
		notifChanCap = cap(notifChan)
	}

	if clientMgr != nil { // Check if client manager exists
		clientCount = clientMgr.GetClientCount() // Access count via thread-safe method
	}

	var matchedStats ebpf.GlobalStats // Zero value if BPF fails
	var bpfErr error
	if bpfMgr != nil { // Check if BPF manager exists
		// GetStats reads cached stats, should be quick and safe.
		_, matchedStats, bpfErr = bpfMgr.GetStats()
		// If bpfErr is not nil, it indicates a real error reading the map.
		// A non-existent key should result in zero stats and nil error from GetStats.
		if bpfErr != nil {
			slog.Warn("Error retrieving BPF stats for logging", "error", bpfErr)
			// Continue logging other stats
		}
	} else {
		slog.Warn("BPF Manager not available for stats logging")
	}

	// --- Log Stats ---
	slog.Info("Service Status",
		"uptime", uptime.String(),
		"active_clients", clientCount,
		"bpf_matched_connections_total", matchedStats.Packets, // Use Packets field for connection count
		"bpf_notification_channel_len", notifChanLen,
		"bpf_notification_channel_cap", notifChanCap,
	)

	// Add more BPF stats if needed, e.g., rates calculated from cache

	// Add specific warnings if needed
	if notifChanCap > 0 && notifChanLen > (notifChanCap*3/4) { // Example threshold 75%
		slog.Warn("BPF notification channel is over 75% full", "len", notifChanLen, "cap", notifChanCap)
	}
}
