package servicecore

import (
	"context"
	"errors"
	"fmt"
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
	if stateMgr == nil {
		slog.Error("FATAL: BackgroundTasks created with nil StateManager")
		// Or return an error / panic depending on desired robustness
		return nil
	}
	return &BackgroundTasks{
		stateManager: stateMgr,
	}
}

// RunStatsLogger starts the periodic stats logging task.
// It reads the interval from the *current* config. Doesn't dynamically update interval on reload yet.
func (bt *BackgroundTasks) RunStatsLogger(ctx context.Context) {
	if bt == nil || bt.stateManager == nil {
		slog.Error("RunStatsLogger called on nil or uninitialized BackgroundTasks. Exiting.")
		return
	}

	cfg := bt.stateManager.GetConfig()
	// Use service stats interval if defined, otherwise default.
	// Let's assume statsInterval in config is primarily for BPF stats for now.
	// We'll use a constant here, but could make it configurable separately later.
	interval := statsLogIntervalDefault
	// Example if we wanted to use ebpf.statsInterval for this too:
	// interval := time.Duration(cfg.EBPF.StatsInterval) * time.Second
	// if interval <= 0 {
	//     slog.Warn("Invalid stats interval for service logger, using default", "configured_seconds", cfg.EBPF.StatsInterval, "default", statsLogIntervalDefault)
	//     interval = statsLogIntervalDefault
	// }

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("Periodic service stats logger started", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Periodic service stats logger stopping due to context cancellation.")
			return
		case <-ticker.C:
			// TODO: Add mechanism to update ticker interval if config changes.
			// Currently requires restart if statsLogIntervalDefault logic changes
			// or if it were tied to a reloadable config value.
			bt.logPeriodicStats()
		}
	}
}

// logPeriodicStats gathers and logs current service statistics.
func (bt *BackgroundTasks) logPeriodicStats() {
	// Get necessary components from state manager
	// These operations should be safe as StateManager provides accessors.
	bpfMgr := bt.stateManager.GetBpfManager()
	clientMgr := bt.stateManager.GetClientManager()
	notifChan := bt.stateManager.GetNotificationChannel() // Read-only access to channel

	// --- Gather Stats ---
	notifChanLen := 0
	notifChanCap := 0
	if notifChan != nil { // Check if channel exists (it should if init succeeded)
		// Reading len/cap of a channel is safe concurrently.
		notifChanLen = len(notifChan)
		notifChanCap = cap(notifChan)
	}

	clientCount := 0
	if clientMgr != nil { // Check if client manager exists
		clientCount = clientMgr.GetClientCount() // Access count via thread-safe method
	}

	chanUtil := 0.0
	if notifChanCap > 0 {
		chanUtil = (float64(notifChanLen) * 100.0) / float64(notifChanCap)
	}

	var matchedStats ebpf.GlobalStats // Zero value if BPF fails
	var bpfErr error
	if bpfMgr != nil { // Check if BPF manager exists
		// GetStats reads cached stats, should be quick and safe.
		_, matchedStats, bpfErr = bpfMgr.GetStats()
	} else {
		bpfErr = errors.New("BPF manager not initialized")
	}

	// --- Log Stats ---
	logArgs := []any{
		slog.Int("connected_clients", clientCount),
		slog.Int("bpf_notif_chan_len", notifChanLen),
		slog.Int("bpf_notif_chan_cap", notifChanCap),
		slog.String("bpf_notif_chan_util", fmt.Sprintf("%.2f%%", chanUtil)),
	}

	if bpfErr != nil {
		logArgs = append(logArgs, slog.String("bpf_error", bpfErr.Error()))
		slog.Warn("Service Stats (BPF Error)", logArgs...)
	} else {
		logArgs = append(logArgs, slog.Uint64("bpf_matched_conns_total", matchedStats.Packets))
		// Add more BPF stats if needed, e.g., rates calculated from cache
		slog.Info("Service Stats", logArgs...)
	}

	// Add specific warnings if needed
	if notifChanCap > 0 && notifChanLen > (notifChanCap*3/4) { // Example threshold 75%
		slog.Warn("BPF notification channel usage is high",
			"length", notifChanLen,
			"capacity", notifChanCap,
			"utilization", fmt.Sprintf("%.2f%%", chanUtil))
	}
}
