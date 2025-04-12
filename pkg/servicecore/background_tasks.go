// FILE: pkg/servicecore/background_tasks.go
package servicecore

import (
	"context"
	"log/slog"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf"
)

const statsLogIntervalDefault = 5 * time.Minute

type BackgroundTasks struct {
	stateManager *StateManager
}

func NewBackgroundTasks(stateMgr *StateManager) *BackgroundTasks {
	return &BackgroundTasks{
		stateManager: stateMgr,
	}
}

// RunStatsLogger is now handled internally by StateManager.logPeriodicStats
// This function remains as a placeholder or can be removed if not used elsewhere.
func (bt *BackgroundTasks) RunStatsLogger(ctx context.Context) {
	sm := bt.stateManager
	if sm == nil {
		slog.Error("BackgroundTasks cannot run stats logger: StateManager is nil")
		return
	}
	// AddWaitGroup and managing statsLoggerRunning is now done within StateManager
	// sm.AddWaitGroup(1)
	// // sm.statsLoggerRunning.Store(true) // Removed
	// defer sm.WaitGroupDone()

	slog.Warn("RunStatsLogger called in BackgroundTasks, but logic moved to StateManager. Ensure StateManager.StartBackgroundTasks handles this.")
	// Wait for cancellation if this goroutine is somehow still started externally
	<-ctx.Done()
}

// logPeriodicStats is now handled internally by StateManager.performPeriodicStatsLog
// This function remains as a placeholder or can be removed.
func (bt *BackgroundTasks) logPeriodicStats() {
	slog.Warn("BackgroundTasks.logPeriodicStats called, but logic is now in StateManager.")
	if bt.stateManager != nil {
		// Call the new method in StateManager if needed for some reason,
		// but ideally the StateManager's own goroutine handles this.
		// bt.stateManager.performPeriodicStatsLog()

		// Re-implementing the logging logic here for simplicity if BackgroundTasks is kept:
		bpfMgr := bt.stateManager.GetBpfManager()
		clientMgr := bt.stateManager.GetClientManager()
		startTime := bt.stateManager.GetStartTime()
		uptime := time.Since(startTime).Round(time.Second)

		clientCount := 0
		if clientMgr != nil {
			clientCount = clientMgr.GetClientCount()
		}

		var currentStats ebpf.GlobalStats
		var bpfErr error
		if bpfMgr != nil {
			currentStats, bpfErr = bpfMgr.GetStats() // Get stats from cache
			if bpfErr != nil {
				slog.Warn("Error retrieving BPF stats for logging (from BackgroundTasks)", "error", bpfErr)
			}
		} else {
			slog.Warn("BPF Manager not available for stats logging (from BackgroundTasks)")
		}

		slog.Info("Service Status (Logged by BackgroundTasks)",
			"uptime", uptime.String(),
			"active_clients", clientCount,
			"bpf_total_redirected", currentStats.Redirected,
			"bpf_total_getsockopt_ok", currentStats.GetsockoptOk,
			"bpf_total_getsockopt_fail", currentStats.GetsockoptFail,
		)
	}
}
