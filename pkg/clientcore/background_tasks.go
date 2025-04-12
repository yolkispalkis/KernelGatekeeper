// FILE: pkg/servicecore/background_tasks.go
package servicecore

import (
	"context"
	"log/slog"
	"time"
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

func (bt *BackgroundTasks) RunStatsLogger(ctx context.Context) {
	sm := bt.stateManager
	if sm == nil {
		slog.Error("BackgroundTasks cannot run stats logger: StateManager is nil")

		return
	}
	sm.AddWaitGroup(1)
	// stateManager.statsLoggerRunning is now internal to stateManager
	// sm.statsLoggerRunning.Store(true) // Removed
	defer sm.WaitGroupDone()

	// Stats logger logic is now handled within StateManager.logPeriodicStats
	// The ticker logic and calling performPeriodicStatsLog are there.
	// This function might not be needed anymore, or could just call stateManager.RunStatsLoggerInternal or similar.
	// For now, let's assume StateManager handles its own stats logging goroutine initiation.
	// If this BackgroundTasks struct is still needed for other tasks, keep it.
	// If not, this file could potentially be removed.

	slog.Warn("RunStatsLogger called in BackgroundTasks, but logic moved to StateManager. Ensure StateManager.StartBackgroundTasks handles this.")
	// Keep the function but make it a no-op or call the state manager's internal runner if designed that way.
	// To avoid breaking changes immediately, keep it as a placeholder.
	// Let StateManager.StartBackgroundTasks handle the actual goroutine start.
	<-ctx.Done() // Wait for cancellation if this goroutine is somehow still started externally
}

func (bt *BackgroundTasks) logPeriodicStats() {
	// This function is now effectively replaced by stateManager.performPeriodicStatsLog()
	slog.Warn("BackgroundTasks.logPeriodicStats called, but logic is now in StateManager.")
	if bt.stateManager != nil {
		// Call the new method in StateManager if needed for some reason,
		// but ideally the StateManager's own goroutine handles this.
		// bt.stateManager.performPeriodicStatsLog()
	}
}
