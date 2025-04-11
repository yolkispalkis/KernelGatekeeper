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

func (bt *BackgroundTasks) RunStatsLogger(ctx context.Context) {
	sm := bt.stateManager
	if sm == nil {
		slog.Error("BackgroundTasks cannot run stats logger: StateManager is nil")

		return
	}
	sm.AddWaitGroup(1)
	sm.statsLoggerRunning.Store(true)
	defer sm.WaitGroupDone()

	interval := statsLogIntervalDefault

	slog.Info("Starting periodic service stats logger", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	bt.logPeriodicStats()

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

func (bt *BackgroundTasks) logPeriodicStats() {
	if bt.stateManager == nil {
		slog.Error("Cannot log stats, StateManager is nil")
		return
	}

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

		currentStats, bpfErr = bpfMgr.GetStats()

		if bpfErr != nil {
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
