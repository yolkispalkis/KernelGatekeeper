package servicecore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/yolki/kernelgatekeeper/pkg/ebpf"
)

const (
	statsLogInterval = 5 * time.Minute
)

type BackgroundTasks struct {
	stateManager *StateManager
}

func NewBackgroundTasks(stateMgr *StateManager) *BackgroundTasks {
	return &BackgroundTasks{
		stateManager: stateMgr,
	}
}

// RunStatsLogger starts only the periodic stats logging task.
func (bt *BackgroundTasks) RunStatsLogger(ctx context.Context) {
	ticker := time.NewTicker(statsLogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Periodic stats logger stopping.")
			return
		case <-ticker.C:
			bt.logPeriodicStats()
		}
	}
}

func (bt *BackgroundTasks) logPeriodicStats() {
	bpfMgr := bt.stateManager.GetBpfManager()
	clientMgr := bt.stateManager.GetClientManager()
	notifChan := bt.stateManager.GetNotificationChannel()

	notifChanLen := 0
	notifChanCap := 0
	if notifChan != nil {
		notifChanLen = len(notifChan)
		notifChanCap = cap(notifChan)
	}

	clientCount := clientMgr.GetClientCount()
	chanUtil := 0.0
	if notifChanCap > 0 {
		chanUtil = float64(notifChanLen) * 100 / float64(notifChanCap)
	}

	var matchedStats ebpf.GlobalStats
	var bpfErr error
	if bpfMgr != nil {
		_, matchedStats, bpfErr = bpfMgr.GetStats()
	} else {
		bpfErr = errors.New("BPF manager not initialized")
	}

	logGroup := slog.Group("service_stats",
		"connected_clients", clientCount,
		"bpf_notif_chan_len", notifChanLen,
		"bpf_notif_chan_cap", notifChanCap,
		"bpf_notif_chan_util", fmt.Sprintf("%.2f%%", chanUtil),
	)
	if bpfErr != nil {
		slog.Warn("Failed to get BPF stats", "error", bpfErr, logGroup)
	} else {
		slog.Info("Service Stats", logGroup,
			slog.Group("bpf_stats", "matched_conns_total", matchedStats.Packets),
		)
	}

	if notifChanLen > (notifChanCap * 3 / 4) {
		slog.Warn("BPF notification channel usage is high", "length", notifChanLen, "capacity", notifChanCap)
	}
}
