package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

type StatsCache struct {
	sync.RWMutex
	matchedConns, lastMatched GlobalStats
	lastStatsTime             time.Time
}

func (m *BPFManager) statsUpdater(ctx context.Context) {
	if m.cfg.StatsInterval <= 0 {
		slog.Info("BPF statistics collection disabled (stats_interval <= 0).")
		return
	}
	interval := time.Duration(m.cfg.StatsInterval) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
		slog.Warn("Invalid ebpf.stats_interval configured, using default.", "default", interval)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("BPF statistics updater started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF statistics updater due to context cancellation.")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF statistics updater due to stop signal.")
			return
		case <-ticker.C:
			if err := m.updateAndLogStats(); err != nil {
				slog.Error("Failed to update BPF statistics", "error", err)
			}
		}
	}
}

func (m *BPFManager) updateAndLogStats() error {
	m.statsCache.Lock()
	defer m.statsCache.Unlock()
	now := time.Now()
	duration := now.Sub(m.statsCache.lastStatsTime).Seconds()
	if duration < 0.1 {
		slog.Debug("Skipping stats update, interval too short", "duration_sec", duration)
		return nil
	}

	matchedCurrent, err := m.readGlobalStats(GlobalStatsMatchedIndex)
	if err != nil {
		return fmt.Errorf("failed to read matched BPF stats: %w", err)
	}

	matchedRateP := 0.0
	deltaPackets := int64(matchedCurrent.Packets - m.statsCache.lastMatched.Packets)
	if deltaPackets < 0 {
		slog.Warn("BPF matched connection counter appeared to wrap or reset", "last", m.statsCache.lastMatched.Packets, "current", matchedCurrent.Packets)
		deltaPackets = int64(matchedCurrent.Packets)
	}
	if duration > 0 {
		matchedRateP = float64(deltaPackets) / duration
	}

	slog.Info("eBPF Statistics",
		slog.Group("matched_conns",
			"total_conns", matchedCurrent.Packets,
			"conn_rate_per_sec", fmt.Sprintf("%.2f", matchedRateP),
		),
		"interval_sec", fmt.Sprintf("%.2f", duration),
	)

	m.statsCache.lastMatched = matchedCurrent
	m.statsCache.lastStatsTime = now
	return nil
}

func (m *BPFManager) readGlobalStats(index uint32) (GlobalStats, error) {
	var aggregate GlobalStats
	globalStatsMap := m.objs.GlobalStats
	if globalStatsMap == nil {
		return aggregate, errors.New("BPF global_stats map is nil (was it loaded?)")
	}

	var perCPUValues []BpfGlobalStatsT
	err := globalStatsMap.Lookup(index, &perCPUValues)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Debug("Stats key not found in BPF global_stats map, returning zero stats.", "key", index)
			return aggregate, nil
		}
		return aggregate, fmt.Errorf("failed lookup stats key %d in BPF global_stats map: %w", index, err)
	}

	for _, cpuStat := range perCPUValues {
		aggregate.Packets += cpuStat.Packets
		aggregate.Bytes += cpuStat.Bytes
	}
	return aggregate, nil
}

func (m *BPFManager) GetStats() (totalIgnored GlobalStats, matched GlobalStats, err error) {
	m.statsCache.RLock()
	defer m.statsCache.RUnlock()
	totalIgnored = GlobalStats{}
	matched = m.statsCache.lastMatched
	return totalIgnored, matched, nil
}
