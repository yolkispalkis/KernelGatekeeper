// FILE: pkg/ebpf/stats.go
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
	totalStats, lastTotalStats GlobalStats
	lastStatsTime              time.Time
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

	currentStats, err := m.readGlobalStats()
	if err != nil {
		return fmt.Errorf("failed to read BPF stats: %w", err)
	}

	calculateRate := func(current, last uint64) float64 {
		delta := int64(current - last)
		if delta < 0 {
			slog.Warn("BPF counter appeared to wrap or reset", "last", last, "current", current)
			delta = int64(current)
		}
		if duration > 0 {
			return float64(delta) / duration
		}
		return 0.0
	}

	redirectRate := calculateRate(currentStats.Redirected, m.statsCache.lastTotalStats.Redirected)
	getsockoptOkRate := calculateRate(currentStats.GetsockoptOk, m.statsCache.lastTotalStats.GetsockoptOk)
	getsockoptFailRate := calculateRate(currentStats.GetsockoptFail, m.statsCache.lastTotalStats.GetsockoptFail)

	slog.Info("eBPF Statistics",
		"total_pkts", currentStats.Packets,
		"total_redirected", currentStats.Redirected,
		"redirect_rate_pps", fmt.Sprintf("%.2f", redirectRate),
		"total_getsockopt_ok", currentStats.GetsockoptOk,
		"getsockopt_ok_rate_pps", fmt.Sprintf("%.2f", getsockoptOkRate),
		"total_getsockopt_fail", currentStats.GetsockoptFail,
		"getsockopt_fail_rate_pps", fmt.Sprintf("%.2f", getsockoptFailRate),
		"interval_sec", fmt.Sprintf("%.2f", duration),
	)

	m.statsCache.lastTotalStats = currentStats
	m.statsCache.lastStatsTime = now
	return nil
}

func (m *BPFManager) readGlobalStats() (GlobalStats, error) {
	var aggregate GlobalStats
	globalStatsMap := m.objs.KgStats
	if globalStatsMap == nil {
		return aggregate, errors.New("BPF kg_stats map is nil (was it loaded?)")
	}

	var perCPUValues []BpfGlobalStatsT
	var mapKey uint32 = 0
	err := globalStatsMap.Lookup(mapKey, &perCPUValues)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Debug("Stats key not found in BPF kg_stats map, returning zero stats.", "key", mapKey)
			return aggregate, nil
		}
		return aggregate, fmt.Errorf("failed lookup stats key %d in BPF kg_stats map: %w", mapKey, err)
	}

	for _, cpuStat := range perCPUValues {
		aggregate.Packets += cpuStat.Packets
		aggregate.Bytes += cpuStat.Bytes
		aggregate.Redirected += cpuStat.Redirected
		aggregate.GetsockoptOk += cpuStat.GetsockoptOk
		aggregate.GetsockoptFail += cpuStat.GetsockoptFail
	}
	return aggregate, nil
}

func (m *BPFManager) GetStats() (GlobalStats, error) {
	m.statsCache.RLock()
	defer m.statsCache.RUnlock()

	return m.statsCache.lastTotalStats, nil
}
