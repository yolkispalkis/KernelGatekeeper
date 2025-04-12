// FILE: pkg/ebpf/manager.go
package ebpf

//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_connect4 ./bpf/connect4.c -- -I./bpf -D__TARGET_ARCH_x86
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_sockops ./bpf/sockops.c -- -I./bpf -D__TARGET_ARCH_x86
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_getsockopt ./bpf/getsockopt.c -- -I./bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

const (
	StatsRedirectedIndex      uint32 = 1
	StatsGetsockoptOkIndex    uint32 = 2
	StatsGetsockoptFailIndex  uint32 = 3
	StatsSockopsPassOkIndex   uint32 = 4
	StatsSockopsPassFailIndex uint32 = 5
	DefaultCgroupPath                = "/sys/fs/cgroup"
	ExcludedMapMaxEntries            = 1024
	DefaultRedirSportMapSize         = 8192
)

// --- Типы данных BPF (используем сгенерированные) ---
type OriginalDestT = bpf_connect4OriginalDestT
type BpfGlobalStatsT = bpf_connect4GlobalStatsT
type BpfKgConfigT = bpf_connect4KgConfigT
type BpfDevInodeKey = bpf_connect4DevInodeKey
type BpfNotificationTupleT = bpf_connect4NotificationTupleT // Используем правильный сгенерированный тип

// --- Типы данных Go ---
type NotificationTuple struct {
	PidTgid     uint64
	SrcIP       net.IP
	OrigDstIP   net.IP
	SrcPort     uint16
	OrigDstPort uint16
	Protocol    uint8
}

type StatsCache struct {
	mu             sync.Mutex
	lastTotalStats GlobalStats
	lastStatsTime  time.Time
}

type bpfObjects struct {
	bpf_connect4Objects
	bpf_sockopsObjects
	bpf_getsockoptObjects

	KernelgatekeeperConnect4   *ebpf.Program `ebpf:"kernelgatekeeper_connect4"`
	KernelgatekeeperSockops    *ebpf.Program `ebpf:"kernelgatekeeper_sockops"`
	KernelgatekeeperGetsockopt *ebpf.Program `ebpf:"kernelgatekeeper_getsockopt"`

	ExcludedDevInodes  *ebpf.Map `ebpf:"excluded_dev_inodes"`
	KgOrigDest         *ebpf.Map `ebpf:"kg_orig_dest"`
	KgRedirSportToOrig *ebpf.Map `ebpf:"kg_redir_sport_to_orig"`
	TargetPorts        *ebpf.Map `ebpf:"target_ports"`
	KgClientPids       *ebpf.Map `ebpf:"kg_client_pids"`
	KgConfig           *ebpf.Map `ebpf:"kg_config"`
	KgStats            *ebpf.Map `ebpf:"kg_stats"`
	KgNotifRb          *ebpf.Map `ebpf:"kg_notif_rb"`
}

func (o *bpfObjects) Close() error {
	closers := []io.Closer{
		&o.bpf_connect4Objects,
		&o.bpf_sockopsObjects,
		&o.bpf_getsockoptObjects,
	}
	var errs []error
	for _, closer := range closers {
		// Check if the closer itself is non-nil before calling Close
		if c, ok := closer.(interface{ Close() error }); ok && !isNil(c) {
			if err := c.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, ringbuf.ErrClosed) {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		finalErr := errors.New("errors closing BPF objects")
		for _, err := range errs {
			finalErr = fmt.Errorf("%w; %w", finalErr, err)
		}
		return finalErr
	}
	return nil
}

// Helper function to check if an interface is nil (needed for embedded structs)
func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch v := i.(type) {
	case interface{ isNil() bool }: // Check if the type has an isNil method (common for pointers in generated code)
		return v.isNil()
	default:
		// Fallback using reflection for other types
		// Be cautious with reflection performance if called frequently
		// return reflect.ValueOf(i).IsNil() // Requires careful handling of non-pointer/interface types
		return false // Assume not nil if no isNil method and not directly nil
	}
}

type BPFManager struct {
	cfg                 *config.EBPFConfig
	objs                bpfObjects
	connect4Link        link.Link
	sockopsLink         link.Link
	getsockoptLink      link.Link
	stopOnce            sync.Once
	stopChan            chan struct{}
	statsCache          StatsCache
	mu                  sync.Mutex
	notificationReader  *ringbuf.Reader
	notificationChannel chan NotificationTuple
	currentExcluded     map[BpfDevInodeKey]string
}

// Configurable EBPF parameters (now part of pkg/config)
// type EBPFConfig struct { ... }

// GlobalStats structure mirroring the C struct
type GlobalStats struct {
	Packets         uint64
	Bytes           uint64
	Redirected      uint64
	GetsockoptOk    uint64
	GetsockoptFail  uint64
	SockopsPassOk   uint64
	SockopsPassFail uint64
}

func NewBPFManager(cfg *config.EBPFConfig, listenerIP net.IP, listenerPort uint16) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "connect4/sockops/getsockopt")
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Warn("Failed to remove memlock rlimit, BPF loading might fail if limits are low", "error", err)
	}

	var objs bpfObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// PinPath: "/sys/fs/bpf/kernelgatekeeper", // Optional pinning
		},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction, // Adjust log level as needed
			LogSize:  1024 * 1024 * 4,          // Use LogSize (VerifierLogSize is likely incorrect)
		},
	}

	specConnect4, err := loadBpf_connect4()
	if err != nil {
		return nil, fmt.Errorf("failed to load connect4 BPF spec: %w", err)
	}

	adjustMapSpec := func(spec *ebpf.MapSpec, name string, maxEntries uint32) {
		if spec != nil && spec.Name == name && maxEntries > 0 {
			spec.MaxEntries = maxEntries
			slog.Debug("Adjusting map spec size", "map", name, "new_max_entries", maxEntries)
		}
	}
	if maps := specConnect4.Maps; maps != nil {
		origDestMapSize := cfg.OrigDestMapSize
		if origDestMapSize <= 0 {
			origDestMapSize = config.DefaultEBPFMapSize
			slog.Warn("ebpf.origDestMapSize invalid or not set, using default", "default", origDestMapSize)
		}
		adjustMapSpec(maps["kg_orig_dest"], "kg_orig_dest", uint32(origDestMapSize))

		redirSportMapSize := cfg.RedirSportMapSize
		if redirSportMapSize <= 0 {
			redirSportMapSize = DefaultRedirSportMapSize
			slog.Warn("ebpf.redirSportMapSize invalid or not set, using default", "default", redirSportMapSize)
		}
		adjustMapSpec(maps["kg_redir_sport_to_orig"], "kg_redir_sport_to_orig", uint32(redirSportMapSize))

		adjustMapSpec(maps["excluded_dev_inodes"], "excluded_dev_inodes", ExcludedMapMaxEntries)
		adjustMapSpec(maps["target_ports"], "target_ports", 65536)
		adjustMapSpec(maps["kg_client_pids"], "kg_client_pids", 1024) // Example size
	}

	if err := specConnect4.LoadAndAssign(&objs.bpf_connect4Objects, opts); err != nil {
		handleVerifierError("connect4", err)
		return nil, fmt.Errorf("failed to load eBPF connect4 objects: %w", err)
	}
	slog.Debug("eBPF connect4 objects loaded successfully.")

	objs.ExcludedDevInodes = objs.bpf_connect4Objects.ExcludedDevInodes
	objs.KgOrigDest = objs.bpf_connect4Objects.KgOrigDest
	objs.KgRedirSportToOrig = objs.bpf_connect4Objects.KgRedirSportToOrig
	objs.TargetPorts = objs.bpf_connect4Objects.TargetPorts
	objs.KgClientPids = objs.bpf_connect4Objects.KgClientPids
	objs.KgConfig = objs.bpf_connect4Objects.KgConfig
	objs.KgStats = objs.bpf_connect4Objects.KgStats
	objs.KgNotifRb = objs.bpf_connect4Objects.KgNotifRb

	specSockops, err := loadBpf_sockops()
	if err != nil {
		objs.bpf_connect4Objects.Close()
		return nil, fmt.Errorf("failed to load sockops BPF spec: %w", err)
	}
	opts.MapReplacements = map[string]*ebpf.Map{
		"kg_orig_dest":           objs.KgOrigDest,
		"kg_redir_sport_to_orig": objs.KgRedirSportToOrig,
		"kg_notif_rb":            objs.KgNotifRb,
		"kg_stats":               objs.KgStats,
	}
	if err := specSockops.LoadAndAssign(&objs.bpf_sockopsObjects, opts); err != nil {
		handleVerifierError("sockops", err)
		objs.bpf_connect4Objects.Close()
		return nil, fmt.Errorf("failed to load eBPF sockops objects: %w", err)
	}
	slog.Debug("eBPF sockops objects loaded successfully.")

	specGetsockopt, err := loadBpf_getsockopt()
	if err != nil {
		objs.bpf_connect4Objects.Close()
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load getsockopt BPF spec: %w", err)
	}
	opts.MapReplacements = map[string]*ebpf.Map{
		"kg_redir_sport_to_orig": objs.KgRedirSportToOrig,
		"kg_stats":               objs.KgStats,
	}
	if err := specGetsockopt.LoadAndAssign(&objs.bpf_getsockoptObjects, opts); err != nil {
		handleVerifierError("getsockopt", err)
		objs.bpf_connect4Objects.Close()
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load eBPF getsockopt objects: %w", err)
	}
	slog.Debug("eBPF getsockopt objects loaded successfully.")

	objs.KernelgatekeeperConnect4 = objs.bpf_connect4Objects.KernelgatekeeperConnect4
	objs.KernelgatekeeperSockops = objs.bpf_sockopsObjects.KernelgatekeeperSockops
	objs.KernelgatekeeperGetsockopt = objs.bpf_getsockoptObjects.KernelgatekeeperGetsockopt

	if objs.KernelgatekeeperConnect4 == nil || objs.KernelgatekeeperSockops == nil || objs.KernelgatekeeperGetsockopt == nil ||
		objs.KgOrigDest == nil || objs.KgRedirSportToOrig == nil || objs.TargetPorts == nil ||
		objs.KgClientPids == nil || objs.KgNotifRb == nil ||
		objs.KgConfig == nil || objs.KgStats == nil || objs.ExcludedDevInodes == nil {
		manager := &BPFManager{objs: objs}
		manager.Close()
		return nil, errors.New("one or more required BPF programs or maps failed to load or assign")
	}

	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs,
		stopChan:            make(chan struct{}),
		notificationChannel: make(chan NotificationTuple, cfg.NotificationChannelSize),
		currentExcluded:     make(map[BpfDevInodeKey]string),
		statsCache: StatsCache{
			lastStatsTime: time.Now(),
		},
	}

	rd, err := ringbuf.NewReader(objs.KgNotifRb)
	if err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	manager.notificationReader = rd
	slog.Info("BPF ring buffer reader initialized.")

	if err := manager.UpdateConfigMap(listenerIP, listenerPort); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial BPF config map: %w", err)
	}
	if err := manager.UpdateTargetPorts(cfg.TargetPorts); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial target ports in BPF map: %w", err)
	}
	// Initial exclude update is handled by the caller (StateManager) after BPFManager is created

	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close()
		return nil, err
	}

	slog.Info("BPF Manager initialized and programs attached successfully.")
	return manager, nil
}

func (m *BPFManager) updateAndLogStats() error {
	m.statsCache.mu.Lock()
	defer m.statsCache.mu.Unlock()
	now := time.Now()
	duration := now.Sub(m.statsCache.lastStatsTime).Seconds()
	if duration < 0.1 {
		slog.Debug("Skipping stats update, interval too short", "duration_sec", duration)
		return nil
	}

	currentStats, err := m.readGlobalStats()
	if err != nil {
		slog.Error("Failed to read BPF stats for updateAndLogStats", "error", err)
		m.statsCache.lastStatsTime = now
		return nil
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
	sockopsPassOkRate := calculateRate(currentStats.SockopsPassOk, m.statsCache.lastTotalStats.SockopsPassOk)
	sockopsPassFailRate := calculateRate(currentStats.SockopsPassFail, m.statsCache.lastTotalStats.SockopsPassFail)

	slog.Info("eBPF Statistics Update",
		"total_pkts", currentStats.Packets,
		"total_redirected", currentStats.Redirected,
		"redirect_rate_pps", fmt.Sprintf("%.2f", redirectRate),
		"total_getsockopt_ok", currentStats.GetsockoptOk,
		"getsockopt_ok_rate_pps", fmt.Sprintf("%.2f", getsockoptOkRate),
		"total_getsockopt_fail", currentStats.GetsockoptFail,
		"getsockopt_fail_rate_pps", fmt.Sprintf("%.2f", getsockoptFailRate),
		"total_sockops_pass_ok", currentStats.SockopsPassOk,
		"sockops_pass_ok_rate_pps", fmt.Sprintf("%.2f", sockopsPassOkRate),
		"total_sockops_pass_fail", currentStats.SockopsPassFail,
		"sockops_pass_fail_rate_pps", fmt.Sprintf("%.2f", sockopsPassFailRate),
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
		return aggregate, errors.New("BPF kg_stats map is nil")
	}

	var perCPUValues []BpfGlobalStatsT // Read the BPF struct type
	var mapKey uint32 = 0
	// Corrected: Use LookupPerCPU, the map type is PERCPU_ARRAY
	if err := globalStatsMap.LookupPerCPU(mapKey, &perCPUValues); err != nil {
		// Note: LookupPerCPU doesn't return ErrKeyNotExist. It returns an empty slice if key 0 doesn't exist (unlikely for array)
		// or if map is empty/uninitialized.
		// Handle the error generally.
		return aggregate, fmt.Errorf("failed to lookup per-CPU stats key %d in BPF kg_stats map: %w", mapKey, err)
	}

	for _, cpuStat := range perCPUValues {
		aggregate.Packets += cpuStat.Packets
		aggregate.Bytes += cpuStat.Bytes
		aggregate.Redirected += cpuStat.Redirected
		aggregate.GetsockoptOk += cpuStat.GetsockoptOk
		aggregate.GetsockoptFail += cpuStat.GetsockoptFail
		aggregate.SockopsPassOk += cpuStat.SockopsPassOk
		aggregate.SockopsPassFail += cpuStat.SockopsPassFail
	}
	return aggregate, nil
}

func handleVerifierError(objType string, err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		slog.Error(fmt.Sprintf("eBPF Verifier error (loading %s objects)", objType), "log_len", len(fmt.Sprintf("%+v", verr)))
		logOutput := fmt.Sprintf("%+v", verr)
		maxLen := 4096
		if len(logOutput) > maxLen {
			logOutput = logOutput[:maxLen/2] + "\n...\n" + logOutput[len(logOutput)-maxLen/2:]
		}
		slog.Debug("eBPF Verifier Log (truncated)", "log_output", logOutput)
	} else {
		slog.Error(fmt.Sprintf("Error loading %s BPF objects (non-verifier)", objType), "error", err)
	}
}

func (m *BPFManager) attachPrograms(cgroupPath string) error {
	connect4Prog := m.objs.KernelgatekeeperConnect4
	sockopsProg := m.objs.KernelgatekeeperSockops
	getsockoptProg := m.objs.KernelgatekeeperGetsockopt

	if connect4Prog == nil || sockopsProg == nil || getsockoptProg == nil {
		return errors.New("internal error: one or more required BPF programs are nil during attach phase")
	}

	fi, err := os.Stat(cgroupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("cgroup v2 path '%s' does not exist", cgroupPath)
		}
		return fmt.Errorf("failed to stat cgroup v2 path '%s': %w", cgroupPath, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("cgroup v2 path '%s' is not a directory", cgroupPath)
	}

	var linkErr error
	m.connect4Link, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: connect4Prog, Attach: ebpf.AttachCGroupInet4Connect})
	if linkErr != nil {
		return fmt.Errorf("failed to attach connect4 program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF connect4 program attached to cgroup", "path", cgroupPath)

	m.sockopsLink, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: sockopsProg, Attach: ebpf.AttachCGroupSockOps})
	if linkErr != nil {
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sock_ops program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF sock_ops program attached to cgroup", "path", cgroupPath)

	m.getsockoptLink, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: getsockoptProg, Attach: ebpf.AttachCGroupGetsockopt})
	if linkErr != nil {
		m.sockopsLink.Close()
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach getsockopt program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF getsockopt program attached to cgroup", "path", cgroupPath)

	return nil
}

func getDevInodeFromFile(filePath string) (BpfDevInodeKey, error) {
	var key BpfDevInodeKey
	cleanedPath := filepath.Clean(filePath)
	fileInfo, err := os.Stat(cleanedPath)
	if err != nil {
		return key, fmt.Errorf("failed to stat file %s: %w", cleanedPath, err)
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return key, fmt.Errorf("failed to convert FileInfo.Sys() to syscall.Stat_t for %s (unexpected OS or type?)", cleanedPath)
	}

	key.DevId = stat.Dev
	key.InodeId = stat.Ino

	if key.DevId == 0 || key.InodeId == 0 {
		slog.Warn("Stat returned zero dev or inode for existing file, this is unusual", "path", cleanedPath, "dev", key.DevId, "inode", key.InodeId)
	}

	return key, nil
}

func (m *BPFManager) UpdateExcludedExecutables(paths []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	excludeMap := m.objs.ExcludedDevInodes
	if excludeMap == nil {
		return errors.New("BPF excluded_dev_inodes map not initialized")
	}

	slog.Debug("Updating BPF excluded executables map...", "requested_paths_count", len(paths))

	desiredExcluded := make(map[BpfDevInodeKey]string)
	var errorsList []error
	for _, p := range paths {
		if p == "" {
			continue
		}
		key, err := getDevInodeFromFile(p)
		if err != nil {
			slog.Error("Failed to get dev/inode for excluded path, skipping", "path", p, "error", err)
			errorsList = append(errorsList, fmt.Errorf("path '%s': %w", p, err))
			continue
		}
		desiredExcluded[key] = p
	}

	keysToDelete := make([]BpfDevInodeKey, 0)
	for cachedKey, cachedPath := range m.currentExcluded {
		if _, exists := desiredExcluded[cachedKey]; !exists {
			keysToDelete = append(keysToDelete, cachedKey)
			slog.Debug("Marking for deletion from BPF exclude map", "dev", cachedKey.DevId, "inode", cachedKey.InodeId, "path", cachedPath)
		}
	}

	keysToAdd := make(map[BpfDevInodeKey]string)
	for desiredKey, desiredPath := range desiredExcluded {
		if _, exists := m.currentExcluded[desiredKey]; !exists {
			keysToAdd[desiredKey] = desiredPath
			slog.Debug("Marking for addition to BPF exclude map", "dev", desiredKey.DevId, "inode", desiredKey.InodeId, "path", desiredPath)
		}
	}

	var deleteErrors []error
	var valueOne uint8 = 1
	for _, key := range keysToDelete {
		if err := excludeMap.Delete(key); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("Failed to delete key from BPF exclude map", "dev", key.DevId, "inode", key.InodeId, "error", err)
				deleteErrors = append(deleteErrors, err)
			}
		} else {
			delete(m.currentExcluded, key)
		}
	}

	var addErrors []error
	for key, path := range keysToAdd {
		if err := excludeMap.Put(key, valueOne); err != nil {
			slog.Error("Failed to add key to BPF exclude map", "dev", key.DevId, "inode", key.InodeId, "path", path, "error", err)
			addErrors = append(addErrors, err)
		} else {
			m.currentExcluded[key] = path
		}
	}

	finalError := ""
	if len(errorsList) > 0 {
		finalError += fmt.Sprintf("Stat errors: %v. ", errorsList)
	}
	if len(deleteErrors) > 0 {
		finalError += fmt.Sprintf("Delete errors: %v. ", deleteErrors)
	}
	if len(addErrors) > 0 {
		finalError += fmt.Sprintf("Add errors: %v.", addErrors)
	}

	if finalError != "" {
		slog.Error("Errors occurred during BPF excluded executables update", "details", finalError)
		return errors.New("failed to fully update BPF excluded executables map: " + finalError)
	}

	slog.Info("BPF excluded executables map updated successfully", "current_excluded_count", len(m.currentExcluded))
	if m.cfg != nil {
		m.cfg.Excluded = paths
	}
	return nil
}

func (m *BPFManager) statsUpdater(ctx context.Context) {
	slog.Debug("BPF stats updater task started.")
	interval := time.Duration(m.cfg.StatsInterval) * time.Second
	if interval <= 1*time.Second {
		interval = 15 * time.Second
		slog.Warn("Invalid or too frequent ebpf.stats_interval, using default for updater.", "default", interval)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF stats updater task (context cancelled).")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF stats updater task (stop signal).")
			return
		case <-ticker.C:
			if err := m.updateAndLogStats(); err != nil {
				slog.Error("Error during periodic BPF stats update", "error", err)
			}
		}
	}
}

func (m *BPFManager) Start(ctx context.Context, wg *sync.WaitGroup) error {
	slog.Info("Starting BPF Manager background tasks...")

	wg.Add(1)
	go func() {
		defer wg.Done()
		m.statsUpdater(ctx)
	}()

	if m.notificationReader != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.readNotifications(ctx)
		}()
	} else {
		slog.Warn("BPF notification reader task not started (reader not initialized).")
	}

	return nil
}

func (m *BPFManager) Close() error {
	var firstErr error
	m.stopOnce.Do(func() {
		slog.Info("Closing BPF Manager...")

		select {
		case <-m.stopChan:
		default:
			close(m.stopChan)
		}

		if m.notificationReader != nil {
			slog.Debug("Closing BPF ring buffer reader...")
			if err := m.notificationReader.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, ringbuf.ErrClosed) {
				slog.Error("Error closing BPF ring buffer reader", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("ring buffer reader close: %w", err)
				}
			}
			m.notificationReader = nil
		}

		links := []link.Link{m.getsockoptLink, m.sockopsLink, m.connect4Link}
		linkNames := []string{"getsockopt", "sockops", "connect4"}
		for i, l := range links {
			if l != nil {
				slog.Debug(fmt.Sprintf("Closing BPF %s link...", linkNames[i]))
				// Corrected: Use link.ErrNotAttached from the correct package
				if err := l.Close(); err != nil && !errors.Is(err, link.ErrNotAttached) {
					slog.Error(fmt.Sprintf("Error closing BPF %s link", linkNames[i]), "error", err)
					if firstErr == nil {
						firstErr = fmt.Errorf("%s link close: %w", linkNames[i], err)
					}
				} else if errors.Is(err, link.ErrNotAttached) {
					slog.Debug(fmt.Sprintf("BPF %s link was already detached", linkNames[i]))
				}
			}
		}
		m.getsockoptLink, m.sockopsLink, m.connect4Link = nil, nil, nil

		slog.Debug("Closing all BPF objects (programs and maps)...")
		if err := m.objs.Close(); err != nil {
			slog.Error("Error closing BPF objects", "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("bpf objects close: %w", err)
			} else {
				firstErr = fmt.Errorf("%w; bpf objects close: %w", firstErr, err)
			}
		}

		if m.notificationChannel != nil {
			select {
			case <-m.notificationChannel:
			default:
				close(m.notificationChannel)
			}
			m.notificationChannel = nil
		}

		slog.Info("BPF Manager closed.")
	})
	return firstErr
}

func (m *BPFManager) GetStats() (GlobalStats, error) {
	m.statsCache.mu.Lock()
	defer m.statsCache.mu.Unlock()
	statsCopy := m.statsCache.lastTotalStats
	return statsCopy, nil
}

func (m *BPFManager) GetNotificationChannel() <-chan NotificationTuple {
	return m.notificationChannel
}

func (m *BPFManager) UpdateTargetPorts(ports []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	targetPortsMap := m.objs.TargetPorts
	if targetPortsMap == nil {
		return errors.New("BPF target_ports map not initialized")
	}

	currentPortsMap := make(map[uint16]bool)
	var mapKey uint16
	var mapValue uint8
	iter := targetPortsMap.Iterate()
	for iter.Next(&mapKey, &mapValue) {
		if mapValue == 1 {
			currentPortsMap[mapKey] = true
		}
	}
	if err := iter.Err(); err != nil {
		slog.Warn("Failed to fully iterate existing BPF target_ports map", "error", err)
	}

	desiredPortsSet := make(map[uint16]bool)
	validNewPortsList := make([]int, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			portKey := uint16(p)
			desiredPortsSet[portKey] = true
			validNewPortsList = append(validNewPortsList, p)
		} else {
			slog.Warn("Invalid port number ignored in UpdateTargetPorts", "port", p)
		}
	}

	deletedCount := 0
	for portKey := range currentPortsMap {
		if !desiredPortsSet[portKey] {
			if err := targetPortsMap.Delete(portKey); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					slog.Error("Failed to delete target port from BPF map", "port", portKey, "error", err)
				}
			} else {
				slog.Debug("Deleted target port from BPF map", "port", portKey)
				deletedCount++
			}
		}
	}

	addedCount := 0
	var mapValueOne uint8 = 1
	for portKey := range desiredPortsSet {
		if !currentPortsMap[portKey] {
			if err := targetPortsMap.Put(portKey, mapValueOne); err != nil {
				slog.Error("Failed to add target port to BPF map", "port", portKey, "error", err)
			} else {
				slog.Debug("Added target port to BPF map", "port", portKey)
				addedCount++
			}
		}
	}

	if addedCount > 0 || deletedCount > 0 {
		slog.Info("BPF target ports map updated", "added", addedCount, "deleted", deletedCount, "final_list", validNewPortsList)
	} else {
		slog.Debug("BPF target ports map remains unchanged", "current_list", validNewPortsList)
	}

	if m.cfg != nil {
		m.cfg.TargetPorts = validNewPortsList
	}
	return nil
}

func (m *BPFManager) UpdateConfigMap(listenerIP net.IP, listenerPort uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	configMap := m.objs.KgConfig
	if configMap == nil {
		return errors.New("BPF kg_config map not initialized")
	}

	ipv4 := listenerIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("listener IP is not IPv4: %s", listenerIP.String())
	}

	var listenerIPInt uint32
	if len(ipv4) == 4 {
		listenerIPInt = binary.BigEndian.Uint32(ipv4)
	} else {
		return fmt.Errorf("unexpected IP format: %s", ipv4.String())
	}

	cfgValue := BpfKgConfigT{
		ListenerIp:   listenerIPInt,
		ListenerPort: listenerPort, // BPF side expects Host Byte Order here, htons is done in BPF C code if needed
	}

	var mapKey uint32 = 0
	if err := configMap.Update(mapKey, cfgValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update kg_config BPF map: %w", err)
	}

	slog.Info("BPF config map updated", "listener_ip", listenerIP, "listener_port", listenerPort)
	return nil
}

func (m *BPFManager) AddExcludedPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clientPidsMap := m.objs.KgClientPids
	if clientPidsMap == nil {
		return errors.New("BPF kg_client_pids map not initialized")
	}

	var mapValue uint8 = 1
	if err := clientPidsMap.Put(pid, mapValue); err != nil {
		return fmt.Errorf("failed to add excluded PID %d to BPF map: %w", pid, err)
	}
	slog.Debug("Added excluded PID to BPF map", "pid", pid)
	return nil
}

func (m *BPFManager) RemoveExcludedPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clientPidsMap := m.objs.KgClientPids
	if clientPidsMap == nil {
		return errors.New("BPF kg_client_pids map not initialized")
	}

	if err := clientPidsMap.Delete(pid); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Debug("Attempted to remove non-existent excluded PID from BPF map", "pid", pid)
			return nil
		}
		return fmt.Errorf("failed to delete excluded PID %d from BPF map: %w", pid, err)
	}
	slog.Debug("Removed excluded PID from BPF map", "pid", pid)
	return nil
}

func (m *BPFManager) readNotifications(ctx context.Context) {
	var bpfTuple BpfNotificationTupleT // Use the alias defined earlier
	tupleSize := binary.Size(bpfTuple)
	if tupleSize <= 0 {
		slog.Error("Could not determine size of BpfNotificationTupleT", "size", tupleSize)
		return
	}
	slog.Debug("BPF ring buffer reader expecting record size", "size", tupleSize)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader due to context cancellation.")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF ring buffer reader due to stop signal.")
			return
		default:
		}

		record, err := m.notificationReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				slog.Info("BPF ring buffer reader closed.")
				return
			}
			if errors.Is(err, context.Canceled) {
				slog.Info("BPF ring buffer reading cancelled by context.")
				return
			}
			slog.Error("Error reading from BPF ring buffer", "error", err)
			select {
			case <-time.After(100 * time.Millisecond):
				continue
			case <-ctx.Done():
				return
			case <-m.stopChan:
				return
			}
		}
		slog.Debug("Received raw BPF ring buffer record", "len", len(record.RawSample))

		if len(record.RawSample) < tupleSize {
			slog.Warn("Received BPF ring buffer event with unexpected size, skipping.", "expected_min", tupleSize, "received", len(record.RawSample))
			continue
		}

		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, common.NativeEndian, &bpfTuple); err != nil {
			slog.Error("Failed to decode BPF ring buffer event data into BpfNotificationTupleT", "error", err)
			continue
		}

		event := NotificationTuple{
			PidTgid:     bpfTuple.PidTgid,
			SrcIP:       bpfutil.IpFromInt(bpfTuple.SrcIp),
			OrigDstIP:   bpfutil.IpFromInt(bpfTuple.OrigDstIp),
			SrcPort:     bpfutil.Ntohs(bpfTuple.SrcPort),
			OrigDstPort: bpfutil.Ntohs(bpfTuple.OrigDstPort),
			Protocol:    bpfTuple.Protocol,
		}

		select {
		case m.notificationChannel <- event:
			slog.Debug("Sent BPF connection notification to service processor", "pid_tgid", event.PidTgid, "src_ip", event.SrcIP, "src_port", event.SrcPort, "orig_dst_ip", event.OrigDstIP, "orig_dst_port", event.OrigDstPort)
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader while sending notification (context cancelled).")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF ring buffer reader while sending notification (stop signal).")
			return
		default:
			slog.Warn("BPF notification channel is full, dropping event.", "channel_cap", cap(m.notificationChannel), "channel_len", len(m.notificationChannel), "event_dst_port", event.OrigDstPort)
		}
	}
}
