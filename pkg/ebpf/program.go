// pkg/ebpf/program.go
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yolki/kernelgatekeeper/pkg/config"
)

//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf_sockops ./bpf/sockops.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf_skmsg ./bpf/skmsg.c -- -I./bpf

const (
	GlobalStatsMatchedIndex = 1
	DefaultCgroupPath       = "/sys/fs/cgroup"
)

type GlobalStats struct {
	Packets uint64
	Bytes   uint64
}

type NotificationTuple struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

type BpfConnectionStateT = bpf_sockopsConnectionStateT

type bpfObjects struct {
	KernelgatekeeperSockops *ebpf.Program
	KernelgatekeeperSkmsg   *ebpf.Program
	ConnectionMap           *ebpf.Map
	GlobalStats             *ebpf.Map
	NotificationRingbuf     *ebpf.Map
	ProxySockMap            *ebpf.Map
	TargetPorts             *ebpf.Map
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		o.KernelgatekeeperSockops,
		o.KernelgatekeeperSkmsg,
		o.ConnectionMap,
		o.GlobalStats,
		o.NotificationRingbuf,
		o.ProxySockMap,
		o.TargetPorts,
	)
}

type BPFManager struct {
	cfg                 *config.EBPFConfig
	objs                bpfObjects
	cgroupLink          link.Link
	skMsgLink           link.Link
	notificationReader  *ringbuf.Reader
	notificationChannel chan NotificationTuple
	stopOnce            sync.Once
	stopChan            chan struct{}
	statsCache          struct {
		sync.RWMutex
		matchedConns  GlobalStats
		lastMatched   GlobalStats
		lastStatsTime time.Time
	}
	mu sync.Mutex
}

func NewBPFManager(cfg *config.EBPFConfig, notifChan chan NotificationTuple) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "sockops/skmsg")

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	specSockops, err := loadBpf_sockops()
	if err != nil {
		return nil, fmt.Errorf("failed to load sockops spec: %w", err)
	}
	specSkmsg, err := loadBpf_skmsg()
	if err != nil {
		return nil, fmt.Errorf("failed to load skmsg spec: %w", err)
	}

	var objs bpfObjects

	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}

	var loadedSockopsMaps bpfSockopsMaps
	var loadedSockopsPrograms bpfSockopsPrograms
	var loadedSkmsgPrograms bpfSkmsgPrograms

	if err := specSockops.LoadAndAssign(&loadedSockopsMaps, opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			slog.Error("eBPF Verifier error (loading maps)", "log", fmt.Sprintf("%+v", verr))
		}
		return nil, fmt.Errorf("failed to load eBPF maps from sockops spec: %w", err)
	}
	slog.Debug("eBPF maps loaded successfully")

	if err := specSockops.LoadAndAssign(&loadedSockopsPrograms, opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			slog.Error("eBPF Verifier error (loading sockops program)", "log", fmt.Sprintf("%+v", verr))
		}
		_ = loadedSockopsMaps.Close()
		return nil, fmt.Errorf("failed to load eBPF sockops program: %w", err)
	}
	slog.Debug("eBPF sockops program loaded successfully")

	if err := specSkmsg.LoadAndAssign(&loadedSkmsgPrograms, opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			slog.Error("eBPF Verifier error (loading skmsg program)", "log", fmt.Sprintf("%+v", verr))
		}
		_ = loadedSockopsMaps.Close()
		_ = loadedSockopsPrograms.Close()
		return nil, fmt.Errorf("failed to load eBPF skmsg program: %w", err)
	}
	slog.Debug("eBPF skmsg program loaded successfully")

	objs.KernelgatekeeperSockops = loadedSockopsPrograms.KernelgatekeeperSockops
	objs.KernelgatekeeperSkmsg = loadedSkmsgPrograms.KernelgatekeeperSkmsg
	objs.ConnectionMap = loadedSockopsMaps.ConnectionMap
	objs.GlobalStats = loadedSockopsMaps.GlobalStats
	objs.NotificationRingbuf = loadedSockopsMaps.NotificationRingbuf
	objs.ProxySockMap = loadedSockopsMaps.ProxySockMap
	objs.TargetPorts = loadedSockopsMaps.TargetPorts

	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs,
		notificationChannel: notifChan,
		stopChan:            make(chan struct{}),
	}
	manager.statsCache.lastStatsTime = time.Now()

	if err := manager.attachPrograms(DefaultCgroupPath, objs.KernelgatekeeperSockops, objs.KernelgatekeeperSkmsg, objs.ProxySockMap); err != nil {
		manager.Close()
		return nil, err
	}

	manager.notificationReader, err = ringbuf.NewReader(objs.NotificationRingbuf)
	if err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	slog.Info("Ring buffer reader initialized")

	if err := manager.UpdateTargetPorts(cfg.TargetPorts); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial target ports: %w", err)
	}

	slog.Info("BPF Manager initialized successfully")
	return manager, nil
}

func (m *BPFManager) attachPrograms(cgroupPath string, sockopsProg *ebpf.Program, skmsgProg *ebpf.Program, sockMap *ebpf.Map) error {
	if sockopsProg == nil {
		return errors.New("sock_ops program is nil")
	}
	if skmsgProg == nil {
		return errors.New("sk_msg program is nil")
	}
	if sockMap == nil {
		return errors.New("proxy_sock_map is nil")
	}

	fi, err := os.Stat(cgroupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("cgroup v2 path %s does not exist", cgroupPath)
		}
		return fmt.Errorf("failed to stat cgroup v2 path %s: %w", cgroupPath, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("cgroup v2 path %s is not a directory", cgroupPath)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: sockopsProg,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return fmt.Errorf("attach sock_ops to cgroup %s failed: %w", cgroupPath, err)
	}
	m.cgroupLink = l
	slog.Info("sock_ops program attached to cgroup", "path", cgroupPath)

	skLink, err := link.AttachRawLink(link.RawLinkOptions{
		Program: skmsgProg,
		Attach:  ebpf.AttachSkMsgVerdict,
		Target:  sockMap.FD(),
		Flags:   0,
	})
	if err != nil {
		m.cgroupLink.Close()
		return fmt.Errorf("attach sk_msg to proxy_sock_map failed: %w", err)
	}
	m.skMsgLink = skLink
	slog.Info("sk_msg program attached to proxy_sock_map")

	return nil
}

func (m *BPFManager) Start(ctx context.Context, wg *sync.WaitGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.notificationReader == nil {
		return errors.New("BPF manager not initialized, cannot start")
	}
	slog.Info("Starting BPF Manager background tasks")
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("Starting BPF ring buffer reader...")
		m.readNotifications(ctx)
		slog.Info("BPF ring buffer reader stopped.")
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("Starting BPF statistics updater...")
		m.statsUpdater(ctx)
		slog.Info("BPF statistics updater stopped.")
	}()
	return nil
}

func (m *BPFManager) readNotifications(ctx context.Context) {
	var tupleSize = binary.Size(bpf_sockopsConnectionTupleT{})
	if tupleSize < 0 {
		slog.Error("Could not determine size of bpfConnectionTupleT (run 'make generate')")
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		default:
			record, err := m.notificationReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, errClosed) {
					slog.Warn("Ring buffer reader closed or context cancelled.")
					return
				}
				slog.Error("Error reading from ring buffer", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if len(record.RawSample) < tupleSize {
				slog.Warn("Ringbuf event has unexpected size", "expected", tupleSize, "got", len(record.RawSample))
				continue
			}

			var bpfTuple bpf_sockopsConnectionTupleT
			if err := binary.Read(bytes.NewReader(record.RawSample), nativeEndian, &bpfTuple); err != nil {
				slog.Error("Error decoding ringbuf event", "error", err)
				continue
			}

			event := NotificationTuple{
				SrcIP:    ipFromInt(bpfTuple.SrcIp),
				DstIP:    ipFromInt(bpfTuple.DstIp),
				SrcPort:  ntohs(bpfTuple.SrcPort),
				DstPort:  ntohs(bpfTuple.DstPort),
				Protocol: bpfTuple.Protocol,
			}

			select {
			case m.notificationChannel <- event:
				slog.Debug("Sent notification to service", "event", event)
			case <-ctx.Done():
				return
			case <-m.stopChan:
				return
			default:
				slog.Warn("Notification channel full, dropping event", "event", event)
			}
		}
	}
}

func (m *BPFManager) statsUpdater(ctx context.Context) {
	if m.cfg.StatsInterval <= 0 {
		slog.Info("Statistics collection disabled (stats_interval <= 0).")
		return
	}
	interval := time.Duration(m.cfg.StatsInterval) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			if err := m.updateAndLogStats(); err != nil {
				slog.Error("Failed to update eBPF stats", "error", err)
			}
		}
	}
}

func (m *BPFManager) updateAndLogStats() error {
	m.statsCache.Lock()
	defer m.statsCache.Unlock()
	now := time.Now()
	duration := now.Sub(m.statsCache.lastStatsTime).Seconds()
	if duration <= 0 {
		duration = 1
	}

	matched, err := m.readGlobalStats(GlobalStatsMatchedIndex)
	if err != nil {
		return fmt.Errorf("read matched stats: %w", err)
	}

	matchedRateP := float64(matched.Packets-m.statsCache.lastMatched.Packets) / duration

	slog.Info("eBPF Statistics (SockOps)",
		slog.Group("matched_conns",
			"total_conns", matched.Packets,
			"conn_rate_per_sec", fmt.Sprintf("%.2f", matchedRateP),
		),
		"interval_sec", fmt.Sprintf("%.2f", duration),
	)

	m.statsCache.matchedConns = matched
	m.statsCache.lastMatched = matched
	m.statsCache.lastStatsTime = now
	return nil
}

func (m *BPFManager) readGlobalStats(index uint32) (GlobalStats, error) {
	var agg GlobalStats

	if m.objs.GlobalStats == nil {
		return agg, errors.New("global_stats map is nil (run 'go generate')")
	}

	var perCPUValues []bpf_sockopsGlobalStatsT
	if err := m.objs.GlobalStats.Lookup(index, &perCPUValues); err != nil {
		return agg, fmt.Errorf("lookup stats index %d failed: %w", index, err)
	}

	for _, s := range perCPUValues {
		agg.Packets += s.Packets
		agg.Bytes += s.Bytes
	}
	return agg, nil
}

func (m *BPFManager) UpdateTargetPorts(ports []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objs.TargetPorts == nil {
		return errors.New("target_ports map not initialized (run 'go generate')")
	}

	currentPorts := make(map[uint16]bool)
	var mapKey uint16
	var mapValue uint8
	iter := m.objs.TargetPorts.Iterate()
	for iter.Next(&mapKey, &mapValue) {
		if mapValue == 1 {
			currentPorts[mapKey] = true
		}
	}
	if err := iter.Err(); err != nil {
		slog.Warn("Failed to iterate existing target_ports map, proceeding with update", "error", err)
		currentPorts = make(map[uint16]bool)
	}

	newPortsSet := make(map[uint16]bool)
	validNewPortsList := []int{}
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			portN := uint16(p)
			newPortsSet[portN] = true
			validNewPortsList = append(validNewPortsList, p)
		} else {
			slog.Warn("Invalid port number ignored", "port", p)
		}
	}

	deletedCount := 0
	for port := range currentPorts {
		if !newPortsSet[port] {
			if err := m.objs.TargetPorts.Delete(port); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					slog.Error("Failed to delete target port from BPF map", "port", port, "error", err)
				}
			} else {
				slog.Debug("Deleted target port from BPF map", "port", port)
				deletedCount++
			}
		}
	}

	addedCount := 0
	var one uint8 = 1
	for port := range newPortsSet {
		if !currentPorts[port] {
			if err := m.objs.TargetPorts.Put(port, one); err != nil {
				slog.Error("Failed to add target port to BPF map", "port", port, "error", err)
			} else {
				slog.Debug("Added target port to BPF map", "port", port)
				addedCount++
			}
		}
	}

	if addedCount > 0 || deletedCount > 0 {
		slog.Info("Target ports map updated", "added", addedCount, "deleted", deletedCount, "final_list", validNewPortsList)
	} else {
		slog.Debug("Target ports map unchanged", "ports", validNewPortsList)
	}

	m.cfg.TargetPorts = validNewPortsList
	return nil
}

func (m *BPFManager) GetConnectionPID(tuple NotificationTuple) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objs.ConnectionMap == nil {
		return 0, errors.New("connection_map not initialized (run 'go generate')")
	}

	key := bpf_sockopsConnectionTupleT{
		SrcIp:    binary.BigEndian.Uint32(tuple.SrcIP.To4()),
		DstIp:    binary.BigEndian.Uint32(tuple.DstIP.To4()),
		SrcPort:  htons(tuple.SrcPort),
		DstPort:  htons(tuple.DstPort),
		Protocol: tuple.Protocol,
	}

	var state bpf_sockopsConnectionStateT
	err := m.objs.ConnectionMap.Lookup(&key, &state)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, fmt.Errorf("connection state not found in map for tuple %+v: %w", tuple, err)
		}
		return 0, fmt.Errorf("failed to lookup connection state for tuple %+v: %w", tuple, err)
	}

	pid := uint32(state.PidTgid & 0xFFFFFFFF)
	if pid == 0 {
		return 0, errors.New("found connection state but PID is zero")
	}

	slog.Debug("Found PID for connection tuple", "tuple", tuple, "pid", pid)
	return pid, nil
}

func (m *BPFManager) GetStats() (total GlobalStats, matched GlobalStats, err error) {
	m.statsCache.RLock()
	defer m.statsCache.RUnlock()

	total = GlobalStats{}
	matched = m.statsCache.matchedConns
	return total, matched, nil
}

func (m *BPFManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	m.stopOnce.Do(func() {
		slog.Info("Closing BPF Manager...")
		close(m.stopChan)

		if m.notificationReader != nil {
			slog.Debug("Closing ring buffer reader...")
			if err := m.notificationReader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				slog.Error("Error closing ringbuf reader", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("ringbuf close: %w", err)
				}
			}
			m.notificationReader = nil
		}

		if m.skMsgLink != nil {
			slog.Debug("Closing sk_msg link...")
			if err := m.skMsgLink.Close(); err != nil {
				slog.Error("Error closing sk_msg link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("sk_msg link close: %w", err)
				}
			}
			m.skMsgLink = nil
		}
		if m.cgroupLink != nil {
			slog.Debug("Closing cgroup link...")
			if err := m.cgroupLink.Close(); err != nil {
				slog.Error("Error closing cgroup link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("cgroup link close: %w", err)
				}
			}
			m.cgroupLink = nil
		}

		slog.Debug("Closing BPF objects...")
		if err := m.objs.Close(); err != nil {
			slog.Error("Error closing BPF objects", "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("bpf objects close: %w", err)
			}
		}
		m.objs = bpfObjects{}

		slog.Info("BPF Manager closed.")
	})
	return firstErr
}

var nativeEndian binary.ByteOrder
var errClosed = errors.New("reader closed")

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = 0xABCD
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Failed to determine native byte order")
	}
}

func ipFromInt(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip
}

func ntohs(n uint16) uint16 {
	if nativeEndian == binary.BigEndian {
		return n
	}
	return (n >> 8) | (n << 8)
}

func htons(n uint16) uint16 {
	if nativeEndian == binary.BigEndian {
		return n
	}
	return (n >> 8) | (n << 8)
}

func GetAvailableInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	var names []string
	for _, i := range interfaces {
		if (i.Flags&net.FlagUp == 0) || (i.Flags&net.FlagLoopback != 0) {
			continue
		}
		if strings.HasPrefix(i.Name, "veth") || strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "br-") {
			continue
		}
		names = append(names, i.Name)
	}
	if len(names) == 0 {
		slog.Warn("No suitable non-loopback, up interfaces found.")
	}
	return names, nil
}

func GetUidFromPid(pid uint32) (uint32, error) {
	statusFilePath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("process %d not found (likely finished): %w", pid, err)
		}
		return 0, fmt.Errorf("failed to read %s: %w", statusFilePath, err)
	}

	lines := strings.SplitN(string(data), "\n", -1)
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uidVal, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					return uint32(uidVal), nil
				} else {
					return 0, fmt.Errorf("failed to parse UID from line '%s': %w", line, err)
				}
			}
		}
	}

	return 0, fmt.Errorf("uid not found in %s", statusFilePath)
}

func _BpfClose(closers ...interface {
	Close() error
}) error {
	var firstErr error
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		if c, ok := closer.(interface{ Close() error }); ok && c != nil {
			if err := c.Close(); err != nil {
				slog.Error("Error closing BPF resource", "error", err)
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}
