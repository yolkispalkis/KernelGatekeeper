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
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yolki/kernelgatekeeper/pkg/config"
)

//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf ./bpf/sockops.c ./bpf/skmsg.c -- -I./bpf

const (
	GlobalStatsTotalIndex   = 0
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

// BpfClientProcessInfoT структура для карты процессов клиентов
type BpfClientProcessInfoT struct {
	PidTgid uint64
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

	objs := bpfObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
	}

	if err := loadBpfObjects(&objs, opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			slog.Error("eBPF Verifier error", "log", fmt.Sprintf("%+v", verr))
		}
		return nil, fmt.Errorf("failed to load eBPF objects (run 'go generate ./pkg/ebpf/...'): %w", err)
	}
	slog.Debug("eBPF objects loaded successfully")

	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs,
		notificationChannel: notifChan,
		stopChan:            make(chan struct{}),
	}
	manager.statsCache.lastStatsTime = time.Now()

	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close()
		return nil, err
	}

	var err error

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

func (m *BPFManager) attachPrograms(cgroupPath string) error {

	if m.objs.KernelgatekeeperSockops == nil {
		return errors.New("sock_ops program not found in BPF objects (run 'go generate')")
	}
	if m.objs.KernelgatekeeperSkmsg == nil {
		return errors.New("sk_msg program not found in BPF objects (run 'go generate')")
	}
	if m.objs.ProxySockMap == nil {
		return errors.New("proxy_sock_map not found in BPF objects (run 'go generate')")
	}

	if fi, err := os.Stat(cgroupPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("cgroup v2 path %s does not exist", cgroupPath)
		}
		return fmt.Errorf("failed to stat cgroup v2 path %s: %w", cgroupPath, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("cgroup v2 path %s is not a directory", cgroupPath)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: m.objs.KernelgatekeeperSockops,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return fmt.Errorf("attach sock_ops to cgroup %s failed: %w", cgroupPath, err)
	}
	m.cgroupLink = l
	slog.Info("sock_ops program attached to cgroup", "path", cgroupPath)

	skLink, err := link.AttachRawLink(link.RawLinkOptions{
		Program: m.objs.KernelgatekeeperSkmsg,
		Attach:  ebpf.AttachSkMsgVerdict,
		Target:  m.objs.ProxySockMap.FD(),
		Flags:   0,
	})
	if err != nil {

		if m.cgroupLink != nil {
			m.cgroupLink.Close()
		}
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

	var tupleSize = binary.Size(bpfConnectionTupleT{})
	if tupleSize < 0 {
		slog.Error("Could not determine size of bpfConnectionTupleT (run 'go generate')")
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

			var bpfTuple bpfConnectionTupleT

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

	var perCPUValues []bpfGlobalStatsT
	if m.objs.GlobalStats == nil {
		return agg, errors.New("global_stats map is nil (run 'go generate')")
	}

	if err := m.objs.GlobalStats.Lookup(index, &perCPUValues); err != nil {

		if errors.Is(err, ebpf.ErrKeyNotExist) && index == GlobalStatsTotalIndex {
			slog.Debug("Total stats index not found in map, skipping", "index", index)
			return agg, nil
		}
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
		currentPorts[mapKey] = true
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

				slog.Error("Failed to delete target port from BPF map", "port", port, "error", err)
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

func (m *BPFManager) RegisterClientProcess(uid uint32, info BpfClientProcessInfoT) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objs.ProcessMap == nil {
		return errors.New("process_map not initialized (run 'go generate')")
	}
	slog.Info("Registering client UID in BPF process map", "uid", uid, "pid_tgid", info.PidTgid)
	if err := m.objs.ProcessMap.Put(uid, info); err != nil {
		return fmt.Errorf("failed to update process_map for uid %d: %w", uid, err)
	}
	return nil
}

func (m *BPFManager) UnregisterClientProcess(uid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objs.ProcessMap == nil {

		slog.Warn("process_map not initialized or already closed during unregister")
		return nil
	}
	slog.Info("Unregistering client UID from BPF process map", "uid", uid)
	if err := m.objs.ProcessMap.Delete(uid); err != nil {

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Warn("Attempted to unregister non-existent UID from BPF map", "uid", uid)
			return nil
		}
		return fmt.Errorf("failed to delete from process_map for uid %d: %w", uid, err)
	}
	return nil
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
			if err := m.notificationReader.Close(); err != nil {
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
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return nativeEndian.Uint16(b)
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

		names = append(names, i.Name)
	}
	if len(names) == 0 {
		slog.Warn("No suitable non-loopback, up interfaces found.")

	}
	return names, nil
}
