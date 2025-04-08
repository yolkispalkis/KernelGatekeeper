// pkg/ebpf/program.go
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io" // Added for io.Closer
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync" // Added for syscall constants like IPPROTO_TCP
	"time"
	"unsafe" // Keep unsafe for nativeEndian init

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yolki/kernelgatekeeper/pkg/config"
)

// Regenerate BPF code wrappers using go generate.
// Includes the connect4 program and ensures shared types are consistent.
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf_connect4 ./bpf/connect4.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf_sockops ./bpf/sockops.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf_skmsg ./bpf/skmsg.c -- -I./bpf

// Constants related to BPF map keys and Cgroup path
const (
	// GlobalStatsMatchedIndex is the key in the global_stats map for connections matched by sockops.
	GlobalStatsMatchedIndex uint32 = 1 // Use uint32 for map keys
	// DefaultCgroupPath is the standard path for the cgroup v2 filesystem root.
	DefaultCgroupPath = "/sys/fs/cgroup"
)

// GlobalStats holds aggregated packet and byte counts from BPF maps.
type GlobalStats struct {
	Packets uint64
	Bytes   uint64 // Note: Bytes are currently NOT collected by the BPF programs.
}

// NotificationTuple holds information about a connection intercepted by BPF,
// sent from the BPF programs to the Go service via the ring buffer.
// **CONFIRMED:** Contains the required fields.
type NotificationTuple struct {
	PidTgid      uint64 // PID/TGID from the BPF program
	SrcIP        net.IP // Source IP address (IPv4) of the connection
	OrigDstIP    net.IP // Original Destination IP address (IPv4) the process tried to connect to
	SrcPort      uint16 // Source port (Host Byte Order) of the connection
	OrigDstPort  uint16 // Original Destination port (Host Byte Order) the process tried to connect to
	Protocol     uint8  // IP protocol (e.g., syscall.IPPROTO_TCP)
	PaddingBytes []byte // Optional: Capture padding from C struct if needed for debugging/validation
}

// BpfConnectionDetailsT corresponds to struct connection_details_t in bpf_shared.h.
// **MODIFIED:** Using the generated type likely prefixed by bpf_connect4.
type BpfConnectionDetailsT = bpf_connect4ConnectionDetailsT

// BpfNotificationTupleT corresponds to struct notification_tuple_t in bpf_shared.h.
// **MODIFIED:** Using the generated type likely prefixed by bpf_connect4 as it includes bpf_shared.h.
// (Even though sockops populates it, bpf2go might use the first encountered definition)
type BpfNotificationTupleT = bpf_connect4NotificationTupleT

// bpfObjects holds references to all loaded eBPF programs and maps from the generated files.
type bpfObjects struct {
	bpf_connect4Objects // Embeds objects from connect4 generation
	bpf_sockopsObjects  // Embeds objects from sockops generation
	bpf_skmsgObjects    // Embeds objects from skmsg generation

	// Direct access fields for commonly used/shared maps/progs for clarity and easier access.
	// These tags must match the SEC(".maps") or SEC("...") names in the C code.
	KernelgatekeeperConnect4 *ebpf.Program `ebpf:"kernelgatekeeper_connect4"`
	KernelgatekeeperSockops  *ebpf.Program `ebpf:"kernelgatekeeper_sockops"`
	KernelgatekeeperSkmsg    *ebpf.Program `ebpf:"kernelgatekeeper_skmsg"`
	ConnectionDetailsMap     *ebpf.Map     `ebpf:"connection_details_map"`
	TargetPorts              *ebpf.Map     `ebpf:"target_ports"`
	ProxySockMap             *ebpf.Map     `ebpf:"proxy_sock_map"`
	NotificationRingbuf      *ebpf.Map     `ebpf:"notification_ringbuf"`
	GlobalStats              *ebpf.Map     `ebpf:"global_stats"`
}

// Close releases all resources associated with the bpfObjects.
func (o *bpfObjects) Close() error {
	closers := []io.Closer{
		&o.bpf_connect4Objects,
		&o.bpf_sockopsObjects,
		&o.bpf_skmsgObjects,
	}
	var errs []error
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			if !errors.Is(err, os.ErrClosed) {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		errorStrings := make([]string, len(errs))
		for i, err := range errs {
			errorStrings[i] = err.Error()
		}
		return errors.New(strings.Join(errorStrings, "; "))
	}
	return nil
}

// BPFManager encapsulates the logic for loading, attaching, and interacting with the eBPF programs.
type BPFManager struct {
	cfg                 *config.EBPFConfig
	objs                bpfObjects
	connect4Link        link.Link
	cgroupLink          link.Link
	skMsgLink           link.Link
	notificationReader  *ringbuf.Reader
	notificationChannel chan<- NotificationTuple
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

// NewBPFManager creates, loads, and attaches the eBPF programs based on the provided configuration.
func NewBPFManager(cfg *config.EBPFConfig, notifChan chan<- NotificationTuple) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "connect4/sockops/skmsg")
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	var objs bpfObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  ebpf.DefaultVerifierLogSize * 10,
		},
	}

	// Load Specs
	specConnect4, err := loadBpf_connect4()
	if err != nil {
		return nil, fmt.Errorf("failed to load connect4 BPF spec: %w", err)
	}
	specSockops, err := loadBpf_sockops()
	if err != nil {
		return nil, fmt.Errorf("failed to load sockops BPF spec: %w", err)
	}
	specSkmsg, err := loadBpf_skmsg()
	if err != nil {
		return nil, fmt.Errorf("failed to load skmsg BPF spec: %w", err)
	}

	// Load connect4 objects
	if err := specConnect4.LoadAndAssign(&objs.bpf_connect4Objects, opts); err != nil {
		handleVerifierError("connect4", err)
		return nil, fmt.Errorf("failed to load eBPF connect4 objects: %w", err)
	}
	slog.Debug("eBPF connect4 objects loaded successfully.")
	// Populate direct fields after first load
	objs.KernelgatekeeperConnect4 = objs.bpf_connect4Objects.KernelgatekeeperConnect4
	objs.ConnectionDetailsMap = objs.bpf_connect4Objects.ConnectionDetailsMap
	objs.TargetPorts = objs.bpf_connect4Objects.TargetPorts
	objs.ProxySockMap = objs.bpf_connect4Objects.ProxySockMap
	objs.NotificationRingbuf = objs.bpf_connect4Objects.NotificationRingbuf
	objs.GlobalStats = objs.bpf_connect4Objects.GlobalStats

	// Load sockops objects, replacing shared maps
	opts.MapReplacements = map[string]*ebpf.Map{
		"connection_details_map": objs.ConnectionDetailsMap,
		"target_ports":           objs.TargetPorts,
		"proxy_sock_map":         objs.ProxySockMap,
		"notification_ringbuf":   objs.NotificationRingbuf,
		"global_stats":           objs.GlobalStats,
	}
	if err := specSockops.LoadAndAssign(&objs.bpf_sockopsObjects, opts); err != nil {
		handleVerifierError("sockops", err)
		objs.bpf_connect4Objects.Close()
		return nil, fmt.Errorf("failed to load eBPF sockops objects: %w", err)
	}
	slog.Debug("eBPF sockops objects loaded successfully.")
	objs.KernelgatekeeperSockops = objs.bpf_sockopsObjects.KernelgatekeeperSockops

	// Load skmsg objects, replacing shared maps
	opts.MapReplacements = map[string]*ebpf.Map{
		"proxy_sock_map": objs.ProxySockMap,
	}
	if err := specSkmsg.LoadAndAssign(&objs.bpf_skmsgObjects, opts); err != nil {
		handleVerifierError("skmsg", err)
		objs.bpf_connect4Objects.Close()
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load eBPF skmsg objects: %w", err)
	}
	slog.Debug("eBPF skmsg objects loaded successfully.")
	objs.KernelgatekeeperSkmsg = objs.bpf_skmsgObjects.KernelgatekeeperSkmsg

	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs,
		notificationChannel: notifChan,
		stopChan:            make(chan struct{}),
	}
	manager.statsCache.lastStatsTime = time.Now()

	// Validate required objects using direct access fields
	if objs.KernelgatekeeperConnect4 == nil ||
		objs.KernelgatekeeperSockops == nil ||
		objs.KernelgatekeeperSkmsg == nil ||
		objs.ConnectionDetailsMap == nil || // Check map references
		objs.TargetPorts == nil ||
		objs.ProxySockMap == nil ||
		objs.NotificationRingbuf == nil ||
		objs.GlobalStats == nil {
		manager.objs.Close()
		return nil, errors.New("one or more required BPF programs or maps failed to load or assign after merging objects")
	}

	// Attach programs
	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close()
		return nil, err
	}

	// Create ring buffer reader
	var ringbufErr error
	manager.notificationReader, ringbufErr = ringbuf.NewReader(objs.NotificationRingbuf) // Use direct field
	if ringbufErr != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", ringbufErr)
	}
	slog.Info("BPF ring buffer reader initialized")

	// Set initial target ports
	if err := manager.UpdateTargetPorts(cfg.TargetPorts); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial target ports in BPF map: %w", err)
	}

	slog.Info("BPF Manager initialized and programs attached successfully.")
	return manager, nil
}

// handleVerifierError remains the same
func handleVerifierError(objType string, err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		slog.Error(fmt.Sprintf("eBPF Verifier error (loading %s objects)", objType), "log", fmt.Sprintf("%+v", verr))
	}
}

// attachPrograms remains the same
func (m *BPFManager) attachPrograms(cgroupPath string) error {
	connect4Prog := m.objs.KernelgatekeeperConnect4
	sockopsProg := m.objs.KernelgatekeeperSockops
	skmsgProg := m.objs.KernelgatekeeperSkmsg
	sockMap := m.objs.ProxySockMap

	if connect4Prog == nil || sockopsProg == nil || skmsgProg == nil || sockMap == nil {
		return errors.New("internal error: one or more required BPF programs or the sockmap are nil during attach phase")
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
	m.connect4Link, linkErr = link.AttachCgroup(link.CgroupOptions{
		Path: cgroupPath, Program: connect4Prog, Attach: ebpf.AttachCGroupInet4Connect,
	})
	if linkErr != nil {
		return fmt.Errorf("failed to attach connect4 program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF connect4 program attached to cgroup", "path", cgroupPath)

	m.cgroupLink, linkErr = link.AttachCgroup(link.CgroupOptions{
		Path: cgroupPath, Program: sockopsProg, Attach: ebpf.AttachCGroupSockOps,
	})
	if linkErr != nil {
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sock_ops program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF sock_ops program attached to cgroup", "path", cgroupPath)

	m.skMsgLink, linkErr = link.AttachRawLink(link.RawLinkOptions{
		Program: skmsgProg, Attach: ebpf.AttachSkMsgVerdict, Target: sockMap.FD(), Flags: 0,
	})
	if linkErr != nil {
		m.cgroupLink.Close()
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sk_msg program to proxy_sock_map (FD %d): %w", sockMap.FD(), linkErr)
	}
	slog.Info("eBPF sk_msg program attached to proxy_sock_map", "map_fd", sockMap.FD())

	return nil
}

// Start remains the same
func (m *BPFManager) Start(ctx context.Context, wg *sync.WaitGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.notificationReader == nil {
		return errors.New("BPF manager not fully initialized (notificationReader is nil), cannot start tasks")
	}
	slog.Info("Starting BPF Manager background tasks (ring buffer reader, stats updater)...")
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("BPF ring buffer reader task started.")
		m.readNotifications(ctx)
		slog.Info("BPF ring buffer reader task stopped.")
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("BPF statistics updater task started.")
		m.statsUpdater(ctx)
		slog.Info("BPF statistics updater task stopped.")
	}()
	return nil
}

// readNotifications reads connection notification events from the BPF ring buffer.
func (m *BPFManager) readNotifications(ctx context.Context) {
	// **MODIFIED:** Use the correct generated type alias
	var bpfTuple BpfNotificationTupleT
	tupleSize := binary.Size(bpfTuple)
	if tupleSize <= 0 {
		slog.Error("Could not determine size of BpfNotificationTupleT (binary.Size failed)", "size", tupleSize)
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
			// ... (error handling remains the same) ...
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
		// **MODIFIED:** Read into the correctly aliased type
		if err := binary.Read(reader, nativeEndian, &bpfTuple); err != nil {
			slog.Error("Failed to decode BPF ring buffer event data into BpfNotificationTupleT", "error", err)
			continue
		}

		// Convert BPF data structure to the application's NotificationTuple struct.
		// Access fields based on the *generated* type `bpfTuple` (e.g., bpf_connect4NotificationTupleT)
		event := NotificationTuple{
			PidTgid:     bpfTuple.PidTgid,
			SrcIP:       ipFromInt(bpfTuple.SrcIp),
			OrigDstIP:   ipFromInt(bpfTuple.OrigDstIp),
			SrcPort:     ntohs(bpfTuple.SrcPort),
			OrigDstPort: ntohs(bpfTuple.OrigDstPort),
			Protocol:    bpfTuple.Protocol,
			// PaddingBytes: append([]byte{}, bpfTuple.Padding[:]...), // Uncomment if needed
		}

		select {
		case m.notificationChannel <- event:
			slog.Debug("Sent BPF connection notification to service processor",
				"pid_tgid", event.PidTgid, "src_ip", event.SrcIP, "src_port", event.SrcPort,
				"orig_dst_ip", event.OrigDstIP, "orig_dst_port", event.OrigDstPort)
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader while sending notification (context cancelled).")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF ring buffer reader while sending notification (stop signal).")
			return
		default:
			slog.Warn("BPF notification channel is full, dropping event.",
				"channel_cap", cap(m.notificationChannel), "channel_len", len(m.notificationChannel),
				"event_dst_port", event.OrigDstPort)
		}
	}
}

// statsUpdater remains the same
func (m *BPFManager) statsUpdater(ctx context.Context) {
	if m.cfg.StatsInterval <= 0 {
		slog.Info("BPF statistics collection disabled (stats_interval <= 0).")
		return
	}
	interval := time.Duration(m.cfg.StatsInterval) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
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

// updateAndLogStats remains the same
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
	slog.Info("eBPF Statistics", slog.Group("matched_conns", "total_conns", matchedCurrent.Packets, "conn_rate_per_sec", fmt.Sprintf("%.2f", matchedRateP)), "interval_sec", fmt.Sprintf("%.2f", duration))
	m.statsCache.matchedConns = matchedCurrent
	m.statsCache.lastMatched = matchedCurrent
	m.statsCache.lastStatsTime = now
	return nil
}

// readGlobalStats reads per-CPU stats from the BPF map and aggregates them.
func (m *BPFManager) readGlobalStats(index uint32) (GlobalStats, error) {
	var aggregate GlobalStats
	// **MODIFIED:** Use the direct access field
	globalStatsMap := m.objs.GlobalStats
	if globalStatsMap == nil {
		return aggregate, errors.New("BPF global_stats map is nil (was it loaded?)")
	}
	// **MODIFIED:** Use the correct generated type alias
	var perCPUValues []bpf_connect4GlobalStatsT
	err := globalStatsMap.Lookup(index, &perCPUValues)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Warn("Stats key not found in BPF global_stats map", "key", index)
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

// UpdateTargetPorts remains the same - already using direct access field m.objs.TargetPorts
func (m *BPFManager) UpdateTargetPorts(ports []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	targetPortsMap := m.objs.TargetPorts // Use direct field
	if targetPortsMap == nil {
		return errors.New("BPF target_ports map not initialized (was it loaded?)")
	}
	// ... (rest of the sync logic remains the same) ...
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
		slog.Warn("Failed to fully iterate existing BPF target_ports map, proceeding with update anyway", "error", err)
		currentPortsMap = make(map[uint16]bool)
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

// GetStats remains the same
func (m *BPFManager) GetStats() (total GlobalStats, matched GlobalStats, err error) {
	m.statsCache.RLock()
	defer m.statsCache.RUnlock()
	total = GlobalStats{}
	matched = m.statsCache.matchedConns
	return total, matched, nil
}

// Close remains the same - already closing all 3 links and objs
func (m *BPFManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
				slog.Error("Error closing BPF ringbuf reader", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("ringbuf close: %w", err)
				}
			}
			m.notificationReader = nil
		}
		if m.skMsgLink != nil {
			slog.Debug("Closing BPF sk_msg link...")
			if err := m.skMsgLink.Close(); err != nil {
				slog.Error("Error closing BPF sk_msg link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("sk_msg link close: %w", err)
				}
			}
			m.skMsgLink = nil
		}
		if m.cgroupLink != nil {
			slog.Debug("Closing BPF cgroup sock_ops link...")
			if err := m.cgroupLink.Close(); err != nil {
				slog.Error("Error closing BPF cgroup sock_ops link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("cgroup sock_ops link close: %w", err)
				}
			}
			m.cgroupLink = nil
		}
		if m.connect4Link != nil {
			slog.Debug("Closing BPF cgroup connect4 link...")
			if err := m.connect4Link.Close(); err != nil {
				slog.Error("Error closing BPF cgroup connect4 link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("cgroup connect4 link close: %w", err)
				}
			}
			m.connect4Link = nil
		}
		slog.Debug("Closing all BPF objects (programs and maps)...")
		if err := m.objs.Close(); err != nil {
			slog.Error("Error closing BPF objects", "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("bpf objects close: %w", err)
			} else {
				firstErr = fmt.Errorf("%w; bpf objects close: %w", firstErr, err)
			}
		}
		slog.Info("BPF Manager closed.")
	})
	return firstErr
}

// --- Utility Functions --- (nativeEndian, init, ipFromInt, ntohs, htons, GetAvailableInterfaces, GetUidFromPid remain the same)
var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = 0xABCD
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
		slog.Debug("Detected native byte order: Little Endian")
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
		slog.Debug("Detected native byte order: Big Endian")
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
	if nativeEndian == binary.LittleEndian {
		return (n >> 8) | (n << 8)
	}
	return n
}
func htons(n uint16) uint16 {
	if nativeEndian == binary.LittleEndian {
		return (n >> 8) | (n << 8)
	}
	return n
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
		if strings.HasPrefix(i.Name, "veth") || strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "lo") {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil || len(addrs) == 0 {
			slog.Debug("Skipping interface with no addresses or error fetching them", "interface", i.Name, "error", err)
			continue
		}
		names = append(names, i.Name)
	}
	if len(names) == 0 {
		slog.Warn("No suitable non-loopback, active network interfaces with IP addresses found.")
	}
	return names, nil
}
func GetUidFromPid(pid uint32) (uint32, error) {
	statusFilePath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("process %d not found (likely exited): %w", pid, err)
		}
		return 0, fmt.Errorf("failed to read process status file %s: %w", statusFilePath, err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uidVal, err := strconv.ParseUint(fields[1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("failed to parse Real UID from status line '%s': %w", line, err)
				}
				return uint32(uidVal), nil
			}
		}
	}
	return 0, fmt.Errorf("uid not found in process status file %s", statusFilePath)
}
