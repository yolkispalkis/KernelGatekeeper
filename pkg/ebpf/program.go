// pkg/ebpf/program.go
package ebpf

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

// Regenerate BPF code wrappers using go generate.
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf_connect4 ./bpf/connect4.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf_sockops ./bpf/sockops.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include" bpf_skmsg ./bpf/skmsg.c -- -I./bpf

// Constants
const (
	GlobalStatsMatchedIndex uint32 = 1
	DefaultCgroupPath              = "/sys/fs/cgroup"
	// Define a local constant for log size if the library one causes issues
	verifierLogSize = 2 * 1024 * 1024 // 2 MiB
)

// GlobalStats definition remains the same
type GlobalStats struct {
	Packets uint64
	Bytes   uint64
}

// NotificationTuple **MUST** match the fields expected by service/main.go AND the C struct notification_tuple_t
type NotificationTuple struct {
	PidTgid     uint64 // <<< ADDED
	SrcIP       net.IP // Source IP address (IPv4)
	OrigDstIP   net.IP // Original Destination IP address (IPv4) // <<< ADDED
	SrcPort     uint16 // Source port (Host Byte Order)
	OrigDstPort uint16 // Original Destination port (Host Byte Order) // <<< ADDED
	Protocol    uint8  // IP protocol (e.g., syscall.IPPROTO_TCP)
	// PaddingBytes []byte // Optional - C struct has padding, but usually not needed in Go unless alignment is critical
}

// BpfConnectionDetailsT corresponds to struct connection_details_t. Use connect4's generated type.
type BpfConnectionDetailsT = bpf_connect4ConnectionDetailsT // Corrected Alias

// BpfNotificationTupleT corresponds to struct notification_tuple_t.
// Define it manually as bpf2go didn't seem to generate it explicitly.
// **CRITICAL:** Field names and types MUST match the C struct exactly.
type BpfNotificationTupleT struct {
	PidTgid     uint64
	SrcIp       uint32 // Network Byte Order IP
	OrigDstIp   uint32 // Network Byte Order IP
	SrcPort     uint16 // Network Byte Order Port
	OrigDstPort uint16 // Network Byte Order Port
	Protocol    uint8
	Padding     [5]uint8 // Match C struct padding
	// _           [X]byte // Add explicit Go padding if needed for binary.Read alignment
}

// Use the generated type for global stats map values
type BpfGlobalStatsT = bpf_connect4GlobalStatsT // Corrected Alias

// bpfObjects holds references to all loaded eBPF programs and maps.
type bpfObjects struct {
	bpf_connect4Objects
	bpf_sockopsObjects
	bpf_skmsgObjects

	// Direct access fields (Redundant if included in embedded objects, but explicit for clarity)
	KernelgatekeeperConnect4 *ebpf.Program `ebpf:"kernelgatekeeper_connect4"`
	KernelgatekeeperSockops  *ebpf.Program `ebpf:"kernelgatekeeper_sockops"`
	KernelgatekeeperSkmsg    *ebpf.Program `ebpf:"kernelgatekeeper_skmsg"`
	ConnectionDetailsMap     *ebpf.Map     `ebpf:"connection_details_map"` // <<< Corrected Name (assuming it's here)
	TargetPorts              *ebpf.Map     `ebpf:"target_ports"`
	ProxySockMap             *ebpf.Map     `ebpf:"proxy_sock_map"`
	NotificationRingbuf      *ebpf.Map     `ebpf:"notification_ringbuf"`
	GlobalStats              *ebpf.Map     `ebpf:"global_stats"`
}

// Close implementation
func (o *bpfObjects) Close() error {
	// Combine closers from all embedded objects
	closers := []io.Closer{
		&o.bpf_connect4Objects,
		&o.bpf_sockopsObjects,
		&o.bpf_skmsgObjects,
	}
	var errs []error
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		// Use type assertion to check if already closed, if the object supports it.
		// Not all ebpf objects might implement this.
		// if c, ok := closer.(interface{ IsClosed() bool }); ok && c.IsClosed() {
		//  continue
		// }

		if err := closer.Close(); err != nil {
			// Ignore error if it signifies already closed (os.ErrClosed is common)
			if !errors.Is(err, os.ErrClosed) { // <<< REMOVED ebpf.ErrClosed check
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		// Aggregate errors more robustly
		finalErr := errors.New("errors closing BPF objects")
		for _, err := range errs {
			finalErr = fmt.Errorf("%w; %w", finalErr, err) // Chain errors
		}
		return finalErr
	}
	return nil
}

// BPFManager definition remains the same
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
		matchedConns, lastMatched GlobalStats
		lastStatsTime             time.Time
	}
	mu sync.Mutex
}

// NewBPFManager
func NewBPFManager(cfg *config.EBPFConfig, notifChan chan<- NotificationTuple) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "connect4/sockops/skmsg")
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	var objs bpfObjects
	// Increase verifier log size for better debugging
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction, // Or LogLevelBranch, LogLevelStats
			LogSize:  verifierLogSize,          // <<< USE LOCAL CONSTANT or a literal value
		},
	}

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

	// Load connect4 first
	if err := specConnect4.LoadAndAssign(&objs.bpf_connect4Objects, opts); err != nil {
		handleVerifierError("connect4", err)
		return nil, fmt.Errorf("failed to load eBPF connect4 objects: %w", err)
	}
	slog.Debug("eBPF connect4 objects loaded successfully.")
	// Explicitly assign direct access fields from the first loaded object where they are defined
	objs.KernelgatekeeperConnect4 = objs.bpf_connect4Objects.KernelgatekeeperConnect4
	objs.ConnectionDetailsMap = objs.bpf_connect4Objects.ConnectionDetailsMap // <<< Assign the actual map object
	objs.TargetPorts = objs.bpf_connect4Objects.TargetPorts
	objs.ProxySockMap = objs.bpf_connect4Objects.ProxySockMap
	objs.NotificationRingbuf = objs.bpf_connect4Objects.NotificationRingbuf
	objs.GlobalStats = objs.bpf_connect4Objects.GlobalStats

	// Load sockops, replacing maps with the ones already loaded from connect4
	opts.MapReplacements = map[string]*ebpf.Map{
		// Ensure ALL maps shared between C files are listed here using the names from C
		"connection_details_map": objs.ConnectionDetailsMap,
		"target_ports":           objs.TargetPorts,
		"proxy_sock_map":         objs.ProxySockMap,
		"notification_ringbuf":   objs.NotificationRingbuf,
		"global_stats":           objs.GlobalStats,
	}
	if err := specSockops.LoadAndAssign(&objs.bpf_sockopsObjects, opts); err != nil {
		handleVerifierError("sockops", err)
		objs.bpf_connect4Objects.Close() // Clean up previously loaded objects
		return nil, fmt.Errorf("failed to load eBPF sockops objects: %w", err)
	}
	slog.Debug("eBPF sockops objects loaded successfully.")
	objs.KernelgatekeeperSockops = objs.bpf_sockopsObjects.KernelgatekeeperSockops // Assign sockops program

	// Load skmsg, replacing the shared sockmap
	opts.MapReplacements = map[string]*ebpf.Map{
		"proxy_sock_map": objs.ProxySockMap, // Only replace the map used by skmsg
	}
	if err := specSkmsg.LoadAndAssign(&objs.bpf_skmsgObjects, opts); err != nil {
		handleVerifierError("skmsg", err)
		objs.bpf_connect4Objects.Close() // Clean up all previous on failure
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load eBPF skmsg objects: %w", err)
	}
	slog.Debug("eBPF skmsg objects loaded successfully.")
	objs.KernelgatekeeperSkmsg = objs.bpf_skmsgObjects.KernelgatekeeperSkmsg // Assign skmsg program

	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs,
		notificationChannel: notifChan,
		stopChan:            make(chan struct{}),
	}
	manager.statsCache.lastStatsTime = time.Now()

	// Verify essential objects are not nil after loading all specs
	if objs.KernelgatekeeperConnect4 == nil || objs.KernelgatekeeperSockops == nil || objs.KernelgatekeeperSkmsg == nil ||
		objs.ConnectionDetailsMap == nil || objs.TargetPorts == nil || objs.ProxySockMap == nil ||
		objs.NotificationRingbuf == nil || objs.GlobalStats == nil {
		manager.objs.Close() // Use the consolidated close method
		return nil, errors.New("one or more required BPF programs or maps failed to load or assign after merging objects")
	}

	// Attach programs
	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close() // Use the consolidated close method
		return nil, err
	}

	// Create ring buffer reader AFTER programs are attached and maps are loaded
	var ringbufErr error
	manager.notificationReader, ringbufErr = ringbuf.NewReader(objs.NotificationRingbuf)
	if ringbufErr != nil {
		manager.Close() // Use the consolidated close method
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", ringbufErr)
	}
	slog.Info("BPF ring buffer reader initialized")

	// Set initial target ports
	if err := manager.UpdateTargetPorts(cfg.TargetPorts); err != nil {
		manager.Close() // Use the consolidated close method
		return nil, fmt.Errorf("failed to set initial target ports in BPF map: %w", err)
	}

	slog.Info("BPF Manager initialized and programs attached successfully.")
	return manager, nil
}

// --- Rest of the file (handleVerifierError, attachPrograms, Start, readNotifications, etc.) remains unchanged from the previous corrected version ---
// handleVerifierError remains the same
func handleVerifierError(objType string, err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		slog.Error(fmt.Sprintf("eBPF Verifier error (loading %s objects)", objType), "log", fmt.Sprintf("%+v", verr))
		// Optionally print the full verifier log if needed for deeper debugging:
		// fmt.Printf("Verifier log for %s:\n%s\n", objType, strings.Join(verr.Log, "\n"))
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
	m.connect4Link, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: connect4Prog, Attach: ebpf.AttachCGroupInet4Connect})
	if linkErr != nil {
		return fmt.Errorf("failed to attach connect4 program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF connect4 program attached to cgroup", "path", cgroupPath)
	m.cgroupLink, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: sockopsProg, Attach: ebpf.AttachCGroupSockOps})
	if linkErr != nil {
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sock_ops program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF sock_ops program attached to cgroup", "path", cgroupPath)
	m.skMsgLink, linkErr = link.AttachRawLink(link.RawLinkOptions{Program: skmsgProg, Attach: ebpf.AttachSkMsgVerdict, Target: sockMap.FD(), Flags: 0})
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
	// **MODIFIED:** Use the manually defined Go type `BpfNotificationTupleT`
	var bpfTuple BpfNotificationTupleT
	// Use unsafe.Sizeof for C-like struct size determination if binary.Size fails or is inaccurate
	tupleSize := int(unsafe.Sizeof(bpfTuple))
	if tupleSize <= 0 {
		// Fallback or error if unsafe.Sizeof also fails
		bsize := binary.Size(bpfTuple)
		if bsize <= 0 {
			slog.Error("Could not determine size of BpfNotificationTupleT (binary.Size and unsafe.Sizeof failed)", "size", bsize)
			return
		}
		tupleSize = bsize

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
			// Avoid busy-looping on persistent errors
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

		// Check if the received data is at least the size of our struct
		if len(record.RawSample) < tupleSize {
			slog.Warn("Received BPF ring buffer event with unexpected size, skipping.", "expected_min", tupleSize, "received", len(record.RawSample))
			continue
		}

		// Use bytes.NewReader for efficient reading
		reader := bytes.NewReader(record.RawSample)
		// **MODIFIED:** Read into the correctly defined type `BpfNotificationTupleT`
		if err := binary.Read(reader, nativeEndian, &bpfTuple); err != nil {
			slog.Error("Failed to decode BPF ring buffer event data into BpfNotificationTupleT", "error", err)
			continue
		}

		// Convert BPF data structure to the application's NotificationTuple struct.
		// Access fields based on the manually defined Go type `BpfNotificationTupleT`
		event := NotificationTuple{
			PidTgid:     bpfTuple.PidTgid,
			SrcIP:       ipFromInt(bpfTuple.SrcIp),     // Use correct field name SrcIp
			OrigDstIP:   ipFromInt(bpfTuple.OrigDstIp), // Use correct field name OrigDstIp
			SrcPort:     ntohs(bpfTuple.SrcPort),       // Use correct field name SrcPort
			OrigDstPort: ntohs(bpfTuple.OrigDstPort),   // Use correct field name OrigDstPort
			Protocol:    bpfTuple.Protocol,
		}

		// Send the decoded event to the processing channel
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
			// Consider using a non-blocking send with a warning if the channel buffer is important
			slog.Warn("BPF notification channel is full, dropping event.", "channel_cap", cap(m.notificationChannel), "channel_len", len(m.notificationChannel), "event_dst_port", event.OrigDstPort)
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
	if interval <= 0 { // Ensure positive interval if config is invalid
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

// updateAndLogStats remains the same
func (m *BPFManager) updateAndLogStats() error {
	m.statsCache.Lock()
	defer m.statsCache.Unlock()
	now := time.Now()
	duration := now.Sub(m.statsCache.lastStatsTime).Seconds()
	// Avoid division by zero or tiny intervals causing huge rates
	if duration < 0.1 {
		slog.Debug("Skipping stats update, interval too short", "duration_sec", duration)
		return nil
	}
	// Read current stats
	matchedCurrent, err := m.readGlobalStats(GlobalStatsMatchedIndex)
	if err != nil {
		return fmt.Errorf("failed to read matched BPF stats: %w", err)
	}
	// Calculate rate
	matchedRateP := 0.0
	// Handle counter reset or wrap-around gracefully
	deltaPackets := int64(matchedCurrent.Packets - m.statsCache.lastMatched.Packets)
	if deltaPackets < 0 {
		slog.Warn("BPF matched connection counter appeared to wrap or reset", "last", m.statsCache.lastMatched.Packets, "current", matchedCurrent.Packets)
		// Assume the current value is the count since the last reading in case of reset
		deltaPackets = int64(matchedCurrent.Packets)
	}
	// Calculate rate safely
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

	// Update cache - only need to update lastMatched now
	m.statsCache.lastMatched = matchedCurrent
	m.statsCache.lastStatsTime = now
	return nil
}

// readGlobalStats reads per-CPU stats from the BPF map and aggregates them.
func (m *BPFManager) readGlobalStats(index uint32) (GlobalStats, error) {
	var aggregate GlobalStats
	globalStatsMap := m.objs.GlobalStats // Use direct access field
	if globalStatsMap == nil {
		return aggregate, errors.New("BPF global_stats map is nil (was it loaded?)")
	}

	// **MODIFIED:** Use the correct generated type alias `BpfGlobalStatsT`
	var perCPUValues []BpfGlobalStatsT
	err := globalStatsMap.Lookup(index, &perCPUValues)
	if err != nil {
		// It's normal for the key not to exist initially if no stats have been recorded
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Debug("Stats key not found in BPF global_stats map, returning zero stats.", "key", index)
			return aggregate, nil // Return zero stats, not an error
		}
		return aggregate, fmt.Errorf("failed lookup stats key %d in BPF global_stats map: %w", index, err)
	}

	// Aggregate values from all CPUs
	for _, cpuStat := range perCPUValues {
		aggregate.Packets += cpuStat.Packets
		aggregate.Bytes += cpuStat.Bytes
	}
	return aggregate, nil
}

// GetStats returns the cached statistics.
// Renamed the first return value to avoid confusion with total packets processed by the NIC.
func (m *BPFManager) GetStats() (totalIgnored GlobalStats, matched GlobalStats, err error) {
	m.statsCache.RLock()
	defer m.statsCache.RUnlock()
	// totalIgnored = m.statsCache.totalConns // If you had a separate counter for total processed
	totalIgnored = GlobalStats{}       // No separate total counter currently
	matched = m.statsCache.lastMatched // Return the last read value
	return totalIgnored, matched, nil
}

// UpdateTargetPorts remains the same
func (m *BPFManager) UpdateTargetPorts(ports []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	targetPortsMap := m.objs.TargetPorts
	if targetPortsMap == nil {
		return errors.New("BPF target_ports map not initialized (was it loaded?)")
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
		slog.Warn("Failed to fully iterate existing BPF target_ports map, proceeding with update anyway", "error", err)
		// Clear the map if iteration failed, ensures we try to add all desired ports
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
	// Delete ports no longer desired
	for portKey := range currentPortsMap {
		if !desiredPortsSet[portKey] {
			// Use DeleteStrict for potentially better error handling if needed
			if err := targetPortsMap.Delete(portKey); err != nil {
				// Don't error out if key already gone, could happen with concurrent updates or map clears
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					slog.Error("Failed to delete target port from BPF map", "port", portKey, "error", err)
					// Maybe return error here if deletes are critical?
				}
			} else {
				slog.Debug("Deleted target port from BPF map", "port", portKey)
				deletedCount++
			}
		}
	}
	addedCount := 0
	var mapValueOne uint8 = 1
	// Add newly desired ports
	for portKey := range desiredPortsSet {
		if !currentPortsMap[portKey] {
			// Use Put/Update instead of Insert if overwriting is acceptable/desired
			if err := targetPortsMap.Put(portKey, mapValueOne); err != nil {
				slog.Error("Failed to add target port to BPF map", "port", portKey, "error", err)
				// Maybe return error here if adds are critical?
			} else {
				slog.Debug("Added target port to BPF map", "port", portKey)
				addedCount++
			}
		}
	}
	// Log summary if changes were made
	if addedCount > 0 || deletedCount > 0 {
		slog.Info("BPF target ports map updated", "added", addedCount, "deleted", deletedCount, "final_list", validNewPortsList)
	} else {
		slog.Debug("BPF target ports map remains unchanged", "current_list", validNewPortsList)
	}
	// Update the cached config in the manager
	if m.cfg != nil {
		m.cfg.TargetPorts = validNewPortsList
	}
	return nil
}

// Close remains the same
func (m *BPFManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	m.stopOnce.Do(func() {
		slog.Info("Closing BPF Manager...")
		// Signal background goroutines to stop
		select {
		case <-m.stopChan: // Already closed
		default:
			close(m.stopChan)
		}

		// Close reader first to stop processing events
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

		// Detach links
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

		// Close the collection objects (programs and maps)
		slog.Debug("Closing all BPF objects (programs and maps)...")
		if err := m.objs.Close(); err != nil { // Use the consolidated Close method
			slog.Error("Error closing BPF objects", "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("bpf objects close: %w", err)
			} else {
				firstErr = fmt.Errorf("%w; bpf objects close: %w", firstErr, err) // Chain errors
			}
		}
		slog.Info("BPF Manager closed.")
	})
	return firstErr
}

// --- Utility Functions --- (remain the same)
var nativeEndian binary.ByteOrder

func init() {
	// Determine native byte order for conversions (like ntohs)
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

// ipFromInt converts a uint32 IP address (Network Byte Order) to net.IP.
func ipFromInt(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	// Use BigEndian here because network byte order is big endian
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip
}

// ntohs converts a uint16 from network byte order (BigEndian) to host byte order.
func ntohs(n uint16) uint16 {
	// If host is LittleEndian, swap bytes. Otherwise, it's already correct.
	if nativeEndian == binary.LittleEndian {
		return (n >> 8) | (n << 8)
	}
	return n
}

// htons converts a uint16 from host byte order to network byte order (BigEndian).
func htons(n uint16) uint16 {
	// If host is LittleEndian, swap bytes. Otherwise, it's already correct.
	if nativeEndian == binary.LittleEndian {
		return (n >> 8) | (n << 8)
	}
	return n
}

// GetAvailableInterfaces lists non-loopback, non-virtual, active interfaces.
func GetAvailableInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	var names []string
	for _, i := range interfaces {
		// Skip down, loopback, point-to-point interfaces
		if (i.Flags&net.FlagUp == 0) || (i.Flags&net.FlagLoopback != 0) || (i.Flags&net.FlagPointToPoint != 0) {
			continue
		}
		// Skip virtual interfaces (like veth, docker, bridge, etc.)
		// Add more patterns if needed for your environment (e.g., flannel, calico, weave)
		if strings.HasPrefix(i.Name, "veth") || strings.HasPrefix(i.Name, "docker") ||
			strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "lo") ||
			strings.HasPrefix(i.Name, "virbr") || strings.HasPrefix(i.Name, "vnet") ||
			strings.HasPrefix(i.Name, "cni") || strings.HasPrefix(i.Name, "flannel") ||
			strings.HasPrefix(i.Name, "cali") || strings.HasPrefix(i.Name, "weave") {
			continue
		}
		// Check if it has at least one usable IP address (optional, but good practice)
		addrs, err := i.Addrs()
		if err != nil || len(addrs) == 0 {
			slog.Debug("Skipping interface with no addresses or error fetching them", "interface", i.Name, "error", err)
			continue
		}
		// Check if any address is a valid global unicast IP (IPv4 or IPv6)
		hasValidIP := false
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsInterfaceLocalMulticast() {
				hasValidIP = true
				break
			}
		}
		if !hasValidIP {
			slog.Debug("Skipping interface with no valid global IP address", "interface", i.Name)
			continue
		}

		names = append(names, i.Name)
	}
	if len(names) == 0 {
		slog.Warn("No suitable non-loopback, active network interfaces with global IP addresses found.")
		// Return empty list, not an error
	}
	return names, nil
}

// GetUidFromPid extracts the real UID of a process from its /proc status file.
func GetUidFromPid(pid uint32) (uint32, error) {
	statusFilePath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusFilePath)
	if err != nil {
		// Process might have exited between BPF hook and this lookup
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("process %d not found (likely exited): %w", pid, err)
		}
		return 0, fmt.Errorf("failed to read process status file %s: %w", statusFilePath, err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Look for the Uid line, which contains: Real, Effective, Saved Set, Filesystem UIDs
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			// The second field is the Real UID
			if len(fields) >= 2 {
				uidVal, err := strconv.ParseUint(fields[1], 10, 32) // Parse Real UID
				if err != nil {
					return 0, fmt.Errorf("failed to parse Real UID from status line '%s': %w", line, err)
				}
				return uint32(uidVal), nil
			}
		}
	}
	// Should not happen if status file is valid
	return 0, fmt.Errorf("uid not found in process status file %s", statusFilePath)
}
