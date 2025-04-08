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
	"unsafe" // Keep unsafe for nativeEndian init

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yolki/kernelgatekeeper/pkg/config"
)

// Regenerate BPF code wrappers using go generate
// Includes the new connect4 program and ensures shared types are consistent.
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

// GlobalStats holds aggregated packet and byte counts.
type GlobalStats struct {
	Packets uint64
	Bytes   uint64 // Note: Bytes are currently NOT collected by the BPF programs.
}

// NotificationTuple holds information about a connection intercepted by BPF.
// Matches the layout of struct notification_tuple_t in bpf_shared.h.
type NotificationTuple struct {
	PidTgid      uint64 // PID/TGID from the BPF program
	SrcIP        net.IP // Source IP address (IPv4)
	OrigDstIP    net.IP // Original Destination IP address (IPv4)
	SrcPort      uint16 // Source port (Host Byte Order)
	OrigDstPort  uint16 // Original Destination port (Host Byte Order)
	Protocol     uint8  // IP protocol (e.g., syscall.IPPROTO_TCP)
	PaddingBytes []byte // Capture any padding explicitly (size matches C struct)
}

// BpfConnectionDetailsT corresponds to struct connection_details_t in bpf_shared.h
// Using the generated type (assuming it's consistent across bpf_connect4/bpf_sockops after generation)
type BpfConnectionDetailsT = bpf_connect4ConnectionDetailsT // Or bpf_sockopsConnectionDetailsT if name differs

// BpfNotificationTupleT corresponds to struct notification_tuple_t in bpf_shared.h
// Using generated type from sockops (where it's populated for the ringbuf)
type BpfNotificationTupleT = bpf_sockopsNotificationTupleT

// bpfObjects holds references to the loaded eBPF programs and maps from all generated files.
type bpfObjects struct {
	bpf_connect4Objects
	bpf_sockopsObjects
	bpf_skmsgObjects
	// Direct access fields for commonly used/shared maps/progs for clarity
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
	// Create a slice of closers from the embedded objects
	closers := []io.Closer{
		&o.bpf_connect4Objects,
		&o.bpf_sockopsObjects,
		&o.bpf_skmsgObjects,
	}

	var errs []error
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		// Combine multiple errors if necessary
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
	objs                bpfObjects // Holds all loaded BPF objects
	connect4Link        link.Link  // Link for connect4 program
	cgroupLink          link.Link  // Link for the sockops program attached to cgroup
	skMsgLink           link.Link  // Link for the sk_msg program attached to the sockmap
	notificationReader  *ringbuf.Reader
	notificationChannel chan<- NotificationTuple // Channel to send notifications to the service
	stopOnce            sync.Once                // Ensures Close actions run only once
	stopChan            chan struct{}            // Signals background goroutines to stop
	statsCache          struct {                 // Cached statistics
		sync.RWMutex
		matchedConns  GlobalStats
		lastMatched   GlobalStats
		lastStatsTime time.Time
	}
	mu sync.Mutex // Protects manager state during init and updates
}

// NewBPFManager creates, loads, and attaches the eBPF programs.
func NewBPFManager(cfg *config.EBPFConfig, notifChan chan<- NotificationTuple) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "connect4/sockops/skmsg")

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	// --- Load eBPF programs and maps ---
	var objs bpfObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin maps if needed for debugging or external access
			// PinPath: "/sys/fs/bpf/kernelgatekeeper",
		},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,         // LogLevelInstruction or LogLevelBranch for more verbosity
			LogSize:  ebpf.DefaultVerifierLogSize * 10, // Increase log buffer size significantly
		},
	}

	// Strategy: Load specs first, then load objects sequentially, reusing maps.
	// 1. Load Specs
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

	// 2. Load connect4 objects (contains initial map definitions)
	if err := specConnect4.LoadAndAssign(&objs.bpf_connect4Objects, opts); err != nil {
		handleVerifierError("connect4", err)
		return nil, fmt.Errorf("failed to load eBPF connect4 objects: %w", err)
	}
	slog.Debug("eBPF connect4 objects loaded successfully.")
	// Populate direct access fields after loading the first set
	objs.KernelgatekeeperConnect4 = objs.bpf_connect4Objects.KernelgatekeeperConnect4
	objs.ConnectionDetailsMap = objs.bpf_connect4Objects.ConnectionDetailsMap
	objs.TargetPorts = objs.bpf_connect4Objects.TargetPorts
	objs.ProxySockMap = objs.bpf_connect4Objects.ProxySockMap
	objs.NotificationRingbuf = objs.bpf_connect4Objects.NotificationRingbuf
	objs.GlobalStats = objs.bpf_connect4Objects.GlobalStats

	// 3. Load sockops objects, replacing shared maps
	opts.MapReplacements = map[string]*ebpf.Map{
		"connection_details_map": objs.ConnectionDetailsMap, // Reuse maps via direct fields
		"target_ports":           objs.TargetPorts,
		"proxy_sock_map":         objs.ProxySockMap,
		"notification_ringbuf":   objs.NotificationRingbuf,
		"global_stats":           objs.GlobalStats,
	}
	if err := specSockops.LoadAndAssign(&objs.bpf_sockopsObjects, opts); err != nil {
		handleVerifierError("sockops", err)
		objs.bpf_connect4Objects.Close() // Clean up already loaded
		return nil, fmt.Errorf("failed to load eBPF sockops objects: %w", err)
	}
	slog.Debug("eBPF sockops objects loaded successfully.")
	objs.KernelgatekeeperSockops = objs.bpf_sockopsObjects.KernelgatekeeperSockops // Populate direct access field

	// 4. Load skmsg objects, replacing the sockmap
	// Rebuild MapReplacements specifically for skmsg if needed (here just sockmap)
	opts.MapReplacements = map[string]*ebpf.Map{
		"proxy_sock_map": objs.ProxySockMap, // skmsg only needs the sockmap
		// Include others if skmsg.c were to reference them directly
	}
	if err := specSkmsg.LoadAndAssign(&objs.bpf_skmsgObjects, opts); err != nil {
		handleVerifierError("skmsg", err)
		objs.bpf_connect4Objects.Close() // Clean up all previously loaded
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load eBPF skmsg objects: %w", err)
	}
	slog.Debug("eBPF skmsg objects loaded successfully.")
	objs.KernelgatekeeperSkmsg = objs.bpf_skmsgObjects.KernelgatekeeperSkmsg // Populate direct access field

	// --- Initialization and Attachment ---
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
		objs.ConnectionDetailsMap == nil ||
		objs.TargetPorts == nil ||
		objs.ProxySockMap == nil ||
		objs.NotificationRingbuf == nil ||
		objs.GlobalStats == nil { // Add checks for all required maps/progs
		manager.objs.Close() // Use the combined closer
		return nil, errors.New("one or more required BPF programs or maps failed to load after merging objects")
	}

	// Attach the loaded programs
	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close()
		return nil, err // Error already contains context
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

// handleVerifierError checks if an error is a VerifierError and logs its details.
func handleVerifierError(objType string, err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		// Print detailed verifier error log
		slog.Error(fmt.Sprintf("eBPF Verifier error (loading %s objects)", objType), "log", fmt.Sprintf("%+v", verr))
	}
}

// attachPrograms attaches connect4, sockops, and sk_msg programs to the cgroup/sockmap.
func (m *BPFManager) attachPrograms(cgroupPath string) error {
	// Use direct access fields for programs and maps
	connect4Prog := m.objs.KernelgatekeeperConnect4
	sockopsProg := m.objs.KernelgatekeeperSockops
	skmsgProg := m.objs.KernelgatekeeperSkmsg
	sockMap := m.objs.ProxySockMap

	if connect4Prog == nil || sockopsProg == nil || skmsgProg == nil || sockMap == nil {
		return errors.New("one or more BPF programs or the sockmap are nil during attach phase")
	}

	// Check cgroup path existence and type
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

	// --- Attach Programs ---
	var linkErr error

	// 1. Attach connect4 program
	m.connect4Link, linkErr = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: connect4Prog,
		Attach:  ebpf.AttachCGroupInet4Connect, // Hook for IPv4 connect syscall
	})
	if linkErr != nil {
		return fmt.Errorf("failed to attach connect4 program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF connect4 program attached to cgroup", "path", cgroupPath)

	// 2. Attach sock_ops program
	m.cgroupLink, linkErr = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: sockopsProg,
		Attach:  ebpf.AttachCGroupSockOps, // Hook for various socket operations
	})
	if linkErr != nil {
		m.connect4Link.Close() // Clean up previous link on failure
		return fmt.Errorf("failed to attach sock_ops program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF sock_ops program attached to cgroup", "path", cgroupPath)

	// 3. Attach sk_msg program to the sockmap
	m.skMsgLink, linkErr = link.AttachRawLink(link.RawLinkOptions{
		Program: skmsgProg,
		Attach:  ebpf.AttachSkMsgVerdict, // Hook for redirecting messages via sockmap
		Target:  sockMap.FD(),            // Target is the sockmap file descriptor
		Flags:   0,                       // Use 0 for modern kernels
	})
	if linkErr != nil {
		m.cgroupLink.Close() // Clean up previous links on failure
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sk_msg program to proxy_sock_map (FD %d): %w", sockMap.FD(), linkErr)
	}
	slog.Info("eBPF sk_msg program attached to proxy_sock_map", "map_fd", sockMap.FD())

	return nil // All attachments successful
}

// Start launches the background goroutines for reading notifications and updating stats.
func (m *BPFManager) Start(ctx context.Context, wg *sync.WaitGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.notificationReader == nil {
		return errors.New("BPF manager not fully initialized, cannot start tasks")
	}

	slog.Info("Starting BPF Manager background tasks (ring buffer reader, stats updater)...")

	// Start Ring Buffer Reader Goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("BPF ring buffer reader task started.")
		m.readNotifications(ctx)
		slog.Info("BPF ring buffer reader task stopped.")
	}()

	// Start Statistics Updater Goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("BPF statistics updater task started.")
		m.statsUpdater(ctx)
		slog.Info("BPF statistics updater task stopped.")
	}()

	return nil
}

// readNotifications continuously reads connection notification events from the BPF ring buffer.
// UPDATED to decode the BpfNotificationTupleT structure.
func (m *BPFManager) readNotifications(ctx context.Context) {
	// Use the generated Go type corresponding to struct notification_tuple_t
	var bpfTuple BpfNotificationTupleT
	tupleSize := binary.Size(bpfTuple)
	if tupleSize <= 0 { // Use <= 0 for safety, Size returns -1 on error
		slog.Error("Could not determine size of BpfNotificationTupleT (binary.Size failed)", "size", tupleSize)
		return // Cannot proceed without knowing the size
	}
	slog.Debug("Expected ringbuf record size", "size", tupleSize)

	for {
		// Check for cancellation signals *before* blocking read
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader due to context cancellation.")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF ring buffer reader due to stop signal.")
			return
		default: // Continue if no signal received
		}

		// Read the next record from the ring buffer
		record, err := m.notificationReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				slog.Info("BPF ring buffer reader closed.")
				return // Exit cleanly if reader is closed
			}
			if errors.Is(err, context.Canceled) { // Check if context was cancelled during read
				slog.Info("BPF ring buffer reading cancelled by context.")
				return
			}
			// Log other errors and potentially add a small delay to avoid spamming
			slog.Error("Error reading from BPF ring buffer", "error", err)
			select { // Avoid tight loop on persistent errors
			case <-time.After(100 * time.Millisecond):
				continue
			case <-ctx.Done():
				return // Check context during delay
			case <-m.stopChan:
				return // Check stop signal during delay
			}
		}

		slog.Debug("Received ringbuf record", "len", len(record.RawSample))

		// Validate the size of the received data against the expected struct size
		if len(record.RawSample) < tupleSize {
			slog.Warn("Received BPF ring buffer event with unexpected size", "expected_min", tupleSize, "received", len(record.RawSample))
			continue // Skip malformed records
		}

		// Decode the raw bytes into the Go struct BpfNotificationTupleT
		// Use nativeEndian determined at init.
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, nativeEndian, &bpfTuple); err != nil {
			slog.Error("Failed to decode BPF ring buffer event data", "error", err)
			continue // Skip records that fail decoding
		}

		// Convert the BPF data structure to the application's NotificationTuple
		// Important: Ensure correct byte order conversion (Network to Host for ports)
		event := NotificationTuple{
			PidTgid:     bpfTuple.PidTgid,
			SrcIP:       ipFromInt(bpfTuple.SrcIp),     // Network order __be32 -> net.IP
			OrigDstIP:   ipFromInt(bpfTuple.OrigDstIp), // Network order __be32 -> net.IP
			SrcPort:     ntohs(bpfTuple.SrcPort),       // Network order __be16 -> host order uint16
			OrigDstPort: ntohs(bpfTuple.OrigDstPort),   // Network order __be16 -> host order uint16
			Protocol:    bpfTuple.Protocol,
			// Copy padding if the Go struct defines it and needs it.
			// Example: PaddingBytes: make([]byte, len(bpfTuple.Padding)); copy(PaddingBytes, bpfTuple.Padding[:])
		}

		// Send the decoded event to the notification channel (non-blocking).
		select {
		case m.notificationChannel <- event:
			slog.Debug("Sent BPF connection notification to service processor",
				"pid_tgid", event.PidTgid,
				"src_ip", event.SrcIP,
				"src_port", event.SrcPort,
				"orig_dst_ip", event.OrigDstIP,
				"orig_dst_port", event.OrigDstPort)
		case <-ctx.Done(): // Check context cancellation during send attempt
			slog.Info("Stopping BPF ring buffer reader while sending notification (context cancelled).")
			return
		case <-m.stopChan: // Check stop signal during send attempt
			slog.Info("Stopping BPF ring buffer reader while sending notification (stop signal).")
			return
		default:
			// This indicates the service's processing loop is falling behind.
			slog.Warn("BPF notification channel is full, dropping event.", "channel_cap", cap(m.notificationChannel), "channel_len", len(m.notificationChannel), "event_dst_port", event.OrigDstPort)
		}
	}
}

// statsUpdater periodically fetches and logs BPF statistics.
func (m *BPFManager) statsUpdater(ctx context.Context) {
	if m.cfg.StatsInterval <= 0 {
		slog.Info("BPF statistics collection disabled (stats_interval <= 0).")
		return
	}
	interval := time.Duration(m.cfg.StatsInterval) * time.Second
	if interval <= 0 { // Sanity check
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return // Exit if main context cancelled
		case <-m.stopChan:
			return // Exit if manager stop signal received
		case <-ticker.C:
			if err := m.updateAndLogStats(); err != nil {
				// Log error but continue trying to update stats
				slog.Error("Failed to update BPF statistics", "error", err)
			}
		}
	}
}

// updateAndLogStats reads the current BPF stats, calculates rates, and logs them.
func (m *BPFManager) updateAndLogStats() error {
	m.statsCache.Lock() // Lock for writing to cache
	defer m.statsCache.Unlock()

	now := time.Now()
	duration := now.Sub(m.statsCache.lastStatsTime).Seconds()
	if duration <= 0.1 { // Avoid division by zero or tiny intervals
		slog.Debug("Skipping stats update, interval too short", "duration", duration)
		return nil
	}

	// Read current matched connection stats from BPF map
	matchedCurrent, err := m.readGlobalStats(GlobalStatsMatchedIndex)
	if err != nil {
		return fmt.Errorf("failed to read matched BPF stats: %w", err)
	}

	// Calculate rate per second for matched connections
	matchedRateP := 0.0
	if duration > 0 { // Avoid division by zero
		// Check for counter wrap-around (unlikely for u64, but good practice)
		deltaPackets := int64(matchedCurrent.Packets - m.statsCache.lastMatched.Packets)
		if deltaPackets < 0 {
			deltaPackets = int64(matchedCurrent.Packets) // Assume counter reset/wrap, use current value as delta
			slog.Warn("BPF matched connection counter appeared to wrap or reset", "last", m.statsCache.lastMatched.Packets, "current", matchedCurrent.Packets)
		}
		matchedRateP = float64(deltaPackets) / duration
	}

	slog.Info("eBPF Statistics",
		slog.Group("matched_conns",
			"total_conns", matchedCurrent.Packets,
			"conn_rate_per_sec", fmt.Sprintf("%.2f", matchedRateP),
			// Bytes not currently tracked in BPF stats map value
		),
		"interval_sec", fmt.Sprintf("%.2f", duration),
	)

	// Update cache for next calculation
	m.statsCache.matchedConns = matchedCurrent // Store current as the latest known value
	m.statsCache.lastMatched = matchedCurrent  // Store current as the 'previous' value for the *next* interval
	m.statsCache.lastStatsTime = now

	return nil
}

// readGlobalStats reads per-CPU stats from the BPF map and aggregates them.
// Uses the correct map reference from the loaded objects.
func (m *BPFManager) readGlobalStats(index uint32) (GlobalStats, error) {
	var aggregate GlobalStats
	// Use the direct access field populated during loading
	globalStatsMap := m.objs.GlobalStats
	if globalStatsMap == nil {
		return aggregate, errors.New("BPF global_stats map is nil (was it loaded?)")
	}

	// Use the generated type for the map value slice
	var perCPUValues []bpf_connect4GlobalStatsT // Or appropriate generated type name

	// Lookup the per-CPU values for the given index
	err := globalStatsMap.Lookup(index, &perCPUValues)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// This might be expected if the index is invalid or map isn't fully populated yet
			slog.Warn("Stats key not found in BPF global_stats map", "key", index)
			// Return zero stats, not necessarily an error for the caller unless stats are critical
			return aggregate, nil
		}
		return aggregate, fmt.Errorf("failed lookup stats key %d in BPF global_stats map: %w", index, err)
	}

	// Sum values from all CPUs
	for _, cpuStat := range perCPUValues {
		aggregate.Packets += cpuStat.Packets
		aggregate.Bytes += cpuStat.Bytes // Summing bytes even if BPF doesn't update them
	}
	return aggregate, nil
}

// UpdateTargetPorts updates the target_ports BPF hash map with the provided list of ports.
// Uses the correct map reference from the loaded objects.
func (m *BPFManager) UpdateTargetPorts(ports []int) error {
	m.mu.Lock() // Lock to prevent concurrent updates
	defer m.mu.Unlock()

	// Use the direct access field populated during loading
	targetPortsMap := m.objs.TargetPorts
	if targetPortsMap == nil {
		return errors.New("BPF target_ports map not initialized (was it loaded?)")
	}

	// --- Logic to sync Go slice with BPF map ---

	// 1. Get current ports from the BPF map
	currentPortsMap := make(map[uint16]bool)
	var mapKey uint16  // Key type in BPF map (Host Byte Order)
	var mapValue uint8 // Value type in BPF map (1 for present)
	iter := targetPortsMap.Iterate()
	for iter.Next(&mapKey, &mapValue) {
		if mapValue == 1 {
			currentPortsMap[mapKey] = true
		}
	}
	if err := iter.Err(); err != nil {
		// Log warning but proceed, assuming map might be empty or partially iterable
		slog.Warn("Failed to iterate existing BPF target_ports map, proceeding with update anyway", "error", err)
		currentPortsMap = make(map[uint16]bool) // Reset map to ensure we add all desired ports
	}

	// 2. Create a set of desired ports from the input list (Host Byte Order)
	desiredPortsSet := make(map[uint16]bool)
	validNewPortsList := make([]int, 0, len(ports)) // For logging the final list
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			portKey := uint16(p) // Key for the map is uint16 (Host Byte Order)
			desiredPortsSet[portKey] = true
			validNewPortsList = append(validNewPortsList, p)
		} else {
			slog.Warn("Invalid port number ignored in UpdateTargetPorts", "port", p)
		}
	}

	// 3. Delete ports from BPF map that are no longer desired
	deletedCount := 0
	for portKey := range currentPortsMap {
		if !desiredPortsSet[portKey] {
			// Port exists in map but not in the new desired list, delete it.
			if err := targetPortsMap.Delete(portKey); err != nil {
				// Log error if deletion fails (unless key already gone)
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					slog.Error("Failed to delete target port from BPF map", "port", portKey, "error", err)
					// Consider returning error here? Or just log? Log for now.
				}
			} else {
				slog.Debug("Deleted target port from BPF map", "port", portKey)
				deletedCount++
			}
		}
	}

	// 4. Add ports to BPF map that are newly desired
	addedCount := 0
	var mapValueOne uint8 = 1 // Value to indicate presence
	for portKey := range desiredPortsSet {
		if !currentPortsMap[portKey] {
			// Port is in desired list but not currently in the map, add it.
			if err := targetPortsMap.Put(portKey, mapValueOne); err != nil {
				slog.Error("Failed to add target port to BPF map", "port", portKey, "error", err)
				// Consider returning error here? Or just log? Log for now.
			} else {
				slog.Debug("Added target port to BPF map", "port", portKey)
				addedCount++
			}
		}
	}

	// Log summary of changes
	if addedCount > 0 || deletedCount > 0 {
		slog.Info("BPF target ports map updated", "added", addedCount, "deleted", deletedCount, "final_list", validNewPortsList)
	} else {
		slog.Debug("BPF target ports map unchanged", "ports", validNewPortsList)
	}

	// Update the config struct field in memory to reflect the actual applied state
	// Note: This modifies the cfg passed during NewBPFManager initialization.
	if m.cfg != nil {
		m.cfg.TargetPorts = validNewPortsList
	}

	return nil
}

// GetConnectionPID is DEPRECATED as PID is now included in the notification tuple.
// Remove or comment out.
/*
func (m *BPFManager) GetConnectionPID(tuple NotificationTuple) (uint32, error) {
	return 0, errors.New("GetConnectionPID is deprecated, PID included in notification")
}
*/

// GetStats returns the cached statistics read periodically from the BPF maps.
func (m *BPFManager) GetStats() (total GlobalStats, matched GlobalStats, err error) {
	m.statsCache.RLock() // Lock for reading cache
	defer m.statsCache.RUnlock()

	// Note: Total stats (key 0) are not currently collected/read. Return empty.
	total = GlobalStats{}
	// Return the last read value for matched connections.
	matched = m.statsCache.matchedConns

	return total, matched, nil
}

// Close cleans up all BPF resources: detaches programs and closes maps and links.
// UPDATED to close all three links and use the combined object closer.
func (m *BPFManager) Close() error {
	m.mu.Lock() // Lock to prevent state changes during close
	defer m.mu.Unlock()

	var firstErr error
	m.stopOnce.Do(func() {
		slog.Info("Closing BPF Manager...")
		// 1. Signal background goroutines to stop
		close(m.stopChan)

		// 2. Close ring buffer reader (unblocks reader goroutine)
		if m.notificationReader != nil {
			slog.Debug("Closing BPF ring buffer reader...")
			if err := m.notificationReader.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, ringbuf.ErrClosed) {
				slog.Error("Error closing BPF ringbuf reader", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("ringbuf close: %w", err)
				}
			}
			m.notificationReader = nil // Prevent double close
		}

		// 3. Detach/close links (Order: sk_msg first, then cgroup hooks)
		if m.skMsgLink != nil {
			slog.Debug("Closing BPF sk_msg link...")
			if err := m.skMsgLink.Close(); err != nil {
				slog.Error("Error closing BPF sk_msg link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("sk_msg link close: %w", err)
				}
			}
			m.skMsgLink = nil // Prevent double close
		}
		if m.cgroupLink != nil {
			slog.Debug("Closing BPF cgroup sock_ops link...")
			if err := m.cgroupLink.Close(); err != nil {
				slog.Error("Error closing BPF cgroup sock_ops link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("cgroup sock_ops link close: %w", err)
				}
			}
			m.cgroupLink = nil // Prevent double close
		}
		if m.connect4Link != nil {
			slog.Debug("Closing BPF cgroup connect4 link...")
			if err := m.connect4Link.Close(); err != nil {
				slog.Error("Error closing BPF cgroup connect4 link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("cgroup connect4 link close: %w", err)
				}
			}
			m.connect4Link = nil // Prevent double close
		}

		// 4. Close all loaded BPF objects (programs and maps) using the combined closer
		slog.Debug("Closing all BPF objects (programs and maps)...")
		if err := m.objs.Close(); err != nil {
			slog.Error("Error closing BPF objects", "error", err)
			if firstErr == nil {
				// Wrap the combined error from objs.Close()
				firstErr = fmt.Errorf("bpf objects close: %w", err)
			} else {
				// Append the error if firstErr already exists
				firstErr = fmt.Errorf("%w; bpf objects close: %w", firstErr, err)
			}
		}

		slog.Info("BPF Manager closed.")
	})
	return firstErr
}

// --- Utility Functions ---

// nativeEndian stores the system's byte order, determined at init.
var nativeEndian binary.ByteOrder

// init determines the native byte order of the host system.
func init() {
	buf := [2]byte{}
	// Write a known 16-bit value to the buffer pointer.
	*(*uint16)(unsafe.Pointer(&buf[0])) = 0xABCD
	switch buf {
	case [2]byte{0xCD, 0xAB}: // Little Endian (e.g., x86) stores LSB first
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}: // Big Endian stores MSB first
		nativeEndian = binary.BigEndian
	default:
		panic("Failed to determine native byte order")
	}
}

// ipFromInt converts a uint32 representing an IPv4 address in network byte order (BigEndian)
// into a net.IP object.
func ipFromInt(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	// binary.BigEndian works correctly regardless of nativeEndian,
	// as it explicitly reads/writes in BigEndian order.
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip
}

// ntohs converts a uint16 from network byte order (Big Endian) to host byte order.
func ntohs(n uint16) uint16 {
	// Check if host order is different from network order (Big Endian)
	if nativeEndian == binary.LittleEndian {
		// Swap bytes
		return (n >> 8) | (n << 8)
	}
	// If host order is Big Endian, no swap needed
	return n
}

// htons converts a uint16 from host byte order to network byte order (Big Endian).
func htons(n uint16) uint16 {
	// Check if host order is different from network order (Big Endian)
	if nativeEndian == binary.LittleEndian {
		// Swap bytes
		return (n >> 8) | (n << 8)
	}
	// If host order is Big Endian, no swap needed
	return n
}

// GetAvailableInterfaces lists suitable network interfaces for potential monitoring/stats.
// Note: Sockops attaches to cgroup, not a specific interface, but this can be useful info.
func GetAvailableInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var names []string
	for _, i := range interfaces {
		// Skip down, loopback, and virtual interfaces
		if (i.Flags&net.FlagUp == 0) || (i.Flags&net.FlagLoopback != 0) {
			continue
		}
		// Simple filter for common virtual interface prefixes
		if strings.HasPrefix(i.Name, "veth") || strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "lo") {
			continue
		}
		// Check if interface has usable IP addresses (optional, but good)
		addrs, err := i.Addrs()
		if err != nil || len(addrs) == 0 {
			continue // Skip interfaces without addresses or errors fetching them
		}

		names = append(names, i.Name)
	}

	if len(names) == 0 {
		slog.Warn("No suitable non-loopback, active network interfaces found.")
		// Return empty list, not an error
	}
	return names, nil
}

// GetUidFromPid reads the UID from the /proc filesystem for a given PID.
func GetUidFromPid(pid uint32) (uint32, error) {
	statusFilePath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusFilePath)
	if err != nil {
		// Process likely exited
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("process %d not found (likely exited): %w", pid, err)
		}
		return 0, fmt.Errorf("failed to read process status file %s: %w", statusFilePath, err)
	}

	// Parse the status file line by line
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line) // Split by whitespace
			// Expecting "Uid:\t<RealUID>\t<EffectiveUID>\t<SavedUID>\t<FilesystemUID>"
			if len(fields) >= 2 {
				// Use the Real UID (first numeric field)
				uidVal, err := strconv.ParseUint(fields[1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("failed to parse Real UID from status line '%s': %w", line, err)
				}
				return uint32(uidVal), nil // Success
			}
		}
	}

	// UID line not found in the status file
	return 0, fmt.Errorf("uid not found in process status file %s", statusFilePath)
}
