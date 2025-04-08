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
// **MODIFIED** to include PidTgid, OrigDstIP, OrigDstPort.
type NotificationTuple struct {
	PidTgid      uint64 // PID/TGID of the process initiating the connection
	SrcIP        net.IP // Source IP address (IPv4) of the connection
	OrigDstIP    net.IP // Original Destination IP address (IPv4) the process tried to connect to
	SrcPort      uint16 // Source port (Host Byte Order) of the connection
	OrigDstPort  uint16 // Original Destination port (Host Byte Order) the process tried to connect to
	Protocol     uint8  // IP protocol (e.g., syscall.IPPROTO_TCP)
	PaddingBytes []byte // Optional: Capture padding from C struct if needed for debugging/validation
}

// BpfConnectionDetailsT corresponds to struct connection_details_t in bpf_shared.h.
// Using the generated type (assuming it's consistent across bpf_connect4/bpf_sockops).
// It stores details captured by the connect4 hook.
type BpfConnectionDetailsT = bpf_connect4ConnectionDetailsT // Adjust if generated name differs

// BpfNotificationTupleT corresponds to struct notification_tuple_t in bpf_shared.h.
// Using generated type from sockops (which populates the ringbuf).
// This struct layout must exactly match the C definition for correct decoding.
type BpfNotificationTupleT = bpf_sockopsNotificationTupleT // Adjust if generated name differs

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
	// Create a slice of closers from the embedded objects to ensure all are closed.
	closers := []io.Closer{
		&o.bpf_connect4Objects,
		&o.bpf_sockopsObjects,
		&o.bpf_skmsgObjects,
	}

	var errs []error
	for _, closer := range closers {
		// Check if the embedded object itself is nil before closing
		// (Might happen if loading failed partially)
		// This requires reflection or checking specific fields, simpler to just attempt close.
		if err := closer.Close(); err != nil {
			// Don't wrap os.ErrClosed as it's expected if already closed
			if !errors.Is(err, os.ErrClosed) {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		// Combine multiple errors if necessary for reporting.
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
	cfg                 *config.EBPFConfig       // Reference to the EBPF section of the config
	objs                bpfObjects               // Holds all loaded BPF objects (programs and maps)
	connect4Link        link.Link                // Link for the connect4 cgroup hook
	cgroupLink          link.Link                // Link for the sockops cgroup hook
	skMsgLink           link.Link                // Link for the sk_msg program attached to the sockmap
	notificationReader  *ringbuf.Reader          // Reader for the BPF ring buffer map
	notificationChannel chan<- NotificationTuple // Channel to send notifications to the service
	stopOnce            sync.Once                // Ensures Close actions run only once
	stopChan            chan struct{}            // Signals background goroutines to stop
	statsCache          struct {                 // Cached BPF statistics
		sync.RWMutex
		matchedConns  GlobalStats // Last read value for matched connections count
		lastMatched   GlobalStats // Previous value for rate calculation
		lastStatsTime time.Time   // Timestamp of the last stats update
	}
	mu sync.Mutex // Protects manager state during initialization and updates
}

// NewBPFManager creates, loads, and attaches the eBPF programs based on the provided configuration.
func NewBPFManager(cfg *config.EBPFConfig, notifChan chan<- NotificationTuple) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "connect4/sockops/skmsg")

	// Remove memory lock limits required for eBPF map creation, especially on older kernels.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	// --- Load eBPF programs and maps from generated Go code ---
	var objs bpfObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Optional: Pin maps to bpffs for external inspection or reuse.
			// PinPath: "/sys/fs/bpf/kernelgatekeeper",
		},
		Programs: ebpf.ProgramOptions{
			// Increase log level and buffer size for better debugging info from the verifier.
			LogLevel: ebpf.LogLevelInstruction,         // Use LogLevelBranch for maximum detail
			LogSize:  ebpf.DefaultVerifierLogSize * 10, // e.g., 20MB buffer
		},
	}

	// Strategy: Load programs sequentially, reusing maps defined in the first loaded spec.
	// 1. Load Specs (metadata about the programs/maps)
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

	// 2. Load connect4 objects (defines maps initially)
	if err := specConnect4.LoadAndAssign(&objs.bpf_connect4Objects, opts); err != nil {
		handleVerifierError("connect4", err) // Log detailed verifier error if possible
		return nil, fmt.Errorf("failed to load eBPF connect4 objects: %w", err)
	}
	slog.Debug("eBPF connect4 objects loaded successfully.")
	// Populate direct access fields after loading the first set containing map definitions.
	// Ensure these field names match the `ebpf:"..."` tags in the bpfObjects struct.
	objs.KernelgatekeeperConnect4 = objs.bpf_connect4Objects.KernelgatekeeperConnect4
	objs.ConnectionDetailsMap = objs.bpf_connect4Objects.ConnectionDetailsMap
	objs.TargetPorts = objs.bpf_connect4Objects.TargetPorts
	objs.ProxySockMap = objs.bpf_connect4Objects.ProxySockMap
	objs.NotificationRingbuf = objs.bpf_connect4Objects.NotificationRingbuf
	objs.GlobalStats = objs.bpf_connect4Objects.GlobalStats

	// 3. Load sockops objects, replacing shared maps with instances from connect4 load.
	opts.MapReplacements = map[string]*ebpf.Map{
		"connection_details_map": objs.ConnectionDetailsMap,
		"target_ports":           objs.TargetPorts,
		"proxy_sock_map":         objs.ProxySockMap,
		"notification_ringbuf":   objs.NotificationRingbuf,
		"global_stats":           objs.GlobalStats,
	}
	if err := specSockops.LoadAndAssign(&objs.bpf_sockopsObjects, opts); err != nil {
		handleVerifierError("sockops", err)
		objs.bpf_connect4Objects.Close() // Clean up already loaded objects on failure
		return nil, fmt.Errorf("failed to load eBPF sockops objects: %w", err)
	}
	slog.Debug("eBPF sockops objects loaded successfully.")
	objs.KernelgatekeeperSockops = objs.bpf_sockopsObjects.KernelgatekeeperSockops // Populate direct prog field

	// 4. Load skmsg objects, replacing the shared sockmap.
	opts.MapReplacements = map[string]*ebpf.Map{
		// sk_msg only directly references proxy_sock_map in this setup.
		"proxy_sock_map": objs.ProxySockMap,
	}
	if err := specSkmsg.LoadAndAssign(&objs.bpf_skmsgObjects, opts); err != nil {
		handleVerifierError("skmsg", err)
		objs.bpf_connect4Objects.Close() // Clean up all previously loaded objects on failure
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load eBPF skmsg objects: %w", err)
	}
	slog.Debug("eBPF skmsg objects loaded successfully.")
	objs.KernelgatekeeperSkmsg = objs.bpf_skmsgObjects.KernelgatekeeperSkmsg // Populate direct prog field

	// --- Initialize Manager Struct and Attach Programs ---
	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs, // Store the combined objects
		notificationChannel: notifChan,
		stopChan:            make(chan struct{}),
	}
	manager.statsCache.lastStatsTime = time.Now() // Initialize stats timestamp

	// Validate that all required programs and maps were successfully loaded and assigned.
	if objs.KernelgatekeeperConnect4 == nil ||
		objs.KernelgatekeeperSockops == nil ||
		objs.KernelgatekeeperSkmsg == nil ||
		objs.ConnectionDetailsMap == nil ||
		objs.TargetPorts == nil ||
		objs.ProxySockMap == nil ||
		objs.NotificationRingbuf == nil ||
		objs.GlobalStats == nil {
		manager.objs.Close() // Attempt cleanup
		return nil, errors.New("one or more required BPF programs or maps failed to load or assign after merging objects")
	}

	// Attach the loaded programs to their respective hooks.
	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close() // Clean up loaded objects if attach fails
		return nil, err // Error from attachPrograms already contains context
	}

	// Create a reader for the BPF ring buffer map used for notifications.
	var ringbufErr error
	// Use the direct access field for the map.
	manager.notificationReader, ringbufErr = ringbuf.NewReader(objs.NotificationRingbuf)
	if ringbufErr != nil {
		manager.Close() // Clean up attachments and objects
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", ringbufErr)
	}
	slog.Info("BPF ring buffer reader initialized")

	// Set the initial target ports in the BPF map based on configuration.
	if err := manager.UpdateTargetPorts(cfg.TargetPorts); err != nil {
		manager.Close() // Clean up attachments and objects
		return nil, fmt.Errorf("failed to set initial target ports in BPF map: %w", err)
	}

	slog.Info("BPF Manager initialized and programs attached successfully.")
	return manager, nil
}

// handleVerifierError checks if an error is a VerifierError and logs its details for debugging.
func handleVerifierError(objType string, err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		// Print the detailed verifier log, which often contains clues about the error.
		slog.Error(fmt.Sprintf("eBPF Verifier error (loading %s objects)", objType), "log", fmt.Sprintf("%+v", verr))
	}
}

// attachPrograms attaches the connect4, sockops, and sk_msg programs to the appropriate hooks.
func (m *BPFManager) attachPrograms(cgroupPath string) error {
	// Use direct access fields for programs and maps for clarity.
	connect4Prog := m.objs.KernelgatekeeperConnect4
	sockopsProg := m.objs.KernelgatekeeperSockops
	skmsgProg := m.objs.KernelgatekeeperSkmsg
	sockMap := m.objs.ProxySockMap

	// Validate that programs and maps needed for attachment are not nil.
	if connect4Prog == nil || sockopsProg == nil || skmsgProg == nil || sockMap == nil {
		return errors.New("internal error: one or more required BPF programs or the sockmap are nil during attach phase")
	}

	// Check cgroup path existence and type before attempting attachment.
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

	// --- Attach Programs sequentially, cleaning up on failure ---
	var linkErr error // Variable to store errors during linking

	// 1. Attach connect4 program to the cgroup's connect4 hook.
	m.connect4Link, linkErr = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: connect4Prog,
		Attach:  ebpf.AttachCGroupInet4Connect, // Hook for IPv4 connect syscall
	})
	if linkErr != nil {
		return fmt.Errorf("failed to attach connect4 program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF connect4 program attached to cgroup", "path", cgroupPath)

	// 2. Attach sock_ops program to the cgroup's sock_ops hook.
	m.cgroupLink, linkErr = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: sockopsProg,
		Attach:  ebpf.AttachCGroupSockOps, // Hook for various socket operations
	})
	if linkErr != nil {
		m.connect4Link.Close() // Clean up the previously attached link
		return fmt.Errorf("failed to attach sock_ops program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF sock_ops program attached to cgroup", "path", cgroupPath)

	// 3. Attach sk_msg program to the proxy_sock_map for message redirection.
	m.skMsgLink, linkErr = link.AttachRawLink(link.RawLinkOptions{
		Program: skmsgProg,
		Attach:  ebpf.AttachSkMsgVerdict, // Hook for redirecting messages via sockmap
		Target:  sockMap.FD(),            // Target is the file descriptor of the sockmap
		Flags:   0,                       // Use 0 for modern kernels; consider BPF_F_REPLACE if needed
	})
	if linkErr != nil {
		m.cgroupLink.Close() // Clean up previously attached links
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sk_msg program to proxy_sock_map (FD %d): %w", sockMap.FD(), linkErr)
	}
	slog.Info("eBPF sk_msg program attached to proxy_sock_map", "map_fd", sockMap.FD())

	return nil // All attachments were successful
}

// Start launches the background goroutines for reading notifications and updating stats.
func (m *BPFManager) Start(ctx context.Context, wg *sync.WaitGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Ensure the manager, especially the ring buffer reader, is initialized before starting tasks.
	if m.notificationReader == nil {
		return errors.New("BPF manager not fully initialized (notificationReader is nil), cannot start tasks")
	}

	slog.Info("Starting BPF Manager background tasks (ring buffer reader, stats updater)...")

	// Goroutine for reading notifications from the BPF ring buffer.
	wg.Add(1)
	go func() {
		defer wg.Done() // Ensure WaitGroup is decremented when goroutine exits
		slog.Info("BPF ring buffer reader task started.")
		m.readNotifications(ctx) // Pass the main context for cancellation control
		slog.Info("BPF ring buffer reader task stopped.")
	}()

	// Goroutine for periodically updating and logging BPF statistics.
	wg.Add(1)
	go func() {
		defer wg.Done() // Ensure WaitGroup is decremented when goroutine exits
		slog.Info("BPF statistics updater task started.")
		m.statsUpdater(ctx) // Pass the main context for cancellation control
		slog.Info("BPF statistics updater task stopped.")
	}()

	return nil
}

// readNotifications continuously reads connection notification events from the BPF ring buffer.
// It decodes the event data into NotificationTuple and sends it to the service channel.
func (m *BPFManager) readNotifications(ctx context.Context) {
	// Use the Go type generated by bpf2go that corresponds to struct notification_tuple_t.
	var bpfTuple BpfNotificationTupleT
	// Determine the expected size of the C struct for validation.
	tupleSize := binary.Size(bpfTuple)
	if tupleSize <= 0 { // binary.Size returns -1 on error
		slog.Error("Could not determine size of BpfNotificationTupleT (binary.Size failed)", "size", tupleSize)
		return // Cannot proceed without knowing the expected size
	}
	slog.Debug("BPF ring buffer reader expecting record size", "size", tupleSize)

	// Loop indefinitely, reading records until context is cancelled or reader is closed.
	for {
		// Check for cancellation signals *before* potentially blocking on Read().
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader due to context cancellation.")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF ring buffer reader due to stop signal.")
			return
		default: // Continue if no signal received
		}

		// Read the next record from the ring buffer. This call blocks until a record is available
		// or the reader is closed.
		record, err := m.notificationReader.Read()
		if err != nil {
			// Check common reasons for the reader to stop.
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				slog.Info("BPF ring buffer reader closed.")
				return // Exit cleanly
			}
			// Check if the context was cancelled while Read() was blocked.
			if errors.Is(err, context.Canceled) {
				slog.Info("BPF ring buffer reading cancelled by context.")
				return
			}
			// Log other errors and pause briefly to prevent spamming logs on persistent issues.
			slog.Error("Error reading from BPF ring buffer", "error", err)
			select {
			case <-time.After(100 * time.Millisecond): // Small delay
				continue // Try reading again
			case <-ctx.Done():
				return // Exit if context cancelled during delay
			case <-m.stopChan:
				return // Exit if stop signal received during delay
			}
		}

		slog.Debug("Received raw BPF ring buffer record", "len", len(record.RawSample))

		// Validate the size of the received data. It must be at least the expected struct size.
		if len(record.RawSample) < tupleSize {
			slog.Warn("Received BPF ring buffer event with unexpected size, skipping.",
				"expected_min", tupleSize, "received", len(record.RawSample))
			continue // Skip malformed or incomplete records
		}

		// Decode the raw bytes from the record into the generated Go struct BpfNotificationTupleT.
		// It's crucial that nativeEndian matches the host's byte order.
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, nativeEndian, &bpfTuple); err != nil {
			slog.Error("Failed to decode BPF ring buffer event data into BpfNotificationTupleT", "error", err)
			continue // Skip records that fail decoding
		}

		// Convert the decoded BPF data structure (BpfNotificationTupleT)
		// into the application's NotificationTuple struct for easier use.
		// This involves converting byte orders (e.g., network to host for ports)
		// and IP address representations.
		event := NotificationTuple{
			PidTgid:     bpfTuple.PidTgid,              // Directly copy uint64
			SrcIP:       ipFromInt(bpfTuple.SrcIp),     // Convert __be32 (Network Order) -> net.IP
			OrigDstIP:   ipFromInt(bpfTuple.OrigDstIp), // Convert __be32 (Network Order) -> net.IP
			SrcPort:     ntohs(bpfTuple.SrcPort),       // Convert __be16 (Network Order) -> uint16 (Host Order)
			OrigDstPort: ntohs(bpfTuple.OrigDstPort),   // Convert __be16 (Network Order) -> uint16 (Host Order)
			Protocol:    bpfTuple.Protocol,             // Directly copy uint8
			// Optionally copy padding bytes if needed for analysis/debugging
			// PaddingBytes: append([]byte{}, bpfTuple.Padding[:]...), // Creates a copy
		}

		// Send the processed event to the notification channel consumed by the service logic.
		// Use a non-blocking send to avoid blocking the reader if the channel is full.
		select {
		case m.notificationChannel <- event:
			slog.Debug("Sent BPF connection notification to service processor",
				"pid_tgid", event.PidTgid,
				"src_ip", event.SrcIP,
				"src_port", event.SrcPort,
				"orig_dst_ip", event.OrigDstIP,
				"orig_dst_port", event.OrigDstPort)
		case <-ctx.Done(): // Check context cancellation during the send attempt
			slog.Info("Stopping BPF ring buffer reader while sending notification (context cancelled).")
			return
		case <-m.stopChan: // Check stop signal during the send attempt
			slog.Info("Stopping BPF ring buffer reader while sending notification (stop signal).")
			return
		default:
			// If the channel send fails immediately (channel is full), log a warning.
			// This indicates the service's processing loop might be falling behind.
			slog.Warn("BPF notification channel is full, dropping event.",
				"channel_cap", cap(m.notificationChannel),
				"channel_len", len(m.notificationChannel),
				"event_dst_port", event.OrigDstPort)
		}
	}
}

// statsUpdater periodically calls updateAndLogStats based on the configured interval.
func (m *BPFManager) statsUpdater(ctx context.Context) {
	// Disable stats collection if interval is not positive.
	if m.cfg.StatsInterval <= 0 {
		slog.Info("BPF statistics collection disabled (stats_interval <= 0).")
		return
	}
	interval := time.Duration(m.cfg.StatsInterval) * time.Second
	// Safety check for interval duration.
	if interval <= 0 {
		slog.Warn("Invalid stats interval configured, defaulting to 15s", "configured", m.cfg.StatsInterval)
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("BPF statistics updater started", "interval", interval)
	// Loop until context cancellation or stop signal.
	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF statistics updater due to context cancellation.")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF statistics updater due to stop signal.")
			return
		case <-ticker.C:
			// On each tick, attempt to update and log the stats.
			if err := m.updateAndLogStats(); err != nil {
				// Log errors but continue the loop.
				slog.Error("Failed to update BPF statistics", "error", err)
			}
		}
	}
}

// updateAndLogStats reads the current BPF stats, calculates rates since the last update, and logs them.
func (m *BPFManager) updateAndLogStats() error {
	m.statsCache.Lock() // Lock for writing to the stats cache
	defer m.statsCache.Unlock()

	now := time.Now()
	// Calculate duration since last update, avoid division by zero or tiny intervals.
	duration := now.Sub(m.statsCache.lastStatsTime).Seconds()
	if duration < 0.1 { // Interval too short, likely due to clock adjustments or rapid calls
		slog.Debug("Skipping stats update, interval too short", "duration_sec", duration)
		return nil
	}

	// Read the current value of matched connections count from the BPF map.
	matchedCurrent, err := m.readGlobalStats(GlobalStatsMatchedIndex)
	if err != nil {
		// Don't update cache times if read fails
		return fmt.Errorf("failed to read matched BPF stats: %w", err)
	}

	// Calculate the rate of matched connections per second.
	matchedRateP := 0.0
	// Check for counter wrap-around (unlikely for u64 packets, but good practice).
	deltaPackets := int64(matchedCurrent.Packets - m.statsCache.lastMatched.Packets)
	if deltaPackets < 0 {
		// Assume counter reset or wrap-around. Use the current value as the delta for this interval.
		slog.Warn("BPF matched connection counter appeared to wrap or reset",
			"last_count", m.statsCache.lastMatched.Packets, "current_count", matchedCurrent.Packets)
		deltaPackets = int64(matchedCurrent.Packets) // Base rate on current count since last known good state
	}
	if duration > 0 { // Avoid division by zero
		matchedRateP = float64(deltaPackets) / duration
	}

	// Log the collected statistics.
	slog.Info("eBPF Statistics",
		slog.Group("matched_conns",
			"total_conns", matchedCurrent.Packets,
			"conn_rate_per_sec", fmt.Sprintf("%.2f", matchedRateP),
			// Add byte stats here if they become implemented in BPF
		),
		"interval_sec", fmt.Sprintf("%.2f", duration),
	)

	// Update the cache for the next calculation cycle.
	m.statsCache.matchedConns = matchedCurrent // Store current as the latest known absolute value
	m.statsCache.lastMatched = matchedCurrent  // Store current as the 'previous' value for the *next* interval
	m.statsCache.lastStatsTime = now

	return nil
}

// readGlobalStats reads per-CPU stats from the BPF map and aggregates them.
// Uses the correct map reference from the loaded objects.
func (m *BPFManager) readGlobalStats(index uint32) (GlobalStats, error) {
	var aggregate GlobalStats
	// Use the direct access field populated during loading.
	globalStatsMap := m.objs.GlobalStats
	if globalStatsMap == nil {
		return aggregate, errors.New("BPF global_stats map is nil (was it loaded?)")
	}

	// The Go value type for a PERCPU_ARRAY map is a slice of the underlying BPF value type.
	// Use the type generated by bpf2go (ensure the name matches your generation).
	var perCPUValues []bpf_connect4GlobalStatsT // Or bpf_sockopsGlobalStatsT if defined there

	// Lookup the per-CPU values for the specified array index.
	err := globalStatsMap.Lookup(index, &perCPUValues)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// It's possible the key is invalid or the map isn't fully populated.
			slog.Warn("Stats key not found in BPF global_stats map", "key", index)
			// Return zero stats rather than failing the caller.
			return aggregate, nil
		}
		// Return other lookup errors.
		return aggregate, fmt.Errorf("failed lookup stats key %d in BPF global_stats map: %w", index, err)
	}

	// Sum the values from all CPUs to get the aggregate count.
	for _, cpuStat := range perCPUValues {
		aggregate.Packets += cpuStat.Packets
		aggregate.Bytes += cpuStat.Bytes // Summing bytes even if BPF doesn't currently update them
	}
	return aggregate, nil
}

// UpdateTargetPorts updates the target_ports BPF hash map with the provided list of ports.
// It synchronizes the map contents with the desired state defined by the `ports` slice.
// Uses the correct map reference from the loaded objects.
func (m *BPFManager) UpdateTargetPorts(ports []int) error {
	m.mu.Lock() // Lock to prevent concurrent updates from different sources (e.g., config reload, IPC)
	defer m.mu.Unlock()

	// Use the direct access field populated during loading.
	targetPortsMap := m.objs.TargetPorts
	if targetPortsMap == nil {
		return errors.New("BPF target_ports map not initialized (was it loaded?)")
	}

	// --- Logic to efficiently synchronize the Go slice with the BPF map state ---

	// 1. Get the set of ports currently present in the BPF map.
	currentPortsMap := make(map[uint16]bool)
	var mapKey uint16  // Key type in BPF map (Port in Host Byte Order)
	var mapValue uint8 // Value type in BPF map (1 means present)
	iter := targetPortsMap.Iterate()
	for iter.Next(&mapKey, &mapValue) {
		// Only consider ports marked as present (value == 1)
		if mapValue == 1 {
			currentPortsMap[mapKey] = true
		}
	}
	// Check for iteration errors, but proceed cautiously if errors occur.
	if err := iter.Err(); err != nil {
		slog.Warn("Failed to fully iterate existing BPF target_ports map, proceeding with update anyway", "error", err)
		// If iteration failed, assume the map state is unknown and force add all desired ports.
		// Clear the map to reflect this assumption.
		currentPortsMap = make(map[uint16]bool)
	}

	// 2. Create a set of desired ports from the input slice (validating ports).
	desiredPortsSet := make(map[uint16]bool)
	validNewPortsList := make([]int, 0, len(ports)) // Keep track of valid ports for logging/config update
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			portKey := uint16(p) // Map key is uint16 (Host Byte Order)
			desiredPortsSet[portKey] = true
			validNewPortsList = append(validNewPortsList, p)
		} else {
			slog.Warn("Invalid port number ignored in UpdateTargetPorts", "port", p)
		}
	}

	// 3. Delete ports from the BPF map that are currently present but no longer desired.
	deletedCount := 0
	for portKey := range currentPortsMap {
		if !desiredPortsSet[portKey] {
			// Port exists in the map but is not in the new desired list -> delete it.
			if err := targetPortsMap.Delete(portKey); err != nil {
				// Log deletion errors unless the key was already gone (ErrKeyNotExist).
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					slog.Error("Failed to delete target port from BPF map", "port", portKey, "error", err)
					// Consider whether to return an error here or just log and continue.
					// Logging is often sufficient for map cleanup operations.
				}
			} else {
				slog.Debug("Deleted target port from BPF map", "port", portKey)
				deletedCount++
			}
		}
	}

	// 4. Add ports to the BPF map that are newly desired and not already present.
	addedCount := 0
	var mapValueOne uint8 = 1 // The value used in the BPF map to indicate presence.
	for portKey := range desiredPortsSet {
		if !currentPortsMap[portKey] {
			// Port is in the desired list but not currently in the map -> add it.
			if err := targetPortsMap.Put(portKey, mapValueOne); err != nil {
				slog.Error("Failed to add target port to BPF map", "port", portKey, "error", err)
				// Consider returning an error if adding essential ports fails.
			} else {
				slog.Debug("Added target port to BPF map", "port", portKey)
				addedCount++
			}
		}
	}

	// Log a summary if any changes were made.
	if addedCount > 0 || deletedCount > 0 {
		slog.Info("BPF target ports map updated", "added", addedCount, "deleted", deletedCount, "final_list", validNewPortsList)
	} else {
		slog.Debug("BPF target ports map remains unchanged", "current_list", validNewPortsList)
	}

	// Update the in-memory config struct field to reflect the actual applied state.
	// This assumes the caller might want the cfg object updated (e.g., after config reload).
	if m.cfg != nil {
		m.cfg.TargetPorts = validNewPortsList
	}

	return nil
}

// GetStats returns the cached BPF statistics.
func (m *BPFManager) GetStats() (total GlobalStats, matched GlobalStats, err error) {
	m.statsCache.RLock() // Use read lock for accessing cached stats
	defer m.statsCache.RUnlock()

	// Note: "total" stats (index 0) are not currently implemented/read in readGlobalStats. Return empty.
	total = GlobalStats{}
	// Return the last successfully read value for matched connections count.
	matched = m.statsCache.matchedConns

	return total, matched, nil
}

// Close cleans up all BPF resources: detaches programs and closes maps and links.
// Ensures all resources associated with the BPF manager are released.
func (m *BPFManager) Close() error {
	m.mu.Lock() // Lock to prevent concurrent close operations or state changes during close
	defer m.mu.Unlock()

	var firstErr error
	// Use sync.Once to ensure the close logic runs exactly once.
	m.stopOnce.Do(func() {
		slog.Info("Closing BPF Manager...")

		// 1. Signal background goroutines (stats updater, ring buffer reader) to stop.
		// Check if stopChan is already closed to prevent panic.
		select {
		case <-m.stopChan:
			// Already closed
		default:
			close(m.stopChan)
		}

		// 2. Close the ring buffer reader. This will unblock the readNotifications goroutine
		//    if it's currently waiting for data.
		if m.notificationReader != nil {
			slog.Debug("Closing BPF ring buffer reader...")
			// Ignore ErrClosed as it means the reader was already closed.
			if err := m.notificationReader.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, ringbuf.ErrClosed) {
				slog.Error("Error closing BPF ringbuf reader", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("ringbuf close: %w", err)
				}
			}
			m.notificationReader = nil // Prevent double close attempts
		}

		// 3. Detach/close BPF program links. Order might matter depending on dependencies,
		//    generally detach specific hooks before generic ones if unsure.
		//    Closing sk_msg link first is safest as it depends on the sockmap.
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

		// 4. Close all loaded BPF objects (programs and maps) using the combined closer method.
		slog.Debug("Closing all BPF objects (programs and maps)...")
		if err := m.objs.Close(); err != nil {
			slog.Error("Error closing BPF objects", "error", err)
			// Append the object closing error to any previous link closing errors.
			if firstErr == nil {
				firstErr = fmt.Errorf("bpf objects close: %w", err)
			} else {
				firstErr = fmt.Errorf("%w; bpf objects close: %w", firstErr, err)
			}
		}

		slog.Info("BPF Manager closed.")
	})
	// Return the first error encountered during the cleanup process, or nil if successful.
	return firstErr
}

// --- Utility Functions ---

// nativeEndian stores the system's byte order, determined at init.
var nativeEndian binary.ByteOrder

// init determines the native byte order of the host system once at package initialization.
func init() {
	buf := [2]byte{}
	// Write a known 16-bit value (0xABCD) into the buffer using a pointer cast.
	*(*uint16)(unsafe.Pointer(&buf[0])) = 0xABCD
	// Check how the bytes are arranged in memory.
	switch buf {
	case [2]byte{0xCD, 0xAB}: // Little Endian (e.g., x86, ARM LE) stores the Least Significant Byte first.
		nativeEndian = binary.LittleEndian
		slog.Debug("Detected native byte order: Little Endian")
	case [2]byte{0xAB, 0xCD}: // Big Endian (e.g., PowerPC, SPARC) stores the Most Significant Byte first.
		nativeEndian = binary.BigEndian
		slog.Debug("Detected native byte order: Big Endian")
	default:
		// This should theoretically never happen on standard systems.
		panic("Failed to determine native byte order")
	}
}

// ipFromInt converts a uint32 representing an IPv4 address in network byte order (BigEndian)
// into a standard net.IP object.
func ipFromInt(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	// binary.BigEndian explicitly puts the bytes in Big Endian order into the slice,
	// which is the standard network byte order for IPv4 addresses represented as uint32.
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip
}

// ntohs converts a uint16 from network byte order (Big Endian) to host byte order.
// This is needed when reading port numbers from BPF structures (which are often __be16)
// for use in Go code (e.g., map lookups, logging).
func ntohs(n uint16) uint16 {
	// If the host system is Little Endian, we need to swap the bytes.
	if nativeEndian == binary.LittleEndian {
		return (n >> 8) | (n << 8)
	}
	// If the host system is Big Endian, network order is the same, so no swap needed.
	return n
}

// htons converts a uint16 from host byte order to network byte order (Big Endian).
// This is needed when writing port numbers from Go code into BPF structures or map keys
// if the BPF C code expects network byte order (__be16).
func htons(n uint16) uint16 {
	// If the host system is Little Endian, swap bytes to get Big Endian.
	if nativeEndian == binary.LittleEndian {
		return (n >> 8) | (n << 8)
	}
	// If the host system is Big Endian, host order is already network order.
	return n
}

// GetAvailableInterfaces lists suitable non-loopback, active network interfaces.
// Useful for configuration hints or status reporting, though not directly used by cgroup sockops attachment.
func GetAvailableInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var names []string
	for _, i := range interfaces {
		// Basic filters: skip interfaces that are down or are loopback devices.
		if (i.Flags&net.FlagUp == 0) || (i.Flags&net.FlagLoopback != 0) {
			continue
		}
		// Filter out common virtual interface prefixes (like Docker, bridges, veth pairs).
		if strings.HasPrefix(i.Name, "veth") || strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "lo") {
			continue
		}
		// Optional but recommended: Check if the interface has any usable IP addresses assigned.
		addrs, err := i.Addrs()
		if err != nil || len(addrs) == 0 {
			slog.Debug("Skipping interface with no addresses or error fetching them", "interface", i.Name, "error", err)
			continue
		}

		names = append(names, i.Name)
	}

	if len(names) == 0 {
		slog.Warn("No suitable non-loopback, active network interfaces with IP addresses found.")
		// Return an empty list, not an error in this case.
	}
	return names, nil
}

// GetUidFromPid reads the Real User ID (UID) from the /proc filesystem for a given Process ID (PID).
// This is used by the service to associate BPF events (which know the PID) with the correct user client.
func GetUidFromPid(pid uint32) (uint32, error) {
	// Construct the path to the process status file.
	statusFilePath := fmt.Sprintf("/proc/%d/status", pid)
	// Read the entire status file content.
	data, err := os.ReadFile(statusFilePath)
	if err != nil {
		// Handle common error: process doesn't exist (likely exited between BPF event and this lookup).
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("process %d not found (likely exited): %w", pid, err)
		}
		// Handle other potential file reading errors.
		return 0, fmt.Errorf("failed to read process status file %s: %w", statusFilePath, err)
	}

	// Parse the status file line by line to find the "Uid:" line.
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			// The line format is typically "Uid:\t<RealUID>\t<EffectiveUID>\t<SavedUID>\t<FilesystemUID>"
			fields := strings.Fields(line) // Split by whitespace
			if len(fields) >= 2 {
				// Parse the second field (Real UID) as an unsigned 32-bit integer.
				uidVal, err := strconv.ParseUint(fields[1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("failed to parse Real UID from status line '%s': %w", line, err)
				}
				return uint32(uidVal), nil // Success: return the parsed UID
			}
		}
	}

	// If the "Uid:" line was not found or couldn't be parsed.
	return 0, fmt.Errorf("uid not found in process status file %s", statusFilePath)
}
