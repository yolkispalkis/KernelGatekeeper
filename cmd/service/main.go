// cmd/service/main.go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix" // For getPeerCredFromConn

	"github.com/yolki/kernelgatekeeper/pkg/config"
	"github.com/yolki/kernelgatekeeper/pkg/ebpf"
	"github.com/yolki/kernelgatekeeper/pkg/ipc"
)

var (
	version   = "dev"
	commit    = "none"
	date      = "unknown"
	startTime = time.Now()
)

// Constants
const (
	defaultNotificationChanSize = 4096 // Default if not in config
	ipcWriteTimeout             = 2 * time.Second
	ipcReadIdleTimeout          = 90 * time.Second  // Max time to wait for *any* client command
	statsLogInterval            = 5 * time.Minute   // Interval for logging channel/client stats
	clientStatusTTL             = 150 * time.Second // How long client status reports are considered valid
)

// ClientState holds runtime information about a connected client.
type ClientState struct {
	UID        uint32
	PID        uint32 // PID reported by client during registration
	LastPing   time.Time
	LastStatus ipc.PingStatusData // Store the last status received from the client
}

// Service holds the state for the KernelGatekeeper service.
type Service struct {
	configPath       string
	config           *config.Config
	configMu         sync.RWMutex
	bpfManager       *ebpf.BPFManager
	ipcListener      net.Listener
	ipcClients       map[net.Conn]*ClientState   // Map connection to client state
	ipcClientsMu     sync.RWMutex                // Mutex for ipcClients map
	stopOnce         sync.Once                   // Ensures shutdown actions run only once
	wg               sync.WaitGroup              // Tracks active goroutines
	notificationChan chan ebpf.NotificationTuple // Channel for BPF notifications (uses updated tuple)
}

func main() {
	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "SERVICE PANIC: %v\n%s\n", r, string(debug.Stack()))
			slog.Error("PANIC", "error", r, "stack", string(debug.Stack()))
			os.Exit(1)
		}
	}()

	// Parse flags
	configPath := flag.String("config", "/etc/kernelgatekeeper/config.yaml", "Path to config file")
	showVersion := flag.Bool("version", false, "Show service version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("KernelGatekeeper Service %s, commit %s, built at %s\n", version, commit, date)
		return
	}

	// Load initial configuration
	cfgPath := "/etc/kernelgatekeeper/config.yaml" // Default path
	if configPath != nil && *configPath != "" {
		cfgPath = *configPath
	}
	initialCfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Failed to load configuration %s: %v\n", cfgPath, err)
		os.Exit(1)
	}

	// Setup logging based on loaded config
	setupLogging(initialCfg.LogLevel, initialCfg.LogPath)
	slog.Info("KernelGatekeeper Service starting", "version", version, "commit", commit, "date", date, "pid", os.Getpid())
	slog.Info("Using configuration file", "path", cfgPath)

	// Create service instance
	svc := &Service{
		configPath: cfgPath,
		config:     initialCfg,
		ipcClients: make(map[net.Conn]*ClientState),
	}

	// Determine notification channel size
	notifChanSize := defaultNotificationChanSize // Use constant default
	if initialCfg.EBPF.NotificationChannelSize > 0 {
		notifChanSize = initialCfg.EBPF.NotificationChannelSize
	} else if initialCfg.EBPF.NotificationChannelSize != 0 { // Allow 0 for default, warn on negative
		slog.Warn("ebpf.notification_channel_size invalid, using default", "configured", initialCfg.EBPF.NotificationChannelSize, "default", defaultNotificationChanSize)
	}
	// Create the channel with the correct NotificationTuple type
	svc.notificationChan = make(chan ebpf.NotificationTuple, notifChanSize)

	// Initialize components (BPF manager)
	if err := svc.initComponents(); err != nil {
		slog.Error("Failed to initialize BPF components", "error", err)
		os.Exit(1)
	}

	// Main application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is cancelled on exit

	// Start background tasks (BPF processing, IPC listener, stats logging)
	svc.startBackgroundTasks(ctx)

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	slog.Info("Service successfully started. Listening for signals and connections...")

	// Main loop to handle signals and context cancellation
	keepRunning := true
	for keepRunning {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("Received termination signal, initiating shutdown...", "signal", sig)
				keepRunning = false // Exit loop
				cancel()            // Cancel context to signal goroutines
			case syscall.SIGHUP:
				slog.Info("Received SIGHUP, reloading configuration...")
				if err := svc.reloadConfig(); err != nil {
					slog.Error("Failed to reload configuration", "error", err)
				} else {
					slog.Info("Configuration reloaded successfully.")
					// Re-setup logging in case log path/level changed
					setupLogging(svc.getConfig().LogLevel, svc.getConfig().LogPath)
				}
			default:
				slog.Info("Received unexpected signal", "signal", sig)
			}
		case <-ctx.Done():
			slog.Info("Main context cancelled, initiating shutdown.")
			keepRunning = false // Exit loop
		}
	}

	// Initiate graceful shutdown
	shutdownTimeout := svc.getConfig().ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = 30 * time.Second // Fallback if config is bad
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	svc.Shutdown(shutdownCtx) // Call shutdown method

	// Wait for all background tasks to complete
	slog.Info("Waiting for background tasks to finish...")
	svc.wg.Wait()
	slog.Info("Service stopped.")
}

// setupLogging configures the global logger based on config.
func setupLogging(logLevelStr, logPath string) {
	var level slog.Level
	switch strings.ToLower(logLevelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo // Default to Info
	}

	var logWriter io.Writer = os.Stderr // Default to stderr
	if logPath != "" {
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			// Use a temporary logger to stderr for this error message
			tempLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			tempLogger.Error("Failed to open configured log file, falling back to stderr", "path", logPath, "error", err)
		} else {
			// Consider closing the file somewhere? Maybe not necessary for long-running service.
			logWriter = logFile
		}
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level <= slog.LevelDebug, // Add source info only for debug level
	}
	logger := slog.New(slog.NewTextHandler(logWriter, opts))
	slog.SetDefault(logger)
}

// initComponents initializes components like the BPF manager.
func (s *Service) initComponents() error {
	slog.Info("Initializing BPF Manager...")
	var err error
	cfg := s.getConfig() // Get a safe copy of config
	// Pass the correctly sized notification channel
	s.bpfManager, err = ebpf.NewBPFManager(&cfg.EBPF, s.notificationChan)
	if err != nil {
		return fmt.Errorf("failed to initialize BPF manager: %w", err)
	}
	slog.Info("BPF Manager initialized.")
	return nil
}

// startBackgroundTasks launches goroutines for BPF processing, IPC, etc.
func (s *Service) startBackgroundTasks(ctx context.Context) {
	slog.Info("Starting background tasks...")

	// Start BPF Manager tasks (stats updater, ring buffer reader)
	if s.bpfManager != nil {
		if err := s.bpfManager.Start(ctx, &s.wg); err != nil {
			// This is fatal, service cannot function without BPF manager tasks
			slog.Error("FATAL: Failed to start BPF manager tasks", "error", err)
			// Use panic to ensure termination after logging
			panic(fmt.Sprintf("failed to start BPF manager tasks: %v", err))
		}
	} else {
		slog.Error("FATAL: BPF Manager is nil, cannot start background tasks.")
		panic("BPF Manager is nil")
	}

	// Start BPF notification processor
	s.wg.Add(1)
	go s.processBPFNotifications(ctx)

	// Start IPC listener
	if err := s.startIPCListener(ctx); err != nil {
		// This is also fatal
		slog.Error("FATAL: Failed to start IPC listener", "error", err)
		panic(fmt.Sprintf("failed to start IPC listener: %v", err))
	}

	// Start periodic stats logger
	s.wg.Add(1)
	go s.logPeriodicStats(ctx)

	slog.Info("Background tasks successfully started.")
}

// logPeriodicStats logs internal stats like channel buffer usage and client count.
func (s *Service) logPeriodicStats(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(statsLogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Periodic stats logger stopping.")
			return
		case <-ticker.C:
			notifChanLen := len(s.notificationChan)
			notifChanCap := cap(s.notificationChan)
			clientCount := s.getClientCount()
			chanUtil := 0.0
			if notifChanCap > 0 {
				chanUtil = float64(notifChanLen) * 100 / float64(notifChanCap)
			}

			// Get BPF stats
			_, matchedStats, bpfErr := s.bpfManager.GetStats()

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

			if notifChanLen > (notifChanCap * 3 / 4) { // Over 75% full
				slog.Warn("BPF notification channel usage is high", "length", notifChanLen, "capacity", notifChanCap)
			}
		}
	}
}

// processBPFNotifications reads from the notification channel and forwards to the appropriate client.
func (s *Service) processBPFNotifications(ctx context.Context) {
	defer s.wg.Done()
	slog.Info("Starting BPF notification processor...")

	for {
		select {
		case <-ctx.Done():
			slog.Info("BPF notification processor stopping (context cancelled).")
			return
		case notification, ok := <-s.notificationChan: // Receives the updated ebpf.NotificationTuple
			if !ok {
				slog.Info("BPF notification channel closed.")
				return // Exit if channel is closed
			}

			// --- Extract PID and TGID from PidTgid ---
			// PidTgid format: (TGID << 32) | PID
			pid_tgid := notification.PidTgid // <<< USE CORRECT FIELD NAME
			pid := uint32(pid_tgid & 0xFFFFFFFF)
			tgid := uint32(pid_tgid >> 32)

			// Use original destination IP/Port from the notification tuple for logging context
			logCtx := slog.With(
				"src_ip", notification.SrcIP.String(),
				"orig_dst_ip", notification.OrigDstIP.String(), // <<< USE CORRECT FIELD NAME
				"orig_dst_port", notification.OrigDstPort, // <<< USE CORRECT FIELD NAME
				"src_port", notification.SrcPort,
				"pid", pid, // Log extracted PID
				"tgid", tgid, // Log extracted TGID
			)
			logCtx.Debug("Received BPF notification tuple")

			if pid == 0 {
				logCtx.Warn("Received notification with zero PID, skipping.", "pid_tgid", pid_tgid)
				continue // Cannot proceed without a valid PID
			}

			// Find UID from the PID using the existing helper function
			uid, err := ebpf.GetUidFromPid(pid)
			if err != nil {
				// This can happen if the process exits quickly after the connect4 hook runs
				logCtx.Warn("Could not get UID for PID (process likely exited?)", "error", err)
				continue // Skip if UID cannot be determined
			}
			logCtx = logCtx.With("uid", uid) // Add uid to log context

			// Find the registered client connection associated with this UID
			clientConn := s.findClientConnByUID(uid) // Use helper that handles locking

			if clientConn == nil {
				logCtx.Debug("No registered client found for UID")
				// Consider logging a warning if this happens frequently, as it might indicate
				// connections from processes not managed by kernelgatekeeper-client.
				continue // No client to send the notification to
			}

			logCtx.Info("Found registered client for connection, sending notification.")

			// Prepare the IPC notification payload using data from the BPF notification tuple
			// Crucially, use the *original* destination IP and Port.
			ipcNotifData := ipc.NotifyAcceptData{
				SrcIP:    notification.SrcIP.String(),     // Actual source IP
				DstIP:    notification.OrigDstIP.String(), // <<< USE CORRECT FIELD NAME
				SrcPort:  notification.SrcPort,            // Actual source port
				DstPort:  notification.OrigDstPort,        // <<< USE CORRECT FIELD NAME
				Protocol: notification.Protocol,
			}

			// Create the IPC command structure
			ipcCmd, err := ipc.NewCommand("notify_accept", ipcNotifData)
			if err != nil {
				logCtx.Error("Failed to create IPC notification command", "error", err)
				continue // Should not happen with valid data, but handle defensively
			}

			// Send the command to the appropriate client asynchronously
			s.sendToClient(clientConn, ipcCmd)
		}
	}
}

// findClientConnByUID finds the client connection for a given UID (Handles locking).
func (s *Service) findClientConnByUID(uid uint32) net.Conn {
	s.ipcClientsMu.RLock()
	defer s.ipcClientsMu.RUnlock()
	for conn, state := range s.ipcClients {
		if state.UID == uid {
			return conn // Return the connection object
		}
	}
	return nil // Not found
}

// sendToClient sends an IPC command to a specific client connection asynchronously.
func (s *Service) sendToClient(conn net.Conn, cmd *ipc.Command) {
	// Get UID before starting goroutine to avoid race if client disconnects quickly
	clientUID := s.getClientUID(conn) // Uses RLock internally

	go func(c net.Conn, command *ipc.Command, uid uint32) {
		logCtx := slog.With("cmd", command.Command, "client_uid", uid) // Use captured UID

		encoder := json.NewEncoder(c)
		// Set write deadline
		c.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
		err := encoder.Encode(command)
		c.SetWriteDeadline(time.Time{}) // Clear deadline immediately

		if err != nil {
			// Don't log cancellation/closure as errors, just info/debug
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || isConnectionClosedErr(err) {
				logCtx.Info("IPC send cancelled or connection closed during send", "error", err)
			} else {
				// Log other errors as warnings/errors
				logCtx.Warn("Failed to send command to client, removing client.", "error", err)
			}
			// Remove the client connection on *any* send error, as it's likely unusable
			s.removeClientConn(c) // removeClientConn handles logging removal
		} else {
			logCtx.Debug("Sent command to client successfully.")
		}
	}(conn, cmd, clientUID) // Pass UID to goroutine
}

// getClientUID retrieves the UID associated with a client connection.
func (s *Service) getClientUID(conn net.Conn) uint32 {
	s.ipcClientsMu.RLock()
	defer s.ipcClientsMu.RUnlock()
	if state, ok := s.ipcClients[conn]; ok {
		return state.UID
	}
	return 0 // Indicate not found (or use a specific value like ^uint32(0))
}

// startIPCListener sets up and runs the Unix domain socket listener.
func (s *Service) startIPCListener(ctx context.Context) error {
	socketPath := s.getConfig().SocketPath // Get path from current config
	if socketPath == "" {
		return errors.New("IPC socket path is not configured")
	}
	dir := filepath.Dir(socketPath)

	// Create directory if needed
	// Use more restricted permissions if appropriate (e.g., 0750 if group matters)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create IPC directory %s: %w", dir, err)
	}

	// Remove stale socket file
	if _, err := os.Stat(socketPath); err == nil {
		// Check if it's actually a socket before removing
		// fi, _ := os.Stat(socketPath) // Re-statting is slightly inefficient but safer
		// if fi.Mode()&os.ModeSocket == 0 {
		//  return fmt.Errorf("existing file at socket path %s is not a socket", socketPath)
		// }
		slog.Info("Removing existing IPC socket file", "path", socketPath)
		if err := os.Remove(socketPath); err != nil {
			// Don't fail if removal fails, maybe permissions issue, Listen will fail later
			slog.Warn("Failed to remove existing IPC socket, continuing...", "path", socketPath, "error", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		// Error occurred during stat, other than file not found
		return fmt.Errorf("failed to stat IPC socket path %s: %w", socketPath, err)
	}

	// Listen on the Unix socket
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on IPC socket %s: %w", socketPath, err)
	}
	s.ipcListener = l // Store the listener

	// Set permissions (0666 allows any user on the system to connect)
	// Consider 0660 and setting appropriate group ownership for better security.
	if err := os.Chmod(socketPath, 0666); err != nil {
		l.Close()
		os.Remove(socketPath) // Clean up socket file
		return fmt.Errorf("failed to chmod IPC socket %s to 0666: %w", socketPath, err)
	}
	// Optionally set group ownership if using 0660
	// gid := ... // Get group ID
	// if err := os.Chown(socketPath, -1, gid); err != nil { ... }

	slog.Info("IPC listener started", "path", socketPath, "permissions", "0666")

	// Goroutine to close listener on context cancellation
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		slog.Info("Closing IPC listener due to context cancellation...")
		if s.ipcListener != nil {
			s.ipcListener.Close() // Close the listener to stop Accept loop
		}
	}()

	// Goroutine to accept incoming connections
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.ipcListener.Accept()
			if err != nil {
				// Check if the error is due to the listener being closed
				if errors.Is(err, net.ErrClosed) {
					slog.Info("IPC listener closed, stopping accept loop.")
					return // Exit loop cleanly
				}
				// Log other accept errors
				slog.Error("IPC accept failed", "error", err)
				// Prevent busy-looping on persistent errors
				select {
				case <-time.After(100 * time.Millisecond):
					continue // Retry accept after a short delay
				case <-ctx.Done():
					return // Exit if context is cancelled
				}
			}
			// Handle connection in a new goroutine
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				s.handleIPCConnection(ctx, c)
			}(conn)
		}
	}()
	return nil
}

// addClientConn adds a new client connection to the map, using credentials from the socket.
func (s *Service) addClientConn(conn net.Conn, reportedPID int) error {
	peerCred, err := getPeerCredFromConn(conn)
	if err != nil {
		return fmt.Errorf("failed to get peer credentials for registering client: %w", err)
	}
	uid := peerCred.Uid
	credentialPID := peerCred.Pid // PID from socket credentials (int32)

	// Optional: Compare reported PID with credential PID for sanity check
	if int32(reportedPID) != credentialPID {
		slog.Warn("Client reported PID differs from socket credential PID",
			"reported_pid", reportedPID, "credential_pid", credentialPID, "uid", uid)
		// Use credentialPID for internal state as it's generally more trustworthy
	}

	s.ipcClientsMu.Lock()
	defer s.ipcClientsMu.Unlock()

	// Check if another connection for the same UID already exists?
	// Policy decision: Allow multiple clients per UID or only one?
	// Current code allows multiple connections from potentially different processes
	// owned by the same user. This seems reasonable.

	// Check if this *specific* connection object is already in map (shouldn't happen)
	if _, exists := s.ipcClients[conn]; exists {
		slog.Warn("Client connection already exists in map during add? Removing old.", "remote_addr", conn.RemoteAddr())
		// Close the old entry's underlying connection? Risky if it's the *same* conn object.
		// Just delete the map entry for now.
		delete(s.ipcClients, conn)
	}

	s.ipcClients[conn] = &ClientState{
		UID:      uid,
		PID:      uint32(credentialPID), // Store the trustworthy PID from credentials
		LastPing: time.Now(),            // Initialize last ping time
	}
	clientCount := len(s.ipcClients)
	slog.Info("IPC client registered and added", "remote_addr", conn.RemoteAddr(), "uid", uid, "pid", credentialPID, "total_clients", clientCount)
	return nil
}

// removeClientConn removes a client connection from the map and closes it.
func (s *Service) removeClientConn(conn net.Conn) {
	s.ipcClientsMu.Lock()
	state, ok := s.ipcClients[conn]
	if ok {
		delete(s.ipcClients, conn)
	}
	clientCount := len(s.ipcClients)
	s.ipcClientsMu.Unlock() // Unlock before potentially slow Close()

	if ok {
		slog.Info("IPC client removed", "remote_addr", conn.RemoteAddr(), "uid", state.UID, "pid", state.PID, "total_clients", clientCount)
	} else {
		// This can happen if remove is called twice for the same conn
		slog.Debug("Attempted to remove non-existent or already removed IPC client", "remote_addr", conn.RemoteAddr())
	}
	// Ensure connection is closed
	if err := conn.Close(); err != nil {
		// Log error during close, but don't panic
		if !errors.Is(err, net.ErrClosed) { // Ignore error if already closed
			slog.Warn("Error closing removed IPC client connection", "remote_addr", conn.RemoteAddr(), "error", err)
		}
	}
}

// getClientCount returns the current number of connected clients.
func (s *Service) getClientCount() int {
	s.ipcClientsMu.RLock()
	defer s.ipcClientsMu.RUnlock()
	return len(s.ipcClients)
}

// handleIPCConnection reads commands from a client connection and processes them.
func (s *Service) handleIPCConnection(ctx context.Context, conn net.Conn) {
	// Use String() representation for logging clarity if available
	clientAddrStr := "unknown"
	if conn.RemoteAddr() != nil {
		clientAddrStr = conn.RemoteAddr().String()
	}
	logCtx := slog.With("client_addr", clientAddrStr) // Use String() representation
	logCtx.Info("Handling new IPC connection")

	// Ensure connection is removed and closed on exit from this handler
	defer func() {
		// Check if client was successfully registered before logging removal
		s.ipcClientsMu.RLock()
		_, registered := s.ipcClients[conn]
		s.ipcClientsMu.RUnlock()
		if registered {
			s.removeClientConn(conn) // removeClientConn logs removal
		} else {
			conn.Close() // Ensure close even if not registered
			logCtx.Info("Closing unregistered IPC connection")
		}
		logCtx.Debug("Finished handling IPC connection") // Use Debug level for finish message
	}()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var clientInfo *ClientState // Store client state once registered

	// Loop reading commands
	for {
		// Check context before potentially blocking read
		select {
		case <-ctx.Done():
			logCtx.Info("Closing IPC handler due to service shutdown.")
			return
		default:
		}

		var cmd ipc.Command
		// Set read deadline to detect idle/dead clients
		conn.SetReadDeadline(time.Now().Add(ipcReadIdleTimeout))
		err := decoder.Decode(&cmd)
		conn.SetReadDeadline(time.Time{}) // Clear deadline immediately after read returns

		if err != nil {
			// Handle different error types gracefully
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isConnectionClosedErr(err) {
				// Client disconnected cleanly or connection broken
				logCtx.Info("IPC connection closed by client or network.")
			} else if isTimeoutError(err) {
				// Client was idle for too long
				logCtx.Warn("IPC connection read timeout. Closing connection.", "timeout", ipcReadIdleTimeout)
			} else {
				// Other decoding errors (e.g., invalid JSON)
				logCtx.Error("Failed to decode IPC command", "error", err)
			}
			return // Exit handler on any error (EOF, timeout, decode error)
		}

		// Get client details for logging if registered
		logCtxCmd := logCtx.With("command", cmd.Command)
		s.ipcClientsMu.RLock()
		registeredClientState := s.ipcClients[conn] // Check current state
		s.ipcClientsMu.RUnlock()
		if registeredClientState != nil {
			logCtxCmd = logCtxCmd.With("uid", registeredClientState.UID, "pid", registeredClientState.PID)
			clientInfo = registeredClientState // Keep clientInfo in sync
		} else {
			clientInfo = nil // Ensure clientInfo is nil if client disconnected between commands
		}

		logCtxCmd.Debug("Received IPC command") // Use Debug level for received command

		// Process the command
		var resp *ipc.Response
		var procErr error

		// --- Command Authorization ---
		// Only allow 'register_client' before client is registered
		isRegistered := clientInfo != nil
		requiresRegistration := cmd.Command != "register_client"

		if requiresRegistration && !isRegistered {
			procErr = errors.New("client not registered")
			logCtxCmd.Warn("Command rejected: client not registered")
			resp = ipc.NewErrorResponse(procErr.Error()) // Ensure response is created
		} else {
			// Pass pointer to update clientInfo on register_client success
			// Need to re-fetch clientInfo inside processIPCCommand if registration happens
			resp, procErr = s.processIPCCommand(conn, &cmd, &clientInfo) // clientInfo can be updated by this call
			if procErr != nil {
				// processIPCCommand returned an error
				resp = ipc.NewErrorResponse(procErr.Error())
				logCtxCmd.Error("Error processing IPC command", "error", procErr)
			} else if resp == nil {
				// Should not happen, processIPCCommand should always return a response
				logCtxCmd.Error("Internal error: processIPCCommand returned nil response and nil error")
				resp = ipc.NewErrorResponse("internal server error processing command")
			}
		}
		// --- End Command Processing ---

		// Send response (unless it's a command that doesn't expect one, e.g., notify?)
		// All current commands expect a response.
		if resp != nil {
			conn.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
			encodeErr := encoder.Encode(resp)
			conn.SetWriteDeadline(time.Time{}) // Clear deadline

			if encodeErr != nil {
				logCtxCmd.Error("Failed to send IPC response", "error", encodeErr)
				// If we can't send response, the connection is likely broken, exit handler
				return
			}
			logCtxCmd.Debug("Sent IPC response", "status", resp.Status)
		} else {
			// This case should ideally not be reached if processIPCCommand is correct
			logCtxCmd.Warn("No response generated for command")
		}

		// If the command was register_client and failed, clientInfo might still be nil.
		// If it succeeded, clientInfo should now be non-nil.
	}
}

// processIPCCommand routes IPC commands to specific handlers.
// It modifies clientInfo pointer if the command is 'register_client' and succeeds.
func (s *Service) processIPCCommand(conn net.Conn, cmd *ipc.Command, clientInfoPtr **ClientState) (*ipc.Response, error) {
	// Dereference pointer for easier access, but remember to update via pointer on success
	currentClientInfo := *clientInfoPtr

	switch cmd.Command {
	case "register_client":
		// Check if already registered (using the passed-in state)
		if currentClientInfo != nil {
			return nil, errors.New("client already registered on this connection")
		}

		var data ipc.RegisterClientData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid register_client data: %w", err)
		}

		// Add client using credentials from socket, passing reported PID for logging/check
		if err := s.addClientConn(conn, data.PID); err != nil {
			slog.Error("Failed to add client connection during registration", "error", err)
			return nil, fmt.Errorf("client registration failed: %w", err)
		}

		// Update the clientInfo pointer in the caller (handleIPCConnection)
		// Re-fetch the state from the map under lock to ensure consistency
		s.ipcClientsMu.RLock()
		newState, ok := s.ipcClients[conn]
		s.ipcClientsMu.RUnlock()
		if !ok || newState == nil {
			// This is an internal error state, registration seemed to succeed but state not found
			return nil, errors.New("internal error: client state not found after successful registration attempt")
		}
		*clientInfoPtr = newState // Update the pointer in the calling scope

		return ipc.NewOKResponse("Client registered successfully") // Return OK response, error is nil

	case "get_config":
		// No specific data needed from command
		cfg := s.getConfig() // Get thread-safe copy
		return ipc.NewOKResponse(ipc.GetConfigData{Config: cfg})

	case "update_ports":
		// This command requires the client to be registered (checked by caller)
		cfg := s.getConfig()
		if !cfg.EBPF.AllowDynamicPorts {
			return nil, errors.New("dynamic port updates disabled by configuration")
		}

		var data ipc.UpdatePortsData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid update_ports data: %w", err)
		}
		if s.bpfManager == nil {
			return nil, errors.New("BPF manager is not ready")
		}

		// Perform the update
		if err := s.bpfManager.UpdateTargetPorts(data.Ports); err != nil {
			// Log with client info if available
			uid := uint32(0)
			if currentClientInfo != nil {
				uid = currentClientInfo.UID
			}
			slog.Error("Failed to update target ports via IPC", "error", err, "client_uid", uid)
			return nil, fmt.Errorf("BPF map update failed: %w", err)
		}

		// Update in-memory config cache as well
		s.configMu.Lock()
		s.config.EBPF.TargetPorts = data.Ports // Directly update the slice
		s.configMu.Unlock()

		uid := uint32(0)
		if currentClientInfo != nil {
			uid = currentClientInfo.UID
		}
		slog.Info("Target ports updated via IPC", "ports", data.Ports, "client_uid", uid)
		return ipc.NewOKResponse("Ports updated successfully")

	case "get_status":
		// No specific data needed from command
		return s.getStatusResponse() // getStatusResponse handles response creation

	case "get_interfaces":
		// No specific data needed from command
		return s.getInterfacesResponse() // getInterfacesResponse handles response creation

	case "ping_status":
		// This command requires the client to be registered (checked by caller)
		var data ipc.PingStatusData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid ping_status data: %w", err)
		}

		s.ipcClientsMu.Lock()
		if state, ok := s.ipcClients[conn]; ok {
			state.LastPing = time.Now()
			state.LastStatus = data // Store the reported status
		} else {
			// Client might have disconnected between receiving command and processing here
			s.ipcClientsMu.Unlock()
			return nil, errors.New("client disconnected before status ping could be processed")
		}
		s.ipcClientsMu.Unlock()

		return ipc.NewOKResponse(nil) // No data needed in OK response for ping

	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Command)
	}
}

// getPeerCredFromConn extracts Unix socket peer credentials.
func getPeerCredFromConn(conn net.Conn) (*unix.Ucred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		// Check if it's a file-backed connection that can provide a descriptor
		fileConn, ok := conn.(interface{ File() (*os.File, error) })
		if !ok {
			return nil, fmt.Errorf("connection type %T does not support peer credentials", conn)
		}
		file, err := fileConn.File()
		if err != nil {
			return nil, fmt.Errorf("failed to get file descriptor from connection: %w", err)
		}
		defer file.Close() // Ensure the file descriptor is closed after use

		// Get credentials from the file descriptor
		ucred, err := unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return nil, fmt.Errorf("getsockopt SO_PEERCRED failed on file descriptor %d: %w", file.Fd(), err)
		}
		return ucred, nil
	}

	// It's a direct UnixConn, get its file descriptor safely
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get SyscallConn from UnixConn: %w", err)
	}
	var ucred *unix.Ucred
	var controlErr, sockoptErr error

	controlErr = rawConn.Control(func(fd uintptr) {
		ucred, sockoptErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})

	if controlErr != nil { // Error from rawConn.Control itself
		return nil, fmt.Errorf("rawConn.Control error getting peer credentials: %w", controlErr)
	}
	if sockoptErr != nil { // Error from GetsockoptUcred inside Control
		return nil, fmt.Errorf("getsockopt SO_PEERCRED failed: %w", sockoptErr)
	}
	if ucred == nil {
		// Should not happen if errors are nil, but check defensively
		return nil, errors.New("getsockopt SO_PEERCRED returned nil credentials without error")
	}
	return ucred, nil
}

// getStatusResponse constructs the data for the get_status command.
func (s *Service) getStatusResponse() (*ipc.Response, error) {
	cfg := s.getConfig() // Get thread-safe copy

	s.ipcClientsMu.RLock()
	clientDetails := make([]ipc.ClientInfo, 0, len(s.ipcClients))
	clientKerberosStates := make(map[uint32]ipc.ClientKerberosStatus) // Key: UID
	now := time.Now()
	for _, state := range s.ipcClients {
		// Add basic client info
		clientDetails = append(clientDetails, ipc.ClientInfo{PID: state.PID, UID: state.UID})
		// Add Kerberos status if the last ping was recent enough
		if !state.LastPing.IsZero() && now.Sub(state.LastPing) < clientStatusTTL {
			clientKerberosStates[state.UID] = state.LastStatus.KerberosStatus // Use UID as key
		}
	}
	clientCount := len(s.ipcClients)
	s.ipcClientsMu.RUnlock()

	statusData := ipc.GetStatusData{
		Status:               "running", // Assume running unless BPF issues found
		ActiveInterface:      cfg.EBPF.Interface,
		ActivePorts:          cfg.EBPF.TargetPorts,
		LoadMode:             cfg.EBPF.LoadMode,
		UptimeSeconds:        int64(time.Since(startTime).Seconds()),
		ServiceVersion:       version,
		ConnectedClients:     clientCount,
		ClientDetails:        clientDetails,        // Include details
		ClientKerberosStates: clientKerberosStates, // Include recent Kerberos statuses
	}

	// Get current BPF stats
	if s.bpfManager != nil {
		_, matched, err := s.bpfManager.GetStats()
		if err != nil {
			slog.Warn("Failed to get eBPF stats for status response", "error", err)
			statusData.Status = "degraded" // Mark as degraded if stats fail
		} else {
			statusData.MatchedConns = matched.Packets // Use Packets field for matched connections
		}
	} else {
		statusData.Status = "degraded" // BPF manager missing is a problem
	}

	return ipc.NewOKResponse(statusData)
}

// getInterfacesResponse retrieves available network interfaces.
func (s *Service) getInterfacesResponse() (*ipc.Response, error) {
	interfaces, err := ebpf.GetAvailableInterfaces()
	if err != nil {
		slog.Error("Failed to get network interfaces for response", "error", err)
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	currentInterface := s.getConfig().EBPF.Interface // Get from config
	data := ipc.GetInterfacesData{Interfaces: interfaces, CurrentInterface: currentInterface}
	return ipc.NewOKResponse(data)
}

// getConfig returns a thread-safe copy of the current configuration.
func (s *Service) getConfig() config.Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	// Create a copy of the config struct
	cfgCopy := *s.config
	// Deep copy slices/maps if they could be mutated elsewhere after returning
	if s.config.EBPF.TargetPorts != nil {
		cfgCopy.EBPF.TargetPorts = make([]int, len(s.config.EBPF.TargetPorts))
		copy(cfgCopy.EBPF.TargetPorts, s.config.EBPF.TargetPorts)
	} else {
		cfgCopy.EBPF.TargetPorts = []int{} // Ensure it's non-nil
	}
	// Copy other slices/maps if necessary
	return cfgCopy
}

// reloadConfig handles SIGHUP to reload configuration from disk.
func (s *Service) reloadConfig() error {
	slog.Info("Reloading configuration...", "path", s.configPath)
	newCfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	// --- Apply configuration changes ---
	// 1. Update logging immediately
	setupLogging(newCfg.LogLevel, newCfg.LogPath)
	slog.Info("Logging reconfigured based on reloaded settings.") // Use new logger

	// 2. Update BPF target ports if changed and allowed
	configChanged := false  // Flag to track if any relevant config changed
	oldCfg := s.getConfig() // Get copy of old config before swapping

	if newCfg.EBPF.AllowDynamicPorts && !equalIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfg.EBPF.TargetPorts) {
		slog.Info("Applying updated target ports from reloaded configuration...", "ports", newCfg.EBPF.TargetPorts)
		if s.bpfManager != nil {
			if err := s.bpfManager.UpdateTargetPorts(newCfg.EBPF.TargetPorts); err != nil {
				slog.Error("Failed to update target ports on config reload", "error", err)
				// Decide on error handling: revert? mark degraded? For now, just log.
			} else {
				slog.Info("Target ports successfully updated in BPF map.")
				configChanged = true
			}
		} else {
			slog.Warn("Cannot update target ports: BPF manager not initialized.")
		}
	} else if !newCfg.EBPF.AllowDynamicPorts && !equalIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfg.EBPF.TargetPorts) {
		slog.Warn("Target ports changed in config, but dynamic updates are disabled. Ports remain unchanged in BPF.", "config_ports", newCfg.EBPF.TargetPorts)
	}

	// 3. Check for changes requiring restart
	if oldCfg.EBPF.NotificationChannelSize != newCfg.EBPF.NotificationChannelSize {
		slog.Warn("Config reload detected change in 'ebpf.notification_channel_size', requires service restart to take effect.")
	}
	if oldCfg.EBPF.StatsInterval != newCfg.EBPF.StatsInterval {
		slog.Warn("Config reload detected change in 'ebpf.stats_interval', requires service restart to take effect.")
		// TODO: Could potentially update ticker in statsUpdater if needed
	}
	if oldCfg.SocketPath != newCfg.SocketPath {
		slog.Warn("Config reload detected change in 'socket_path', requires service restart to take effect.")
	}
	if oldCfg.ShutdownTimeout != newCfg.ShutdownTimeout {
		slog.Info("Shutdown timeout updated.", "old", oldCfg.ShutdownTimeout, "new", newCfg.ShutdownTimeout)
		// No restart needed, will be used on next shutdown
		configChanged = true
	}

	// 4. Update the main config struct under lock
	s.configMu.Lock()
	s.config = newCfg
	s.configMu.Unlock()

	// 5. Notify clients about config changes? (Optional)
	// Could send an IPC message to clients telling them to fetch new config.
	// if configChanged {
	//   s.notifyClientsOfConfigChange()
	// }

	slog.Info("Configuration reload finished.")
	return nil
}

// Shutdown performs graceful shutdown of the service components.
func (s *Service) Shutdown(ctx context.Context) {
	s.stopOnce.Do(func() {
		slog.Info("Initiating graceful shutdown...")

		// 1. Close IPC listener to stop accepting new clients
		if s.ipcListener != nil {
			slog.Debug("Closing IPC listener...")
			if err := s.ipcListener.Close(); err != nil {
				slog.Error("Error closing IPC listener", "error", err)
			}
		}

		// 2. Close existing client connections
		s.ipcClientsMu.Lock()
		connsToClose := make([]net.Conn, 0, len(s.ipcClients))
		for c := range s.ipcClients {
			connsToClose = append(connsToClose, c)
		}
		s.ipcClients = make(map[net.Conn]*ClientState) // Clear map immediately
		s.ipcClientsMu.Unlock()

		slog.Debug("Closing active IPC client connections...", "count", len(connsToClose))
		var closeWg sync.WaitGroup
		closeWg.Add(len(connsToClose))
		for _, c := range connsToClose {
			go func(connToClose net.Conn) {
				defer closeWg.Done()
				// Set a deadline for closing? Probably not necessary.
				if err := connToClose.Close(); err != nil {
					// Log error but continue shutdown
					if !errors.Is(err, net.ErrClosed) {
						slog.Warn("Error closing client connection during shutdown", "remote_addr", connToClose.RemoteAddr(), "error", err)
					}
				}
			}(c)
		}
		// Wait for connections to close, but with a timeout from the context
		closeDone := make(chan struct{})
		go func() {
			closeWg.Wait()
			close(closeDone)
		}()
		select {
		case <-closeDone:
			slog.Debug("Finished closing client connections.")
		case <-ctx.Done():
			slog.Warn("Timeout waiting for client connections to close during shutdown.")
		}

		// 3. Close BPF Manager (detaches programs, closes maps)
		if s.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := s.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager during shutdown", "error", err)
			} else {
				slog.Debug("BPF manager closed.")
			}
		}

		// 4. Close notification channel (after BPF manager closes its writer)
		if s.notificationChan != nil {
			slog.Debug("Closing notification channel...")
			// Add safety check in case it was already closed
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Debug("Notification channel already closed or panic during close.", "panic", r)
					}
				}()
				close(s.notificationChan)
			}()
			s.notificationChan = nil // Clear reference
		}

		slog.Info("Shutdown sequence complete. Waiting for remaining tasks via main WaitGroup...")
	})
}

// --- Utility Functions ---

// equalIntSliceUnordered checks if two integer slices contain the same elements, order agnostic.
func equalIntSliceUnordered(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	// Handle nil slices explicitly if necessary, though len check covers most cases
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) == 0 {
		return true // Both empty or nil handled above
	}

	// Use a map to count elements in slice 'a'
	counts := make(map[int]int, len(a))
	for _, x := range a {
		counts[x]++
	}
	// Decrement counts for elements in slice 'b'
	for _, x := range b {
		if counts[x] == 0 {
			return false // Element in b not in a, or count mismatch
		}
		counts[x]--
	}
	// If all counts are zero, the slices are equivalent
	// (No need to check explicitly, if loop finished, counts must match)
	return true
}

// isTimeoutError checks if an error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// Check for net.Error timeout
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Check for context deadline exceeded (often wraps timeout errors)
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

// isConnectionClosedErr checks for common network errors indicating closure.
func isConnectionClosedErr(err error) bool {
	if err == nil {
		return false
	}
	// Standard library errors
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// Common syscall errors indicating closure
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}

	// Check error strings for common messages (less reliable but helpful)
	errMsg := err.Error()
	if strings.Contains(errMsg, "use of closed network connection") ||
		strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "connection reset by peer") ||
		strings.Contains(errMsg, "forcibly closed by the remote host") || // Windows specific
		strings.Contains(errMsg, "socket is not connected") { // Can happen with unix sockets
		return true
	}

	// Unwrap net.OpError to check underlying syscall errors
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Check specific syscall errors wrapped by OpError
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, syscall.EPIPE) || errors.Is(sysErr.Err, syscall.ECONNRESET) || errors.Is(sysErr.Err, syscall.ENOTCONN) {
				return true
			}
		}
		// Check common underlying error string within OpError
		if opErr.Err != nil && opErr.Err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}
