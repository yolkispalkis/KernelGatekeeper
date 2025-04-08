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

	"golang.org/x/sys/unix"

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
	PID        uint32
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
	notificationChan chan ebpf.NotificationTuple // Channel for BPF notifications
}

func main() {
	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			// Ensure panic is logged, especially if slog isn't fully set up
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
	// Use default path if flag isn't set correctly (though flag has default)
	cfgPath := "/etc/kernelgatekeeper/config.yaml" // Default path
	if configPath != nil && *configPath != "" {
		cfgPath = *configPath
	}
	initialCfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		// Log to stderr as slog might not be configured yet
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
	notifChanSize := initialCfg.EBPF.NotificationChannelSize
	if notifChanSize <= 0 {
		slog.Warn("ebpf.notification_channel_size invalid, using default", "configured", notifChanSize, "default", defaultNotificationChanSize)
		notifChanSize = defaultNotificationChanSize
	}
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
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), svc.getConfig().ShutdownTimeout)
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
			// Log fallback to stderr using a temporary logger
			tempLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			tempLogger.Error("Failed to open configured log file, falling back to stderr", "path", logPath, "error", err)
		} else {
			logWriter = logFile
			// Consider closing the file? For long-running service, maybe not needed until shutdown.
		}
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level <= slog.LevelDebug, // Add source info only for debug
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
			// This is likely fatal if BPF manager can't start its core tasks
			slog.Error("FATAL: Failed to start BPF manager tasks", "error", err)
			// Consider triggering shutdown?
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
		slog.Error("FATAL: Failed to start IPC listener", "error", err)
		// If IPC fails to start, service cannot function
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

			slog.Info("Service Stats",
				"connected_clients", clientCount,
				"bpf_notif_chan_len", notifChanLen,
				"bpf_notif_chan_cap", notifChanCap,
				"bpf_notif_chan_util", fmt.Sprintf("%.2f%%", float64(notifChanLen)*100/float64(notifChanCap)),
			)
			// Log warning if channel is getting full
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
		case notification, ok := <-s.notificationChan:
			if !ok {
				slog.Info("BPF notification channel closed.")
				// This might happen during shutdown, or if the BPF reader failed catastrophically.
				return
			}

			logCtx := slog.With("src_ip", notification.SrcIP, "dst_ip", notification.DstIP, "dst_port", notification.DstPort)
			logCtx.Debug("Received BPF notification tuple")

			// Find PID associated with the connection tuple from the BPF map
			pid, err := s.bpfManager.GetConnectionPID(notification)
			if err != nil {
				// This can happen if the process exits quickly after connecting
				logCtx.Warn("Could not get PID for connection tuple (process likely exited?)", "error", err)
				continue
			}
			logCtx = logCtx.With("pid", pid)

			// Find UID from the PID
			uid, err := ebpf.GetUidFromPid(pid)
			if err != nil {
				// Process might have exited between getting PID and getting UID
				logCtx.Warn("Could not get UID for PID (process likely exited?)", "error", err)
				continue
			}
			logCtx = logCtx.With("uid", uid)

			// Find the registered client connection for this UID
			s.ipcClientsMu.RLock()
			clientConn := s.findClientConnByUID_nolock(uid) // Use nolock version
			s.ipcClientsMu.RUnlock()

			if clientConn == nil {
				logCtx.Debug("No registered client found for UID")
				// Maybe log Warn if this happens frequently?
				continue
			}

			logCtx.Info("Found registered client for connection, sending notification.")

			// Prepare and send the notification command over IPC
			ipcNotifData := ipc.NotifyAcceptData{
				// Convert IPs to strings for JSON
				SrcIP:    notification.SrcIP.String(),
				DstIP:    notification.DstIP.String(),
				SrcPort:  notification.SrcPort,
				DstPort:  notification.DstPort,
				Protocol: notification.Protocol,
			}
			ipcCmd, err := ipc.NewCommand("notify_accept", ipcNotifData)
			if err != nil {
				logCtx.Error("Failed to create IPC notification command", "error", err)
				continue // Should not happen with valid data
			}

			// Send asynchronously to avoid blocking the notification loop
			s.sendToClient(clientConn, ipcCmd)
		}
	}
}

// findClientConnByUID_nolock finds the client connection for a given UID. Caller must hold ipcClientsMu (Read).
func (s *Service) findClientConnByUID_nolock(uid uint32) net.Conn {
	for conn, state := range s.ipcClients {
		if state.UID == uid {
			return conn // Return the connection object
		}
	}
	return nil // Not found
}

// sendToClient sends an IPC command to a specific client connection asynchronously.
// It handles potential write errors and removes the client if sending fails.
func (s *Service) sendToClient(conn net.Conn, cmd *ipc.Command) {
	go func(c net.Conn, command *ipc.Command) {
		// Get client UID for logging before potentially removing
		clientUID := s.getClientUID(c)
		logCtx := slog.With("cmd", command.Command, "client_uid", clientUID)

		encoder := json.NewEncoder(c)
		// Set a reasonable write deadline
		c.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
		err := encoder.Encode(command)
		c.SetWriteDeadline(time.Time{}) // Clear deadline immediately

		if err != nil {
			// Log error and remove the client connection
			// Don't log error if it's just context cancellation during shutdown
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || isConnectionClosedErr(err) {
				logCtx.Info("IPC send cancelled or connection closed during send (likely shutdown)", "error", err)
			} else {
				logCtx.Warn("Failed to send command to client, removing client.", "error", err)
				// Remove the connection from the map
				s.removeClientConn(c)
			}
		} else {
			logCtx.Debug("Sent command to client successfully.")
		}
	}(conn, cmd)
}

// getClientUID retrieves the UID associated with a client connection.
func (s *Service) getClientUID(conn net.Conn) uint32 {
	s.ipcClientsMu.RLock()
	defer s.ipcClientsMu.RUnlock()
	if state, ok := s.ipcClients[conn]; ok {
		return state.UID
	}
	return 0 // Return 0 or some indicator for not found
}

// startIPCListener sets up and runs the Unix domain socket listener for client connections.
func (s *Service) startIPCListener(ctx context.Context) error {
	socketPath := s.getConfig().SocketPath
	dir := filepath.Dir(socketPath)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0750); err != nil { // Permissions suitable for root/group access
		return fmt.Errorf("failed to create IPC directory %s: %w", dir, err)
	}

	// Remove stale socket file if it exists
	// Use Stat first to check type, avoid removing directories etc.
	if fi, err := os.Stat(socketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("existing file at socket path %s is not a socket", socketPath)
		}
		// Attempt removal
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("failed to remove existing IPC socket %s: %w", socketPath, err)
		}
		slog.Info("Removed stale IPC socket file", "path", socketPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		// Error stating the file other than not existing
		return fmt.Errorf("failed to stat IPC socket path %s: %w", socketPath, err)
	}

	// Listen on the Unix socket
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on IPC socket %s: %w", socketPath, err)
	}
	s.ipcListener = l // Store the listener

	// Set permissions on the socket file
	// 0660 allows user and group (root and kg_users?) - Requires group setup.
	// Using 0666 for now as per original code, but flagged for security review.
	// TODO: SECURITY: Change permissions to 0660 and manage group ownership.
	if err := os.Chmod(socketPath, 0666); err != nil {
		l.Close()             // Close listener if chmod fails
		os.Remove(socketPath) // Clean up socket file
		return fmt.Errorf("failed to chmod IPC socket %s to 0666: %w", socketPath, err)
	}
	// TODO: SECURITY: Chown socketPath to root:kg_users group.

	slog.Info("IPC listener started", "path", socketPath, "permissions", "0666") // Update log if permissions change

	// Goroutine to close listener on context cancellation
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		slog.Info("Closing IPC listener due to context cancellation...")
		s.ipcListener.Close() // Closing the listener unblocks Accept
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
				// Log other accept errors and continue (maybe with a small delay)
				slog.Error("IPC accept failed", "error", err)
				// Add delay to prevent potential tight loop on persistent errors
				select {
				case <-time.After(100 * time.Millisecond):
					continue
				case <-ctx.Done(): // Check context while delaying
					return
				}
			}
			// Handle accepted connection in a new goroutine
			s.wg.Add(1) // Increment wait group for the handler goroutine
			go func(c net.Conn) {
				defer s.wg.Done()             // Decrement wait group when handler finishes
				s.handleIPCConnection(ctx, c) // Pass context to handler
			}(conn)
		}
	}()
	return nil
}

// addClientConn adds a new client connection to the map.
func (s *Service) addClientConn(conn net.Conn, uid uint32, pid uint32) {
	s.ipcClientsMu.Lock()
	defer s.ipcClientsMu.Unlock()

	// Remove existing entry for this conn if any (shouldn't happen)
	if _, exists := s.ipcClients[conn]; exists {
		slog.Warn("Client connection already exists in map during add? Removing old.", "remote_addr", conn.RemoteAddr())
		delete(s.ipcClients, conn)
	}

	s.ipcClients[conn] = &ClientState{
		UID:      uid,
		PID:      pid,
		LastPing: time.Now(), // Initialize LastPing on registration
	}
	clientCount := len(s.ipcClients)
	slog.Info("IPC client registered and added", "remote_addr", conn.RemoteAddr(), "uid", uid, "pid", pid, "total_clients", clientCount)
}

// removeClientConn removes a client connection from the map and closes it.
func (s *Service) removeClientConn(conn net.Conn) {
	s.ipcClientsMu.Lock()
	state, ok := s.ipcClients[conn]
	if ok {
		delete(s.ipcClients, conn)
	}
	clientCount := len(s.ipcClients)
	s.ipcClientsMu.Unlock() // Unlock before closing connection

	if ok {
		slog.Info("IPC client removed", "remote_addr", conn.RemoteAddr(), "uid", state.UID, "pid", state.PID, "total_clients", clientCount)
	} else {
		slog.Debug("Attempted to remove non-existent or already removed IPC client", "remote_addr", conn.RemoteAddr())
	}
	conn.Close() // Close the connection regardless
}

// getClientCount returns the current number of connected clients.
func (s *Service) getClientCount() int {
	s.ipcClientsMu.RLock()
	defer s.ipcClientsMu.RUnlock()
	return len(s.ipcClients)
}

// handleIPCConnection reads commands from a client connection and processes them.
func (s *Service) handleIPCConnection(ctx context.Context, conn net.Conn) {
	clientAddr := conn.RemoteAddr().String() // Get address for logging
	logCtx := slog.With("client_addr", clientAddr)
	logCtx.Info("Handling new IPC connection")

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var clientInfo *ClientState // Store client state once registered

	// Ensure connection is removed on exit
	defer func() {
		// Check if client was registered before removing
		s.ipcClientsMu.RLock()
		_, registered := s.ipcClients[conn]
		s.ipcClientsMu.RUnlock()
		if registered {
			s.removeClientConn(conn) // Use the removal function which also closes
		} else {
			conn.Close() // Ensure close if never registered
		}
		logCtx.Info("Finished handling IPC connection")
	}()

	// Loop reading commands
	for {
		select {
		case <-ctx.Done(): // Check for global shutdown
			logCtx.Info("Closing IPC handler due to service shutdown.")
			return
		default:
			// Proceed with reading
		}

		var cmd ipc.Command
		// Set read deadline to detect inactive/hung clients
		conn.SetReadDeadline(time.Now().Add(ipcReadIdleTimeout)) // Use the defined constant
		err := decoder.Decode(&cmd)
		conn.SetReadDeadline(time.Time{}) // Clear deadline

		if err != nil {
			// Handle read errors
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isConnectionClosedErr(err) {
				logCtx.Info("IPC connection closed by client or network.")
			} else if isTimeoutError(err) {
				logCtx.Warn("IPC connection timeout waiting for command. Closing connection.")
			} else {
				// Log other decoding errors
				logCtx.Error("Failed to decode IPC command", "error", err)
			}
			return // Exit handler on any error
		}

		// Log received command
		logCtxCmd := logCtx.With("command", cmd.Command)
		if clientInfo != nil {
			logCtxCmd = logCtxCmd.With("uid", clientInfo.UID, "pid", clientInfo.PID)
		}
		logCtxCmd.Info("Received IPC command")

		// Process the command
		var resp *ipc.Response
		var procErr error

		// Check registration status for commands requiring it
		isRegistered := clientInfo != nil
		requiresRegistration := cmd.Command != "register_client" // Only register doesn't require prior registration

		if requiresRegistration && !isRegistered {
			procErr = errors.New("client not registered")
			logCtxCmd.Warn("Command rejected: client not registered")
		} else {
			// Process the specific command
			resp, procErr = s.processIPCCommand(conn, &cmd, &clientInfo) // Pass pointer to update clientInfo on register
		}

		// Prepare response (use ErrorResponse if processing failed)
		if procErr != nil {
			resp = ipc.NewErrorResponse(procErr.Error())
			logCtxCmd.Error("Error processing IPC command", "error", procErr)
		} else if resp == nil {
			// Should not happen if procErr is nil, but defensive
			logCtxCmd.Error("Internal error: processIPCCommand returned nil response and nil error")
			resp = ipc.NewErrorResponse("internal server error processing command")
		}

		// Send response
		conn.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
		encodeErr := encoder.Encode(resp)
		conn.SetWriteDeadline(time.Time{})

		if encodeErr != nil {
			logCtxCmd.Error("Failed to send IPC response", "error", encodeErr)
			return // Exit handler if we can't send response
		}
		logCtxCmd.Debug("Sent IPC response", "status", resp.Status)
	}
}

// processIPCCommand routes IPC commands to specific handlers.
// It modifies clientInfo if the command is 'register_client'.
func (s *Service) processIPCCommand(conn net.Conn, cmd *ipc.Command, clientInfo **ClientState) (*ipc.Response, error) {
	switch cmd.Command {
	case "register_client":
		// Check if already registered on this connection
		if *clientInfo != nil {
			return nil, errors.New("client already registered on this connection")
		}

		var data ipc.RegisterClientData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid register_client data: %w", err)
		}

		// Get credentials (UID/PID) from the socket itself for security
		peerCred, err := getPeerCredFromConn(conn)
		if err != nil {
			slog.Error("Failed to get peer credentials for registering client", "error", err)
			return nil, errors.New("cannot verify client credentials")
		}
		uid := peerCred.Uid
		pid := peerCred.Pid // Get PID from credentials as well (int32)

		// Check if PID from credentials matches PID from message (optional sanity check)
		// Cast both to int32 for comparison
		if int32(data.PID) != pid {
			slog.Warn("Client reported PID differs from socket credential PID", "reported_pid", data.PID, "credential_pid", pid)
			// Decide whether to reject or just log. Using credential PID is safer.
		}

		// Add client to the map - cast pid to uint32 here
		s.addClientConn(conn, uid, uint32(pid))

		// Update the clientInfo pointer in the caller (handleIPCConnection)
		s.ipcClientsMu.RLock()
		*clientInfo = s.ipcClients[conn] // Get the newly added state
		s.ipcClientsMu.RUnlock()

		if *clientInfo == nil {
			// This should not happen if addClientConn succeeded
			return nil, errors.New("internal error: client state not found after registration")
		}

		return ipc.NewOKResponse("Client registered successfully")

	case "get_config":
		// Registration check happens in handleIPCConnection
		cfg := s.getConfig() // Get thread-safe copy
		return ipc.NewOKResponse(ipc.GetConfigData{Config: cfg})

	case "update_ports":
		// Registration check happens in handleIPCConnection
		cfg := s.getConfig() // Get current config for validation
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

		// Apply the port update to the BPF map
		if err := s.bpfManager.UpdateTargetPorts(data.Ports); err != nil {
			slog.Error("Failed to update target ports via IPC", "error", err, "client_uid", (*clientInfo).UID)
			return nil, fmt.Errorf("BPF map update failed: %w", err)
		}

		// Update the in-memory config as well
		s.configMu.Lock()
		s.config.EBPF.TargetPorts = data.Ports // Store the validated & applied ports
		s.configMu.Unlock()

		slog.Info("Target ports updated via IPC", "ports", data.Ports, "client_uid", (*clientInfo).UID)
		return ipc.NewOKResponse("Ports updated successfully")

	case "get_status":
		// Registration check happens in handleIPCConnection
		return s.getStatusResponse()

	case "get_interfaces":
		// Registration check happens in handleIPCConnection
		return s.getInterfacesResponse()

	case "ping_status":
		// Registration check happens in handleIPCConnection
		var data ipc.PingStatusData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid ping_status data: %w", err)
		}
		// Update client state
		s.ipcClientsMu.Lock()
		if state, ok := s.ipcClients[conn]; ok {
			state.LastPing = time.Now()
			state.LastStatus = data // Store the received status
		}
		s.ipcClientsMu.Unlock()

		// No data needed in OK response for ping
		return ipc.NewOKResponse(nil)

	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Command)
	}
}

// getPeerCredFromConn extracts Unix socket peer credentials.
func getPeerCredFromConn(conn net.Conn) (*unix.Ucred, error) {
	// Check if it's a UnixConn
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		// If not directly a UnixConn, try to get the underlying file descriptor
		fileConn, ok := conn.(interface {
			File() (*os.File, error)
		})
		if !ok {
			return nil, fmt.Errorf("connection type %T does not support peer credentials", conn)
		}
		file, err := fileConn.File()
		if err != nil {
			return nil, fmt.Errorf("failed to get file descriptor from connection: %w", err)
		}
		defer file.Close() // Close the duplicated fd

		// Get credentials from the file descriptor
		ucred, err := unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return nil, fmt.Errorf("getsockopt SO_PEERCRED failed on file descriptor: %w", err)
		}
		return ucred, nil
	}

	// It's already a UnixConn, get credentials via File() method which is more reliable.
	file, fileErr := unixConn.File()
	if fileErr != nil {
		return nil, fmt.Errorf("failed to get file descriptor from unixConn: %w", fileErr)
	}
	defer file.Close()

	ucred, err := unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED failed via file descriptor: %w", err)
	}
	return ucred, nil
}

// getStatusResponse constructs the data for the get_status command.
func (s *Service) getStatusResponse() (*ipc.Response, error) {
	cfg := s.getConfig() // Get thread-safe copy

	// Collect client info and status
	s.ipcClientsMu.RLock()
	clientDetails := make([]ipc.ClientInfo, 0, len(s.ipcClients))
	clientKerberosStates := make(map[uint32]ipc.ClientKerberosStatus)
	for _, state := range s.ipcClients {
		clientDetails = append(clientDetails, ipc.ClientInfo{PID: state.PID, UID: state.UID})
		// Only include Kerberos status if the client reported it recently
		if time.Since(state.LastPing) < clientStatusTTL { // Use the defined constant
			clientKerberosStates[state.UID] = state.LastStatus.KerberosStatus
		}
	}
	clientCount := len(s.ipcClients)
	s.ipcClientsMu.RUnlock()

	statusData := ipc.GetStatusData{
		Status:               "running", // TODO: Add logic for "degraded" status if needed
		ActiveInterface:      cfg.EBPF.Interface,
		ActivePorts:          cfg.EBPF.TargetPorts,
		LoadMode:             cfg.EBPF.LoadMode,
		UptimeSeconds:        int64(time.Since(startTime).Seconds()),
		ServiceVersion:       version,
		ConnectedClients:     clientCount,
		ClientDetails:        clientDetails,
		ClientKerberosStates: clientKerberosStates,
		// MatchedBytes removed as it's not collected currently
	}

	// Get BPF stats if available
	if s.bpfManager != nil {
		_, matched, err := s.bpfManager.GetStats() // Ignoring total stats for now
		if err != nil {
			slog.Warn("Failed to get eBPF stats for status response", "error", err)
			statusData.Status = "degraded" // Indicate issue if stats fail
		} else {
			statusData.MatchedConns = matched.Packets
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
		// Don't fail the whole command, return empty list? Or error? Return error.
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	currentInterface := s.getConfig().EBPF.Interface // Informational
	data := ipc.GetInterfacesData{Interfaces: interfaces, CurrentInterface: currentInterface}
	return ipc.NewOKResponse(data)
}

// getConfig returns a thread-safe copy of the current configuration.
func (s *Service) getConfig() config.Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	// Create a shallow copy
	cfgCopy := *s.config
	// Create deep copies of slices/maps to prevent modification races
	// if they are modified directly elsewhere (TargetPorts is handled)
	if cfgCopy.EBPF.TargetPorts != nil {
		cfgCopy.EBPF.TargetPorts = append([]int{}, s.config.EBPF.TargetPorts...)
	} else {
		cfgCopy.EBPF.TargetPorts = []int{} // Ensure it's not nil
	}
	// Deep copy other slices/maps if needed
	return cfgCopy
}

// reloadConfig handles SIGHUP to reload configuration from disk.
func (s *Service) reloadConfig() error {
	slog.Info("Reloading configuration...", "path", s.configPath)
	newCfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	s.configMu.Lock()
	oldCfg := s.config // Keep old config for comparison/rollback
	s.config = newCfg  // Atomically update the pointer
	s.configMu.Unlock()

	// Update logging based on new config
	// Note: This changes the global default logger
	setupLogging(newCfg.LogLevel, newCfg.LogPath)
	slog.Info("Logging reconfigured based on reloaded settings.")

	// Apply changes that can be applied dynamically
	if s.bpfManager != nil {
		// Update Target Ports if they changed and dynamic updates are allowed
		if newCfg.EBPF.AllowDynamicPorts && !equalIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfg.EBPF.TargetPorts) {
			slog.Info("Applying updated target ports from reloaded configuration...", "ports", newCfg.EBPF.TargetPorts)
			if err := s.bpfManager.UpdateTargetPorts(newCfg.EBPF.TargetPorts); err != nil {
				slog.Error("Failed to update target ports on config reload, BPF map may be inconsistent with config!", "error", err)
				// Should we revert the config change? For now, just log the error.
				// Reverting config might be complex if other changes were already applied.
				// s.configMu.Lock()
				// s.config.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts // Revert just the ports part
				// s.configMu.Unlock()
			} else {
				slog.Info("Target ports successfully updated in BPF map.")
			}
		}

		// Update Notification Channel Size? Requires recreating the channel and potentially BPF manager - skip for now.
		if oldCfg.EBPF.NotificationChannelSize != newCfg.EBPF.NotificationChannelSize {
			slog.Warn("Configuration reload detected change in 'ebpf.notification_channel_size', but this requires a service restart to take effect.")
		}

		// Add other dynamic updates here if needed (e.g., stats interval)

	} else {
		slog.Warn("Cannot apply BPF config changes on reload: BPF manager not initialized.")
	}

	// TODO: Notify clients about config changes if necessary?
	// Currently, clients fetch config periodically.

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
			s.ipcListener.Close()
		}

		// 2. Close existing client connections
		s.ipcClientsMu.Lock()
		connsToClose := make([]net.Conn, 0, len(s.ipcClients))
		for c := range s.ipcClients {
			connsToClose = append(connsToClose, c)
		}
		// Clear map immediately inside lock
		s.ipcClients = make(map[net.Conn]*ClientState)
		s.ipcClientsMu.Unlock()

		slog.Debug("Closing active IPC client connections...", "count", len(connsToClose))
		closeWg := sync.WaitGroup{}
		closeWg.Add(len(connsToClose))
		for _, c := range connsToClose {
			go func(connToClose net.Conn) {
				defer closeWg.Done()
				connToClose.Close() // Close connections concurrently
			}(c)
		}
		closeWg.Wait() // Wait for all closes to finish
		slog.Debug("Finished closing client connections.")

		// 3. Close BPF Manager (detaches programs, closes maps, stops readers)
		if s.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := s.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager during shutdown", "error", err)
			} else {
				slog.Debug("BPF manager closed.")
			}
		}

		// 4. Close notification channel (signal processor to stop)
		// Ensure channel is closed only once and after BPF manager reader has stopped.
		// BPFManager.Close() should handle stopping the reader that writes here.
		// Closing the channel signals the processor `processBPFNotifications` to exit its range loop.
		// Do this *after* BPF manager close guarantees no more writes.
		if s.notificationChan != nil {
			slog.Debug("Closing notification channel...")
			close(s.notificationChan)
			s.notificationChan = nil // Avoid double close
		}

		slog.Info("Shutdown sequence initiated. Waiting for remaining tasks to complete...")
		// Main loop waits for s.wg after this function returns
	})
}

// Close is a convenience method for shutdown (e.g., called via defer).
// Deprecated: Use Shutdown with context instead. Included for compatibility if used.
func (s *Service) Close() {
	slog.Warn("Service.Close() called directly, prefer Shutdown() with context.")
	shutdownTimeout := 5 * time.Second // Default shorter timeout for direct Close()
	if s.config != nil && s.config.ShutdownTimeout > 0 {
		shutdownTimeout = s.config.ShutdownTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	s.Shutdown(ctx)
}

// --- Utility Functions ---

// equalIntSliceUnordered checks if two integer slices contain the same elements, regardless of order.
func equalIntSliceUnordered(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	if (a == nil && b != nil) || (a != nil && b == nil) {
		return false // Handles case where one is nil and other is empty
	}
	if a == nil && b == nil {
		return true // Both nil
	}

	// Use a map to count elements in 'a'
	counts := make(map[int]int, len(a))
	for _, x := range a {
		counts[x]++
	}

	// Decrement counts for elements in 'b'
	for _, x := range b {
		if counts[x] == 0 {
			return false // Element in b not in a or too many occurrences
		}
		counts[x]--
	}

	// If all counts are zero, the slices are equal (ignoring order)
	// This check is implicitly covered by the previous loop if lengths are equal.
	return true
}

// isTimeoutError checks if an error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
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
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "use of closed network connection") ||
		strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "connection reset by peer") ||
		strings.Contains(errMsg, "forcibly closed by the remote host") ||
		strings.Contains(errMsg, "socket is not connected") {
		return true
	}
	if opErr, ok := err.(*net.OpError); ok {
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
			if errors.Is(sysErr.Err, syscall.EPIPE) || errors.Is(sysErr.Err, syscall.ECONNRESET) || errors.Is(sysErr.Err, syscall.ENOTCONN) {
				return true
			}
		}
		if opErr.Err != nil && opErr.Err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}
