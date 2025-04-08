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
			tempLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			tempLogger.Error("Failed to open configured log file, falling back to stderr", "path", logPath, "error", err)
		} else {
			logWriter = logFile
		}
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level <= slog.LevelDebug,
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
			slog.Error("FATAL: Failed to start BPF manager tasks", "error", err)
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

			slog.Info("Service Stats",
				"connected_clients", clientCount,
				"bpf_notif_chan_len", notifChanLen,
				"bpf_notif_chan_cap", notifChanCap,
				"bpf_notif_chan_util", fmt.Sprintf("%.2f%%", chanUtil),
			)
			if notifChanLen > (notifChanCap * 3 / 4) { // Over 75% full
				slog.Warn("BPF notification channel usage is high", "length", notifChanLen, "capacity", notifChanCap)
			}
		}
	}
}

// processBPFNotifications reads from the notification channel and forwards to the appropriate client.
// UPDATED to use PID from notification tuple.
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

			// Use original destination IP/Port from the notification tuple for logging context
			logCtx := slog.With(
				"src_ip", notification.SrcIP.String(), // Use String() for logging IPs
				"orig_dst_ip", notification.OrigDstIP.String(),
				"orig_dst_port", notification.OrigDstPort,
				"src_port", notification.SrcPort, // Include source port for context
			)
			logCtx.Debug("Received BPF notification tuple")

			// --- Get PID directly from the notification tuple ---
			pid_tgid := notification.PidTgid
			pid := uint32(pid_tgid & 0xFFFFFFFF) // Extract PID from lower 32 bits
			tgid := uint32(pid_tgid >> 32)       // Extract TGID from upper 32 bits (optional)

			if pid == 0 {
				logCtx.Warn("Received notification with zero PID, skipping.", "pid_tgid", pid_tgid)
				continue // Cannot proceed without a valid PID
			}
			logCtx = logCtx.With("pid", pid, "tgid", tgid) // Add pid/tgid to log context

			// Find UID from the PID using the existing helper function
			uid, err := ebpf.GetUidFromPid(pid)
			if err != nil {
				// This can happen if the process exits quickly after the connect4 hook runs
				logCtx.Warn("Could not get UID for PID (process likely exited?)", "error", err)
				continue // Skip if UID cannot be determined
			}
			logCtx = logCtx.With("uid", uid)

			// Find the registered client connection associated with this UID
			s.ipcClientsMu.RLock()
			clientConn := s.findClientConnByUID_nolock(uid)
			s.ipcClientsMu.RUnlock()

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
				DstIP:    notification.OrigDstIP.String(), // Original destination IP
				SrcPort:  notification.SrcPort,            // Actual source port
				DstPort:  notification.OrigDstPort,        // Original destination port
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
func (s *Service) sendToClient(conn net.Conn, cmd *ipc.Command) {
	go func(c net.Conn, command *ipc.Command) {
		clientUID := s.getClientUID(c)
		logCtx := slog.With("cmd", command.Command, "client_uid", clientUID)

		encoder := json.NewEncoder(c)
		c.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
		err := encoder.Encode(command)
		c.SetWriteDeadline(time.Time{}) // Clear deadline

		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || isConnectionClosedErr(err) {
				logCtx.Info("IPC send cancelled or connection closed during send", "error", err)
			} else {
				logCtx.Warn("Failed to send command to client, removing client.", "error", err)
			}
			// Remove the client connection on any send error
			s.removeClientConn(c)
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
	return 0 // Indicate not found
}

// startIPCListener sets up and runs the Unix domain socket listener.
func (s *Service) startIPCListener(ctx context.Context) error {
	socketPath := s.getConfig().SocketPath
	dir := filepath.Dir(socketPath)

	// Create directory if needed
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create IPC directory %s: %w", dir, err)
	}

	// Remove stale socket file
	if fi, err := os.Stat(socketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("existing file at socket path %s is not a socket", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("failed to remove existing IPC socket %s: %w", socketPath, err)
		}
		slog.Info("Removed stale IPC socket file", "path", socketPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to stat IPC socket path %s: %w", socketPath, err)
	}

	// Listen on the Unix socket
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on IPC socket %s: %w", socketPath, err)
	}
	s.ipcListener = l

	// Set permissions (TODO: Review security - 0660 might be better with group mgmt)
	if err := os.Chmod(socketPath, 0666); err != nil {
		l.Close()
		os.Remove(socketPath)
		return fmt.Errorf("failed to chmod IPC socket %s to 0666: %w", socketPath, err)
	}
	slog.Info("IPC listener started", "path", socketPath, "permissions", "0666")

	// Goroutine to close listener on context cancellation
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		slog.Info("Closing IPC listener due to context cancellation...")
		if s.ipcListener != nil {
			s.ipcListener.Close()
		}
	}()

	// Goroutine to accept incoming connections
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.ipcListener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					slog.Info("IPC listener closed, stopping accept loop.")
					return // Exit loop cleanly
				}
				slog.Error("IPC accept failed", "error", err)
				select {
				case <-time.After(100 * time.Millisecond):
					continue
				case <-ctx.Done():
					return
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

	// Optional: Compare reported PID with credential PID
	if int32(reportedPID) != credentialPID {
		slog.Warn("Client reported PID differs from socket credential PID",
			"reported_pid", reportedPID, "credential_pid", credentialPID)
		// Use credentialPID for internal state as it's more trustworthy
	}

	s.ipcClientsMu.Lock()
	defer s.ipcClientsMu.Unlock()

	if _, exists := s.ipcClients[conn]; exists {
		slog.Warn("Client connection already exists in map during add? Removing old.", "remote_addr", conn.RemoteAddr())
		delete(s.ipcClients, conn)
	}

	s.ipcClients[conn] = &ClientState{
		UID:      uid,
		PID:      uint32(credentialPID), // Store the trustworthy PID
		LastPing: time.Now(),
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
	s.ipcClientsMu.Unlock()

	if ok {
		slog.Info("IPC client removed", "remote_addr", conn.RemoteAddr(), "uid", state.UID, "pid", state.PID, "total_clients", clientCount)
	} else {
		slog.Debug("Attempted to remove non-existent or already removed IPC client", "remote_addr", conn.RemoteAddr())
	}
	conn.Close() // Close the connection
}

// getClientCount returns the current number of connected clients.
func (s *Service) getClientCount() int {
	s.ipcClientsMu.RLock()
	defer s.ipcClientsMu.RUnlock()
	return len(s.ipcClients)
}

// handleIPCConnection reads commands from a client connection and processes them.
func (s *Service) handleIPCConnection(ctx context.Context, conn net.Conn) {
	clientAddr := conn.RemoteAddr().String() // Use String() for logging clarity
	logCtx := slog.With("client_addr", clientAddr)
	logCtx.Info("Handling new IPC connection")

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var clientInfo *ClientState // Store client state once registered

	// Ensure connection is removed on exit
	defer func() {
		s.ipcClientsMu.RLock()
		_, registered := s.ipcClients[conn]
		s.ipcClientsMu.RUnlock()
		if registered {
			s.removeClientConn(conn)
		} else {
			conn.Close()
		}
		logCtx.Info("Finished handling IPC connection")
	}()

	// Loop reading commands
	for {
		select {
		case <-ctx.Done():
			logCtx.Info("Closing IPC handler due to service shutdown.")
			return
		default:
		}

		var cmd ipc.Command
		conn.SetReadDeadline(time.Now().Add(ipcReadIdleTimeout))
		err := decoder.Decode(&cmd)
		conn.SetReadDeadline(time.Time{}) // Clear deadline

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isConnectionClosedErr(err) {
				logCtx.Info("IPC connection closed by client or network.")
			} else if isTimeoutError(err) {
				logCtx.Warn("IPC connection timeout waiting for command. Closing connection.")
			} else {
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

		isRegistered := clientInfo != nil
		requiresRegistration := cmd.Command != "register_client"

		if requiresRegistration && !isRegistered {
			procErr = errors.New("client not registered")
			logCtxCmd.Warn("Command rejected: client not registered")
		} else {
			// Pass pointer to update clientInfo on register_client success
			resp, procErr = s.processIPCCommand(conn, &cmd, &clientInfo)
		}

		if procErr != nil {
			resp = ipc.NewErrorResponse(procErr.Error())
			logCtxCmd.Error("Error processing IPC command", "error", procErr)
		} else if resp == nil {
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
		if *clientInfo != nil {
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
		s.ipcClientsMu.RLock()
		*clientInfo = s.ipcClients[conn] // Get the newly added state
		s.ipcClientsMu.RUnlock()
		if *clientInfo == nil {
			return nil, errors.New("internal error: client state not found after registration")
		}
		return ipc.NewOKResponse("Client registered successfully")

	case "get_config":
		cfg := s.getConfig()
		return ipc.NewOKResponse(ipc.GetConfigData{Config: cfg})

	case "update_ports":
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
		if err := s.bpfManager.UpdateTargetPorts(data.Ports); err != nil {
			slog.Error("Failed to update target ports via IPC", "error", err, "client_uid", (*clientInfo).UID)
			return nil, fmt.Errorf("BPF map update failed: %w", err)
		}
		// Update in-memory config as well
		s.configMu.Lock()
		s.config.EBPF.TargetPorts = data.Ports
		s.configMu.Unlock()
		slog.Info("Target ports updated via IPC", "ports", data.Ports, "client_uid", (*clientInfo).UID)
		return ipc.NewOKResponse("Ports updated successfully")

	case "get_status":
		return s.getStatusResponse()

	case "get_interfaces":
		return s.getInterfacesResponse()

	case "ping_status":
		var data ipc.PingStatusData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid ping_status data: %w", err)
		}
		s.ipcClientsMu.Lock()
		if state, ok := s.ipcClients[conn]; ok {
			state.LastPing = time.Now()
			state.LastStatus = data
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
		// Handle case where it might be wrapped (less common for direct unix sockets)
		fileConn, ok := conn.(interface{ File() (*os.File, error) })
		if !ok {
			return nil, fmt.Errorf("connection type %T does not support peer credentials", conn)
		}
		file, err := fileConn.File()
		if err != nil {
			return nil, fmt.Errorf("failed to get file descriptor from connection: %w", err)
		}
		defer file.Close()
		return unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}

	// Directly use file descriptor from UnixConn
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get SyscallConn from UnixConn: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	err = rawConn.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil { // Error from rawConn.Control itself
		return nil, fmt.Errorf("rawConn.Control error getting peer credentials: %w", err)
	}
	if credErr != nil { // Error from GetsockoptUcred
		return nil, fmt.Errorf("getsockopt SO_PEERCRED failed: %w", credErr)
	}
	return cred, nil
}

// getStatusResponse constructs the data for the get_status command.
func (s *Service) getStatusResponse() (*ipc.Response, error) {
	cfg := s.getConfig() // Get thread-safe copy

	s.ipcClientsMu.RLock()
	clientDetails := make([]ipc.ClientInfo, 0, len(s.ipcClients))
	clientKerberosStates := make(map[uint32]ipc.ClientKerberosStatus)
	for _, state := range s.ipcClients {
		clientDetails = append(clientDetails, ipc.ClientInfo{PID: state.PID, UID: state.UID})
		if time.Since(state.LastPing) < clientStatusTTL {
			clientKerberosStates[state.UID] = state.LastStatus.KerberosStatus
		}
	}
	clientCount := len(s.ipcClients)
	s.ipcClientsMu.RUnlock()

	statusData := ipc.GetStatusData{
		Status:               "running", // Assume running, could be degraded if BPF fails
		ActiveInterface:      cfg.EBPF.Interface,
		ActivePorts:          cfg.EBPF.TargetPorts,
		LoadMode:             cfg.EBPF.LoadMode,
		UptimeSeconds:        int64(time.Since(startTime).Seconds()),
		ServiceVersion:       version,
		ConnectedClients:     clientCount,
		ClientDetails:        clientDetails,
		ClientKerberosStates: clientKerberosStates,
	}

	if s.bpfManager != nil {
		_, matched, err := s.bpfManager.GetStats() // Ignoring total stats for now
		if err != nil {
			slog.Warn("Failed to get eBPF stats for status response", "error", err)
			statusData.Status = "degraded"
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
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	currentInterface := s.getConfig().EBPF.Interface
	data := ipc.GetInterfacesData{Interfaces: interfaces, CurrentInterface: currentInterface}
	return ipc.NewOKResponse(data)
}

// getConfig returns a thread-safe copy of the current configuration.
func (s *Service) getConfig() config.Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	cfgCopy := *s.config
	// Deep copy slices/maps if needed
	if s.config.EBPF.TargetPorts != nil {
		cfgCopy.EBPF.TargetPorts = append([]int{}, s.config.EBPF.TargetPorts...)
	} else {
		cfgCopy.EBPF.TargetPorts = []int{}
	}
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
	oldCfg := s.config
	s.config = newCfg
	s.configMu.Unlock()

	setupLogging(newCfg.LogLevel, newCfg.LogPath) // Update logging
	slog.Info("Logging reconfigured based on reloaded settings.")

	// Apply dynamic changes
	if s.bpfManager != nil {
		if newCfg.EBPF.AllowDynamicPorts && !equalIntSliceUnordered(oldCfg.EBPF.TargetPorts, newCfg.EBPF.TargetPorts) {
			slog.Info("Applying updated target ports from reloaded configuration...", "ports", newCfg.EBPF.TargetPorts)
			if err := s.bpfManager.UpdateTargetPorts(newCfg.EBPF.TargetPorts); err != nil {
				slog.Error("Failed to update target ports on config reload", "error", err)
				// Consider reverting config or marking state as degraded
			} else {
				slog.Info("Target ports successfully updated in BPF map.")
			}
		}
		if oldCfg.EBPF.NotificationChannelSize != newCfg.EBPF.NotificationChannelSize {
			slog.Warn("Config reload detected change in 'ebpf.notification_channel_size', requires restart.")
		}
		// Update stats interval? Needs changes in BPFManager.Start/statsUpdater
	} else {
		slog.Warn("Cannot apply BPF config changes on reload: BPF manager not initialized.")
	}

	slog.Info("Configuration reload finished.")
	return nil
}

// Shutdown performs graceful shutdown of the service components.
func (s *Service) Shutdown(ctx context.Context) {
	s.stopOnce.Do(func() {
		slog.Info("Initiating graceful shutdown...")

		// Close IPC listener
		if s.ipcListener != nil {
			slog.Debug("Closing IPC listener...")
			s.ipcListener.Close()
		}

		// Close client connections
		s.ipcClientsMu.Lock()
		connsToClose := make([]net.Conn, 0, len(s.ipcClients))
		for c := range s.ipcClients {
			connsToClose = append(connsToClose, c)
		}
		s.ipcClients = make(map[net.Conn]*ClientState) // Clear map
		s.ipcClientsMu.Unlock()

		slog.Debug("Closing active IPC client connections...", "count", len(connsToClose))
		var closeWg sync.WaitGroup
		closeWg.Add(len(connsToClose))
		for _, c := range connsToClose {
			go func(connToClose net.Conn) { defer closeWg.Done(); connToClose.Close() }(c)
		}
		closeWg.Wait()
		slog.Debug("Finished closing client connections.")

		// Close BPF Manager
		if s.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := s.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager during shutdown", "error", err)
			} else {
				slog.Debug("BPF manager closed.")
			}
		}

		// Close notification channel (after BPF manager closes its writer)
		if s.notificationChan != nil {
			slog.Debug("Closing notification channel...")
			// Check if already closed by BPF manager shutdown internally if applicable
			// Or just close here assuming BPF manager stopped writing.
			// Add safety:
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Debug("Notification channel already closed.")
					}
				}()
				close(s.notificationChan)
			}()

			s.notificationChan = nil
		}

		slog.Info("Shutdown sequence initiated. Waiting for remaining tasks...")
	})
}

// --- Utility Functions ---

// equalIntSliceUnordered checks if two integer slices contain the same elements.
func equalIntSliceUnordered(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) == 0 {
		return true
	} // Both empty or nil handled above

	counts := make(map[int]int, len(a))
	for _, x := range a {
		counts[x]++
	}
	for _, x := range b {
		if counts[x] == 0 {
			return false
		}
		counts[x]--
	}
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
