package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	// Import gokrb5 client specifically
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/yolki/kernelgatekeeper/pkg/config"
	"github.com/yolki/kernelgatekeeper/pkg/ipc"
	"github.com/yolki/kernelgatekeeper/pkg/kerb"
	"github.com/yolki/kernelgatekeeper/pkg/proxy"
	"golang.org/x/sync/semaphore"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Global state variables
var (
	globalConfig           *config.Config // Current configuration
	globalConfigMu         sync.RWMutex   // Mutex for config access
	globalKerbClient       *kerb.KerberosClient
	globalProxyMgr         *proxy.ProxyManager
	globalShutdownOnce     sync.Once           // Ensures shutdown actions run only once
	globalWg               sync.WaitGroup      // Tracks active goroutines for graceful shutdown
	workerSemaphore        *semaphore.Weighted // Limits concurrent connection handling goroutines
	activeConnections      atomic.Int64        // Counter for active proxied connections
	globalCtx              context.Context     // Master context for the application
	globalCancel           context.CancelFunc  // Function to cancel the master context
	ipcConnection          net.Conn            // Current connection to the service
	ipcConnectionMu        sync.Mutex          // Mutex for accessing ipcConnection
	ipcConnectionState     atomic.Int32        // 0 = disconnected, 1 = connected
	ipcConnectionStateChan chan bool           // Signals connection state changes
)

// Constants
const (
	localListenPort         = 3129        // Port the client listens on for connections from BPF sockmap
	localListenAddr         = "127.0.0.1" // Address the client listens on
	maxConcurrentWorkers    = 200         // Max number of connections handled concurrently
	baseReconnectDelay      = 1 * time.Second
	maxReconnectDelay       = 60 * time.Second
	kerberosCheckInterval   = 5 * time.Minute
	configRefreshInterval   = 15 * time.Minute
	statusPingInterval      = 1 * time.Minute
	proxyConnectDialTimeout = 10 * time.Second // Timeout for dialing the actual proxy server
	proxyCONNECTTimeout     = 30 * time.Second // Timeout for the HTTP CONNECT request itself
	relayCopyTimeout        = 5 * time.Minute  // Timeout for inactivity during data relay
)

type clientFlags struct {
	socketPath     string
	showVersion    bool
	connectTimeout time.Duration // Timeout for initial connection to service socket
}

func main() {
	// Setup panic recovery
	defer func() {
		if r := recover(); r != nil {
			// Log panic to stderr before potentially closing slog output
			fmt.Fprintf(os.Stderr, "CLIENT PANIC: %v\n%s\n", r, string(debug.Stack()))
			// Ensure shutdown logic runs if possible
			triggerShutdown()
			os.Exit(1)
		}
	}()

	// Parse command line flags
	flags := parseFlags()

	// Setup structured logging
	setupLogging()

	// Handle version flag
	if flags.showVersion {
		fmt.Printf("KernelGatekeeper Client %s, commit %s, built at %s\n", version, commit, date)
		return
	}

	slog.Info("Starting KernelGatekeeper Client (SockOps Model)", "version", version, "pid", os.Getpid())

	// Initialize global context and cancellation
	globalCtx, globalCancel = context.WithCancel(context.Background())
	ipcConnectionStateChan = make(chan bool, 1) // Buffered channel

	// Setup signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("Received signal, initiating shutdown...", "signal", sig)
		triggerShutdown()
	}()

	// Initialize semaphore for limiting concurrent workers
	workerSemaphore = semaphore.NewWeighted(maxConcurrentWorkers)

	// Goroutine to manage connection to the service IPC
	globalWg.Add(1)
	go manageIPCConnection(globalCtx, flags)

	// Wait for the initial connection attempt
	slog.Info("Waiting for initial connection to service...")
	select {
	case isConnected := <-ipcConnectionStateChan:
		if !isConnected {
			slog.Error("Initial connection to service failed. Check service status and socket path.", "socket", flags.socketPath)
			triggerShutdown() // Trigger cleanup before exiting
			globalWg.Wait()   // Wait for manager to exit
			os.Exit(1)
		}
		slog.Info("Successfully connected to service IPC.")
	case <-time.After(flags.connectTimeout + 5*time.Second): // Add buffer to connectTimeout
		slog.Error("Timeout waiting for initial service connection.", "timeout", flags.connectTimeout)
		triggerShutdown()
		globalWg.Wait()
		os.Exit(1)
	case <-globalCtx.Done():
		slog.Info("Shutdown initiated before initial connection completed.")
		globalWg.Wait()
		os.Exit(1)
	}

	// Initial setup after successful connection
	if err := performInitialSetup(); err != nil {
		slog.Error("Failed during initial setup after connecting to service", "error", err)
		triggerShutdown()
		globalWg.Wait()
		os.Exit(1)
	}

	// Start the local listener for BPF connections
	listener, err := startLocalListener()
	if err != nil {
		slog.Error("Failed to start local listener", "address", net.JoinHostPort(localListenAddr, strconv.Itoa(localListenPort)), "error", err)
		triggerShutdown()
		globalWg.Wait()
		os.Exit(1)
	}
	defer listener.Close() // Ensure listener is closed on exit

	// Start background tasks (config refresh, kerberos check, status ping)
	globalWg.Add(1)
	go runBackgroundTasks(globalCtx)

	// Start the main loop listening for IPC notifications (like notify_accept)
	globalWg.Add(1)
	go listenIPCNotifications(globalCtx, listener)

	slog.Info("Client initialization complete. Ready to accept proxied connections.")

	// Wait for shutdown signal
	<-globalCtx.Done()
	slog.Info("Shutdown initiated. Waiting for background tasks and connections to complete...")

	// Close listener to stop accepting new connections
	listener.Close()

	// Wait for all goroutines (IPC manager, background tasks, connection handlers) to finish
	globalWg.Wait()

	// Final cleanup
	cleanupResources()
	slog.Info("Client exited gracefully.")
}

// triggerShutdown cancels the global context and ensures cleanup runs once.
func triggerShutdown() {
	globalShutdownOnce.Do(func() {
		slog.Info("Triggering application shutdown...")
		if globalCancel != nil {
			globalCancel()
		}
	})
}

// cleanupResources closes global resources like Kerberos client and Proxy manager.
func cleanupResources() {
	slog.Debug("Cleaning up global resources...")
	if globalProxyMgr != nil {
		globalProxyMgr.Close()
		slog.Debug("Proxy manager closed.")
	}
	if globalKerbClient != nil {
		globalKerbClient.Close()
		slog.Debug("Kerberos client closed.")
	}
	ipcConnectionMu.Lock()
	if ipcConnection != nil {
		ipcConnection.Close()
		ipcConnection = nil
		slog.Debug("IPC connection explicitly closed.")
	}
	ipcConnectionMu.Unlock()
}

// parseFlags parses command-line flags.
func parseFlags() clientFlags {
	var flags clientFlags
	flag.StringVar(&flags.socketPath, "socket", config.DefaultSocketPath, "Path to service UNIX socket")
	flag.BoolVar(&flags.showVersion, "version", false, "Show client version")
	flag.DurationVar(&flags.connectTimeout, "timeout", 10*time.Second, "Connection timeout to the service socket")
	flag.Parse()
	return flags
}

// setupLogging configures the global logger.
func setupLogging() {
	logLevelStr := os.Getenv("LOG_LEVEL")
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

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level <= slog.LevelDebug, // Add source only for debug level
	}
	// Log to stderr by default for clients
	logger := slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(logger)
}

// manageIPCConnection handles connecting, reconnecting, and registering with the service IPC.
func manageIPCConnection(ctx context.Context, flags clientFlags) {
	defer globalWg.Done()
	defer slog.Info("IPC connection manager stopped.")

	var currentDelay time.Duration = 0 // Start with immediate attempt
	var attempt int = 0

	for {
		select {
		case <-ctx.Done():
			return // Exit if main context is cancelled
		case <-time.After(currentDelay):
			// Attempt connection
			attempt++
			slog.Info("Attempting to connect to service IPC...", "attempt", attempt, "socket", flags.socketPath)
			conn, err := net.DialTimeout("unix", flags.socketPath, flags.connectTimeout)

			if err != nil {
				slog.Warn("Failed to connect to service IPC", "error", err)
				ipcSetConnectionState(false) // Signal disconnection

				// Calculate next delay using exponential backoff with jitter
				currentDelay = time.Duration(math.Pow(2, float64(min(attempt, 6)))) * baseReconnectDelay // Limit exponent to avoid huge delays
				jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
				currentDelay = minDuration(currentDelay+jitter, maxReconnectDelay)
				slog.Info("Will retry IPC connection", "delay", currentDelay)
				continue // Loop to wait for the delay
			}

			// Connection successful
			slog.Info("Successfully connected to service IPC", "socket", flags.socketPath)
			attempt = 0                 // Reset attempt counter on success
			currentDelay = 0            // Reset delay
			setIPCConnection(conn)      // Store the connection safely
			ipcSetConnectionState(true) // Signal connection success

			// Register with the service
			if err := registerWithService(conn); err != nil {
				slog.Error("Failed to register with service after connection", "error", err)
				conn.Close() // Close the connection
				setIPCConnection(nil)
				ipcSetConnectionState(false)
				currentDelay = baseReconnectDelay // Start backoff again
				continue                          // Loop to retry
			}
			slog.Info("Client registered with service", "pid", os.Getpid())

			// Wait until the connection is closed or context is cancelled
			waitForConnectionClose(ctx, conn)

			// Connection was closed, reset state and prepare for reconnect
			slog.Warn("IPC connection lost. Preparing to reconnect...")
			setIPCConnection(nil)
			ipcSetConnectionState(false)
			currentDelay = baseReconnectDelay // Start backoff on disconnect
		}
	}
}

// setIPCConnection safely updates the global IPC connection reference.
func setIPCConnection(conn net.Conn) {
	ipcConnectionMu.Lock()
	// Close existing connection if any (shouldn't happen often here, but defensive)
	if ipcConnection != nil && ipcConnection != conn {
		ipcConnection.Close()
	}
	ipcConnection = conn
	ipcConnectionMu.Unlock()
}

// getIPCConnection safely retrieves the current IPC connection reference.
func getIPCConnection() net.Conn {
	ipcConnectionMu.Lock()
	defer ipcConnectionMu.Unlock()
	return ipcConnection
}

// ipcSetConnectionState updates the connection state and notifies waiters.
func ipcSetConnectionState(connected bool) {
	newState := int32(0)
	if connected {
		newState = 1
	}

	// Update the atomic state
	oldState := ipcConnectionState.Swap(newState)

	// Notify only if the state actually changed
	if oldState != newState {
		select {
		case ipcConnectionStateChan <- connected: // Send notification
		default: // Non-blocking send: if buffer is full, someone already got notified
		}
	}
}

// isIPCConnected checks the current connection state.
func isIPCConnected() bool {
	return ipcConnectionState.Load() == 1
}

// waitForConnectionClose monitors the connection for closure.
func waitForConnectionClose(ctx context.Context, conn net.Conn) {
	if conn == nil {
		return
	}
	// Use a simple read probe to detect closure. Set a long deadline.
	// This isn't perfect but avoids a dedicated read goroutine per connection lifecycle.
	probeTicker := time.NewTicker(30 * time.Second)
	defer probeTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return // Main context cancelled
		case <-probeTicker.C:
			one := make([]byte, 1)
			// Set a very short deadline for the read probe
			conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			_, err := conn.Read(one)
			conn.SetReadDeadline(time.Time{}) // Clear the deadline immediately

			if err != nil {
				// EOF or timeout likely means connection closed or unresponsive
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isTimeoutError(err) || isConnectionClosedErr(err) {
					slog.Debug("IPC connection probe detected closure or error", "error", err)
					return // Signal connection is lost
				}
				// Other errors might be transient, log them but continue probing
				slog.Warn("IPC connection probe encountered unexpected error", "error", err)
			}
		}
	}
}

// registerWithService sends the registration command to the service.
func registerWithService(conn net.Conn) error {
	if conn == nil {
		return errors.New("cannot register with nil IPC connection")
	}
	pid := os.Getpid()
	reqData := ipc.RegisterClientData{PID: pid}
	cmd, err := ipc.NewCommand("register_client", reqData)
	if err != nil {
		return fmt.Errorf("failed to create register command: %w", err)
	}

	encoder := json.NewEncoder(conn)
	// Set a write deadline
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = encoder.Encode(cmd)
	conn.SetWriteDeadline(time.Time{}) // Clear deadline
	if err != nil {
		if isConnectionClosedErr(err) {
			return fmt.Errorf("IPC connection closed before sending register_client: %w", err)
		}
		return fmt.Errorf("failed to send register command: %w", err)
	}

	// Wait for response
	decoder := json.NewDecoder(conn)
	var resp ipc.Response
	// Set a read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = decoder.Decode(&resp)
	conn.SetReadDeadline(time.Time{}) // Clear deadline
	if err != nil {
		if isConnectionClosedErr(err) {
			return fmt.Errorf("IPC connection closed while waiting for register_client response: %w", err)
		}
		return fmt.Errorf("failed to decode register response: %w", err)
	}

	if resp.Status != ipc.StatusOK {
		return fmt.Errorf("service registration failed: %s", resp.Error)
	}
	return nil
}

// performInitialSetup fetches config, initializes Kerberos and Proxy Manager.
func performInitialSetup() error {
	slog.Info("Performing initial setup...")
	// Get initial config
	initialConfig, err := getConfigFromService()
	if err != nil {
		return fmt.Errorf("failed to get initial config from service: %w", err)
	}
	setConfig(initialConfig) // Set the global config

	// Initialize Kerberos client
	kClient, err := kerb.NewKerberosClient(&initialConfig.Kerberos)
	if err != nil {
		// Log warning, but maybe continue if Kerberos isn't strictly needed?
		// For now, treat as error. Could be made configurable later.
		slog.Error("Failed to initialize Kerberos client", "error", err)
		return fmt.Errorf("Kerberos initialization failed: %w", err)
	}
	globalKerbClient = kClient
	slog.Info("Kerberos client initialized.")

	// Initialize Proxy Manager
	pMgr, err := proxy.NewProxyManager(&initialConfig.Proxy)
	if err != nil {
		slog.Error("Failed to initialize Proxy Manager", "error", err)
		return fmt.Errorf("Proxy Manager initialization failed: %w", err)
	}
	globalProxyMgr = pMgr
	slog.Info("Proxy Manager initialized.")

	return nil
}

// getConfigFromService fetches the current configuration from the service via IPC.
func getConfigFromService() (*config.Config, error) {
	conn := getIPCConnection()
	if conn == nil {
		return nil, errors.New("cannot get config, not connected to service")
	}

	cmd, err := ipc.NewCommand("get_config", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get_config command: %w", err)
	}

	encoder := json.NewEncoder(conn)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = encoder.Encode(cmd)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		if isConnectionClosedErr(err) {
			return nil, fmt.Errorf("IPC connection closed before sending get_config: %w", err)
		}
		return nil, fmt.Errorf("failed to send get_config command: %w", err)
	}

	decoder := json.NewDecoder(conn)
	var resp ipc.Response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = decoder.Decode(&resp)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		if isConnectionClosedErr(err) {
			return nil, fmt.Errorf("IPC connection closed while waiting for get_config response: %w", err)
		}
		return nil, fmt.Errorf("failed to decode get_config response: %w", err)
	}

	if resp.Status != ipc.StatusOK {
		return nil, fmt.Errorf("service returned error for get_config: %s", resp.Error)
	}

	var data ipc.GetConfigData
	if err := ipc.DecodeData(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to decode config data from response: %w", err)
	}

	slog.Debug("Successfully retrieved config from service via IPC.")
	return &data.Config, nil
}

// startLocalListener starts the TCP listener for BPF sockmap connections.
func startLocalListener() (net.Listener, error) {
	listenAddress := fmt.Sprintf("%s:%d", localListenAddr, localListenPort)
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to start local listener on %s: %w", listenAddress, err)
	}
	slog.Info("Started local listener for BPF connections", "address", listenAddress)
	return listener, nil
}

// listenIPCNotifications listens for commands (like notify_accept) from the service.
func listenIPCNotifications(ctx context.Context, localListener net.Listener) {
	defer globalWg.Done()
	defer slog.Info("IPC notification listener stopped.")

	var decoder *json.Decoder
	var currentConn net.Conn

	for {
		select {
		case <-ctx.Done():
			return // Exit if main context cancelled
		default:
			// Get current connection safely
			conn := getIPCConnection()

			// If connection changed or decoder is nil, recreate decoder
			if conn != currentConn && conn != nil {
				slog.Debug("IPC connection changed or initialized, creating new JSON decoder.")
				decoder = json.NewDecoder(conn)
				currentConn = conn
			} else if conn == nil {
				// If connection is lost, wait for reconnection signal
				slog.Debug("IPC connection lost, waiting for reconnection...")
				currentConn = nil
				decoder = nil
				// Wait for connected state or context cancellation
				select {
				case <-ipcConnectionStateChan: // Wait for any state change signal
					// Loop will re-evaluate connection on next iteration
					continue
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second): // Prevent busy-loop if channel is sticky
					continue
				}
			}

			// Decode command with timeout
			var cmd ipc.Command
			// Set a read deadline to prevent blocking forever if connection hangs
			if currentConn != nil {
				currentConn.SetReadDeadline(time.Now().Add(statusPingInterval + 10*time.Second)) // Longer timeout
			}
			err := decoder.Decode(&cmd)
			if currentConn != nil {
				currentConn.SetReadDeadline(time.Time{}) // Clear deadline
			}

			if err != nil {
				if ctx.Err() != nil {
					return // Exit if context was cancelled during decode
				}
				// Handle errors: EOF/closed likely means disconnect
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isConnectionClosedErr(err) {
					slog.Warn("IPC connection lost while reading notifications.", "error", err)
					// Connection manager will handle reconnect
					currentConn = nil // Ensure decoder is recreated on reconnect
					decoder = nil
					// Don't trigger backoff here, manageIPCConnection handles it
					time.Sleep(500 * time.Millisecond) // Small delay before checking connection again
				} else {
					// Log other decoding errors
					slog.Error("Failed to decode IPC command", "error", err)
					// Potential stream corruption? Maybe force reconnect?
					if currentConn != nil {
						currentConn.Close() // Close potentially bad connection
					}
					currentConn = nil
					decoder = nil
					time.Sleep(1 * time.Second)
				}
				continue // Retry reading or wait for reconnect
			}

			// Process received command
			switch cmd.Command {
			case "notify_accept":
				var data ipc.NotifyAcceptData
				if err := ipc.DecodeData(cmd.Data, &data); err != nil {
					slog.Error("Failed to decode notify_accept data", "error", err)
					continue
				}
				slog.Info("Received 'notify_accept' from service", "src", data.SrcIP, "dst", data.DstIP, "dport", data.DstPort)
				// Accept the connection passed via sockmap
				handleBPFAccept(ctx, localListener, data)
			// Handle other commands if needed in the future (e.g., config_updated)
			default:
				slog.Warn("Received unknown command from service via IPC", "command", cmd.Command)
			}
		}
	}
}

// handleBPFAccept accepts the connection from the local listener and starts processing.
func handleBPFAccept(ctx context.Context, listener net.Listener, originalDest ipc.NotifyAcceptData) {
	acceptedConn, err := listener.Accept()
	if err != nil {
		// Check if the error is due to the listener being closed during shutdown
		if errors.Is(err, net.ErrClosed) {
			slog.Info("Local listener closed while attempting to accept BPF connection (likely shutdown).")
			return
		}
		slog.Error("Failed to accept connection from BPF sockmap", "error", err)
		return
	}
	slog.Debug("Accepted connection from BPF sockmap", "local", acceptedConn.LocalAddr(), "remote", acceptedConn.RemoteAddr())

	// Acquire semaphore before starting goroutine
	if err := workerSemaphore.Acquire(ctx, 1); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			slog.Info("Worker semaphore acquisition cancelled or timed out during shutdown")
		} else {
			slog.Error("Failed to acquire worker semaphore", "error", err)
		}
		acceptedConn.Close() // Close the connection if we can't handle it
		return
	}

	// Increment active connection counter
	activeConnections.Add(1)
	globalWg.Add(1) // Add to wait group for graceful shutdown

	// Launch goroutine to handle the connection
	go func(conn net.Conn, dest ipc.NotifyAcceptData) {
		defer globalWg.Done()
		defer workerSemaphore.Release(1)
		defer activeConnections.Add(-1) // Decrement counter when done
		// Pass the main context down
		handleAcceptedConnection(globalCtx, conn, dest)
	}(acceptedConn, originalDest)
}

// handleAcceptedConnection processes a connection accepted from the BPF sockmap via the local listener.
// It determines the correct proxy, establishes a tunnel, and relays data.
func handleAcceptedConnection(ctx context.Context, acceptedConn net.Conn, originalDest ipc.NotifyAcceptData) {
	defer acceptedConn.Close()

	targetAddr := net.JoinHostPort(originalDest.DstIP, strconv.Itoa(int(originalDest.DstPort)))
	// Construct a target URL (needed for PAC execution)
	// Assume https for common ports, otherwise http. This is a heuristic.
	scheme := "http"
	if originalDest.DstPort == 443 || originalDest.DstPort == 8443 {
		scheme = "https"
	}
	targetURLStr := fmt.Sprintf("%s://%s", scheme, targetAddr)
	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		slog.Error("Failed to parse target address into URL", "target_addr", targetAddr, "error", err)
		return
	}

	logCtx := slog.With("target_addr", targetAddr, "target_url", targetURLStr)
	logCtx.Info("Handling proxied connection")

	if globalProxyMgr == nil {
		logCtx.Error("Proxy manager is not initialized")
		return
	}

	// --- Dynamic Proxy Selection ---
	proxyResult, err := globalProxyMgr.GetEffectiveProxyForURL(targetURL)
	if err != nil {
		logCtx.Error("Failed to determine effective proxy for target", "error", err)
		return
	}

	switch proxyResult.Type {
	case proxy.ProxyResultDirect:
		// KernelGatekeeper sockops model *cannot* handle DIRECT connections gracefully
		// because the connection is already intercepted by BPF and sent to this client.
		// We cannot simply "let it go". Log an error and close.
		logCtx.Error("PAC script returned DIRECT, but KernelGatekeeper (sockops) cannot bypass proxy once connection is intercepted. Closing connection.", "pac_result", "DIRECT")
		return // Close the accepted connection

	case proxy.ProxyResultError:
		logCtx.Error("Error determining proxy from PAC or configuration. Closing connection.", "pac_result", "ERROR")
		return // Close the accepted connection

	case proxy.ProxyResultProxy:
		if len(proxyResult.Proxies) == 0 {
			logCtx.Error("Proxy result indicates PROXY but list is empty. Closing connection.")
			return
		}
		logCtx.Info("Proxy determined for target", "proxies", proxy.UrlsToStrings(proxyResult.Proxies)) // Use exported helper for logging

		var proxyConn net.Conn
		var selectedProxyURL *url.URL
		var connectErr error

		// Try proxies from the list in order
		for _, currentProxyURL := range proxyResult.Proxies {
			logCtx.Info("Attempting connection via proxy", "proxy_url", currentProxyURL.String())
			selectedProxyURL = currentProxyURL // Store the one we are trying

			// Dial the proxy server
			proxyDialer := net.Dialer{Timeout: proxyConnectDialTimeout}
			proxyConn, connectErr = proxyDialer.DialContext(ctx, "tcp", currentProxyURL.Host)
			if connectErr != nil {
				logCtx.Warn("Failed to connect to proxy server, trying next (if any)", "proxy_url", currentProxyURL.String(), "error", connectErr)
				continue // Try next proxy
			}
			defer proxyConn.Close() // Ensure connection is closed if tunnel fails or relay ends
			logCtx.Debug("Connected to proxy server", "proxy_url", currentProxyURL.String())

			// Establish CONNECT tunnel
			connectErr = establishConnectTunnel(ctx, proxyConn, targetAddr, globalKerbClient)
			if connectErr != nil {
				logCtx.Warn("Failed to establish CONNECT tunnel, trying next proxy (if any)", "proxy_url", currentProxyURL.String(), "error", connectErr)
				proxyConn.Close() // Close connection to this failed proxy
				proxyConn = nil   // Reset proxyConn
				continue          // Try next proxy
			}

			// Tunnel established successfully
			logCtx.Info("CONNECT tunnel established via proxy", "proxy_url", currentProxyURL.String())
			break // Exit loop, we have a working connection
		}

		// Check if we successfully established a connection and tunnel
		if proxyConn == nil || connectErr != nil {
			logCtx.Error("Failed to establish connection through any configured/PAC-provided proxy.", "last_error", connectErr)
			return // Close acceptedConn (defer does this)
		}

		// Relay data
		logCtx.Debug("Starting data relay", "selected_proxy", selectedProxyURL.String())
		relayErr := relayDataBidirectionally(ctx, acceptedConn, proxyConn) // Pass context
		if relayErr != nil && !isConnectionClosedErr(relayErr) && !errors.Is(relayErr, context.Canceled) {
			logCtx.Warn("Data relay ended with error", "error", relayErr)
		} else {
			logCtx.Debug("Data relay completed.")
		}

	default:
		logCtx.Error("Unknown proxy result type encountered", "type", proxyResult.Type)
	}
}

// establishConnectTunnel sends the HTTP CONNECT request and handles authentication.
func establishConnectTunnel(ctx context.Context, proxyConn net.Conn, targetAddr string, krbClient *kerb.KerberosClient) error {
	logCtx := slog.With("target_addr", targetAddr, "proxy_host", proxyConn.RemoteAddr().String())
	logCtx.Debug("Establishing CONNECT tunnel")

	var resp *http.Response
	var lastErr error

	// Use a context with timeout for the entire CONNECT attempt (including auth retries)
	connectCtx, cancel := context.WithTimeout(ctx, proxyCONNECTTimeout)
	defer cancel()

	// Maximum 2 attempts: 1st potentially without auth, 2nd with auth after 407
	for attempt := 1; attempt <= 2; attempt++ {
		select {
		case <-connectCtx.Done():
			return fmt.Errorf("connect tunnel timeout exceeded before attempt %d: %w", attempt, connectCtx.Err())
		default:
		}

		logCtx.Debug("CONNECT attempt", "attempt", attempt)
		// Create CONNECT request object
		connectReq := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: targetAddr, Host: targetAddr}, // Opaque for CONNECT target, Host for header
			Host:   targetAddr,                                     // Specifies the target host for the CONNECT request
			Header: make(http.Header),
		}
		connectReq.Header.Set("User-Agent", fmt.Sprintf("KernelGatekeeper-Client/%s", version))
		connectReq.Header.Set("Proxy-Connection", "Keep-Alive") // Optional but common
		connectReq.Header.Set("Connection", "Keep-Alive")       // Optional

		// Add Kerberos / SPNEGO header if available and required (or on 2nd attempt)
		// NOTE: Removed unused `needsAuth` variable
		if krbClient != nil {
			// Check ticket validity before attempting SPNEGO (non-fatal warning if fails)
			if kerr := krbClient.CheckAndRefreshClient(); kerr != nil {
				logCtx.Warn("Kerberos ticket potentially invalid before CONNECT", "attempt", attempt, "error", kerr)
			}

			// Use gokrb5's SPNEGO helper to add the header
			// It's okay if CheckAndRefreshClient warned, SetSPNEGOHeader will use the available TGT
			// Pass empty service principal name "" for standard HTTP proxy SPN (HTTP/proxy.host@REALM)
			gokrbCl := krbClient.Gokrb5Client() // Get the underlying client using the new exported method
			if gokrbCl == nil && attempt > 1 {
				// If we need auth on 2nd attempt but Kerberos client isn't initialized internally
				lastErr = errors.New("kerberos client not initialized internally, cannot add SPNEGO header on retry")
				logCtx.Error("Cannot add SPNEGO header", "error", lastErr)
				continue // Try next proxy? Or return error? Return error.
				// return lastErr
			}

			var spnegoErr error
			if gokrbCl != nil { // Only attempt if the underlying client is available
				spnegoErr = spnego.SetSPNEGOHeader(gokrbCl, connectReq, "")
			} else if attempt > 1 {
				// If we must authenticate but underlying client is nil
				spnegoErr = errors.New("kerberos client not initialized internally, cannot generate SPNEGO token")
			}

			if spnegoErr != nil {
				// Log error but continue without header if it fails? Or fail hard?
				// Let's fail hard on 2nd attempt if SPNEGO header fails.
				if attempt > 1 {
					lastErr = fmt.Errorf("failed to set SPNEGO header on attempt %d: %w", attempt, spnegoErr)
					logCtx.Error("SPNEGO header generation failed on retry attempt", "error", lastErr)
					continue // Or return lastErr? Let's try continue first. Maybe proxy doesn't *require* krb?
				} else {
					logCtx.Warn("Failed to set SPNEGO header on initial attempt, proceeding without", "error", spnegoErr)
				}
			} else if connectReq.Header.Get("Proxy-Authorization") != "" {
				logCtx.Debug("SPNEGO Proxy-Authorization header added", "attempt", attempt)
				// needsAuth = true // We added an auth header - needsAuth is unused
			} else if attempt > 1 {
				logCtx.Warn("SPNEGO did not add Proxy-Authorization header on retry attempt")
			}
		} else if attempt > 1 {
			// If krbClient is nil and we got a 407, we cannot authenticate.
			logCtx.Error("Received 407 Proxy Authentication Required, but Kerberos client is not available.")
			// Use the error from the previous iteration (407 response)
			if lastErr == nil {
				lastErr = errors.New("proxy authentication required, but Kerberos is not configured/initialized")
			}
			return lastErr
		}

		// Write the CONNECT request to the proxy connection
		writeErr := connectReq.Write(proxyConn)
		if writeErr != nil {
			if isConnectionClosedErr(writeErr) {
				return fmt.Errorf("proxy connection closed before writing CONNECT (attempt %d): %w", attempt, writeErr)
			}
			return fmt.Errorf("failed to send CONNECT request (attempt %d): %w", attempt, writeErr)
		}
		logCtx.Debug("CONNECT request sent", "attempt", attempt)

		// Read the response
		// Use a buffered reader for ReadResponse
		proxyReader := bufio.NewReader(proxyConn)
		// Set a deadline specific to reading the response header
		readDeadline := time.Now().Add(proxyCONNECTTimeout / 2) // Use half the total timeout for response reading
		proxyConn.SetReadDeadline(readDeadline)
		resp, lastErr = http.ReadResponse(proxyReader, connectReq)
		proxyConn.SetReadDeadline(time.Time{}) // Clear deadline

		if lastErr != nil {
			if isTimeoutError(lastErr) {
				logCtx.Error("Timeout reading CONNECT response", "attempt", attempt, "error", lastErr)
			} else if isConnectionClosedErr(lastErr) {
				logCtx.Error("Proxy closed connection unexpectedly after CONNECT request", "attempt", attempt, "error", lastErr)
			} else {
				logCtx.Error("Failed to read CONNECT response", "attempt", attempt, "error", lastErr)
			}
			// Don't retry on read errors generally, indicates a problem.
			return fmt.Errorf("failed reading CONNECT response (attempt %d): %w", attempt, lastErr)
		}

		// Process the response
		logCtx.Debug("Received CONNECT response", "attempt", attempt, "status", resp.StatusCode)
		if resp.StatusCode == http.StatusOK {
			// Success! Drain any remaining body and return nil.
			if resp.Body != nil {
				io.Copy(io.Discard, resp.Body) // Read and discard any potential body content
				resp.Body.Close()
			}
			logCtx.Debug("CONNECT tunnel established successfully")
			return nil // Success
		}

		// Handle Authentication Required
		if resp.StatusCode == http.StatusProxyAuthRequired {
			// Read and discard body
			if resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			// Check if we should retry with authentication
			if attempt == 1 && krbClient != nil {
				logCtx.Info("Received 407 Proxy Authentication Required, will retry with Kerberos auth.")
				lastErr = errors.New(resp.Status) // Store the 407 status text as the error
				continue                          // Go to the next attempt
			} else {
				logCtx.Error("Received 407 Proxy Authentication Required, but cannot retry or Kerberos not available.")
				lastErr = fmt.Errorf("proxy authentication failed: %s (Kerberos available: %t, attempt: %d)", resp.Status, krbClient != nil, attempt)
				return lastErr
			}
		}

		// Handle other non-OK, non-407 responses
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512)) // Read some body for context
		if resp.Body != nil {
			resp.Body.Close()
		}
		errMsg := fmt.Sprintf("proxy CONNECT request failed: %s (%s)", resp.Status, strings.TrimSpace(string(bodyBytes)))
		logCtx.Error("Proxy returned error for CONNECT", "status", resp.Status, "body_preview", string(bodyBytes))
		lastErr = errors.New(errMsg)
		return lastErr // Return error for non-200, non-407 status
	}

	// If loop finishes without success (shouldn't happen with current logic, but defensive)
	if lastErr == nil {
		lastErr = errors.New("failed to establish CONNECT tunnel after maximum attempts")
	}
	return lastErr
}

// relayDataBidirectionally copies data between the accepted connection and the proxy connection.
// It now accepts a context for cancellation.
func relayDataBidirectionally(ctx context.Context, conn1, conn2 net.Conn) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2) // Channel to capture errors from goroutines

	copyData := func(dst, src net.Conn, tag string) {
		defer wg.Done()
		// Use a buffer allocated outside the loop
		buf := make([]byte, 32*1024) // 32KB buffer

		for {
			// Check for context cancellation before each read/write cycle
			select {
			case <-ctx.Done():
				errChan <- fmt.Errorf("%s relay cancelled by context: %w", tag, ctx.Err())
				// Close connections to interrupt the other side? Or rely on CloseWrite?
				// Closing write signals EOF to the other side.
				if tcpDst, ok := dst.(*net.TCPConn); ok {
					tcpDst.CloseWrite()
				}
				if tcpSrc, ok := src.(*net.TCPConn); ok {
					tcpSrc.CloseRead() // Optional: signal we won't read anymore
				}
				return
			default:
				// Proceed with copy attempt
			}

			// Set deadline for read operation to implement inactivity timeout
			// and allow periodic context checking.
			readDeadline := time.Now().Add(relayCopyTimeout)
			if err := src.SetReadDeadline(readDeadline); err != nil {
				// This might happen if the connection is already closed.
				if !isConnectionClosedErr(err) {
					slog.Warn("Failed to set read deadline for relay", "tag", tag, "error", err)
					// Attempt to continue without deadline? Or report error? Report error.
					errChan <- fmt.Errorf("%s set read deadline failed: %w", tag, err)
				} else {
					// If connection closed while setting deadline, report EOF/closed
					errChan <- io.EOF
				}
				return
			}

			// Perform the read
			nr, readErr := src.Read(buf)

			// Clear the read deadline immediately after read returns
			src.SetReadDeadline(time.Time{})

			// Write the data if read was successful
			if nr > 0 {
				// Set write deadline
				writeDeadline := time.Now().Add(relayCopyTimeout)
				if err := dst.SetWriteDeadline(writeDeadline); err != nil {
					if !isConnectionClosedErr(err) {
						slog.Warn("Failed to set write deadline for relay", "tag", tag, "error", err)
						errChan <- fmt.Errorf("%s set write deadline failed: %w", tag, err)
					} else {
						errChan <- io.EOF
					}
					return
				}

				nw, writeErr := dst.Write(buf[0:nr])

				// Clear write deadline
				dst.SetWriteDeadline(time.Time{})

				if writeErr != nil {
					// Report write error
					errChan <- fmt.Errorf("%s write failed: %w", tag, writeErr)
					// Attempt to close the write side of source to signal peer
					if tcpSrc, ok := src.(*net.TCPConn); ok {
						tcpSrc.CloseRead() // We can't write anymore, stop reading too?
					}
					return
				}
				if nr != nw {
					// Report short write error
					errChan <- fmt.Errorf("%s short write: %d != %d", tag, nw, nr)
					if tcpSrc, ok := src.(*net.TCPConn); ok {
						tcpSrc.CloseRead()
					}
					return
				}
			}

			// Handle read errors
			if readErr != nil {
				// If EOF, it's a clean closure by the source.
				if readErr == io.EOF {
					slog.Debug("Relay source closed (EOF)", "tag", tag)
					// Signal EOF to the destination by closing the write half.
					if tcpDst, ok := dst.(*net.TCPConn); ok {
						tcpDst.CloseWrite() // Best effort
					}
					errChan <- nil // Report success (EOF is not an application error)
				} else if isTimeoutError(readErr) {
					// Inactivity timeout occurred
					slog.Warn("Relay inactivity timeout", "tag", tag, "timeout", relayCopyTimeout)
					errChan <- fmt.Errorf("%s inactivity timeout after %s", tag, relayCopyTimeout)
					// Close both sides on timeout? Or just report error? Report error.
					if tcpDst, ok := dst.(*net.TCPConn); ok {
						tcpDst.Close() // Close the whole connection on timeout
					}
					if tcpSrc, ok := src.(*net.TCPConn); ok {
						tcpSrc.Close()
					}
				} else if isConnectionClosedErr(readErr) || errors.Is(readErr, context.Canceled) {
					// Connection closed or context cancelled during read
					slog.Debug("Relay source closed or cancelled during read", "tag", tag, "error", readErr)
					errChan <- nil // Not an application error
				} else {
					// Report other read errors
					errChan <- fmt.Errorf("%s read failed: %w", tag, readErr)
				}
				return // Exit goroutine on any read error (including EOF and timeout)
			}
		} // end for loop
	}

	wg.Add(2)
	go copyData(conn1, conn2, "proxy->client(bpf)")
	go copyData(conn2, conn1, "client(bpf)->proxy")

	// Wait for both copy goroutines to finish
	wg.Wait()
	close(errChan) // Close the channel signals that all errors (or nil) have been sent

	// Check for the first error reported
	for err := range errChan {
		if err != nil {
			// Log the first error encountered
			slog.Debug("Relay finished with error", "error", err)
			return err // Return the first error
		}
	}

	slog.Debug("Relay finished successfully.")
	return nil // No errors reported
}

// runBackgroundTasks manages periodic tasks like config refresh, Kerberos check, and status pings.
func runBackgroundTasks(ctx context.Context) {
	defer globalWg.Done()
	defer slog.Info("Background task runner stopped.")

	// Use separate tickers for different intervals
	configRefreshTicker := time.NewTicker(configRefreshInterval)
	defer configRefreshTicker.Stop()
	kerbCheckTicker := time.NewTicker(kerberosCheckInterval)
	defer kerbCheckTicker.Stop()
	statusPingTicker := time.NewTicker(statusPingInterval)
	defer statusPingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return // Exit if main context is cancelled

		case <-configRefreshTicker.C:
			slog.Debug("Attempting periodic configuration refresh...")
			if !isIPCConnected() {
				slog.Warn("Cannot refresh config, IPC disconnected.")
				continue
			}
			// Fetch new config from service
			newCfg, err := getConfigFromService()
			if err != nil {
				slog.Error("Failed to refresh configuration from service", "error", err)
				// Check if error indicates disconnect, connection manager will handle it
				if isConnectionClosedErr(err) || errors.Is(err, net.ErrClosed) {
					ipcSetConnectionState(false) // Ensure state reflects disconnect
				}
				continue
			}

			// Compare and apply if changed
			currentCfg := getConfig() // Get thread-safe copy
			// Compare relevant sections (Proxy, Kerberos)
			// Note: DeepEqual might be too strict if unexported fields change internally.
			// Compare relevant fields directly if necessary.
			configChanged := !reflect.DeepEqual(currentCfg.Proxy, newCfg.Proxy) ||
				!reflect.DeepEqual(currentCfg.Kerberos, newCfg.Kerberos) // Add other sections if they become dynamic

			if configChanged {
				slog.Info("Configuration change detected, applying...")
				setConfig(newCfg) // Update global config

				// Re-initialize Proxy Manager if proxy config changed
				if !reflect.DeepEqual(currentCfg.Proxy, newCfg.Proxy) {
					slog.Info("Proxy configuration changed, re-initializing proxy manager.")
					if globalProxyMgr != nil {
						globalProxyMgr.Close() // Close old manager
					}
					newProxyMgr, proxyErr := proxy.NewProxyManager(&newCfg.Proxy)
					if proxyErr != nil {
						slog.Error("Failed to re-initialize proxy manager after config refresh", "error", proxyErr)
						// What state are we in now? Maybe revert config? For now, log error.
					} else {
						globalProxyMgr = newProxyMgr // Assign new manager
						slog.Info("Proxy manager re-initialized.")
					}
				}

				// Re-initialize Kerberos if config changed (though less likely to change dynamically)
				if !reflect.DeepEqual(currentCfg.Kerberos, newCfg.Kerberos) {
					slog.Info("Kerberos configuration changed, re-initializing Kerberos client.")
					if globalKerbClient != nil {
						globalKerbClient.Close()
					}
					newKerbClient, krbErr := kerb.NewKerberosClient(&newCfg.Kerberos)
					if krbErr != nil {
						slog.Error("Failed to re-initialize Kerberos client after config refresh", "error", krbErr)
					} else {
						globalKerbClient = newKerbClient
						slog.Info("Kerberos client re-initialized.")
					}
				}
			} else {
				slog.Debug("Configuration unchanged.")
			}

		case <-kerbCheckTicker.C:
			if globalKerbClient != nil {
				slog.Debug("Performing periodic Kerberos ticket check/refresh...")
				if err := globalKerbClient.CheckAndRefreshClient(); err != nil {
					// This is expected if the user ticket expired and kinit wasn't run
					slog.Warn("Periodic Kerberos check/refresh failed", "error", err)
				} else {
					slog.Debug("Kerberos ticket check/refresh successful.")
				}
			}

		case <-statusPingTicker.C:
			slog.Debug("Sending status ping to service...")
			if !isIPCConnected() {
				slog.Warn("Cannot send status ping, IPC disconnected.")
				continue
			}
			sendClientStatusPing()
		}
	}
}

// sendClientStatusPing gathers client status and sends it to the service.
func sendClientStatusPing() {
	conn := getIPCConnection()
	if conn == nil {
		slog.Warn("Cannot send status ping, IPC connection is nil.")
		return
	}

	// Gather status data
	var kStatus ipc.ClientKerberosStatus
	if globalKerbClient != nil {
		kStatus = ipc.ClientKerberosStatusToIPC(globalKerbClient.GetStatus())
	} else {
		kStatus.Initialized = false
	}

	pingData := ipc.PingStatusData{
		ActiveConnections: activeConnections.Load(),
		KerberosStatus:    kStatus,
	}

	cmd, err := ipc.NewCommand("ping_status", pingData)
	if err != nil {
		slog.Error("Failed to create ping_status command", "error", err)
		return
	}

	// Send command (no response expected)
	encoder := json.NewEncoder(conn)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = encoder.Encode(cmd)
	conn.SetWriteDeadline(time.Time{})

	if err != nil {
		if isConnectionClosedErr(err) {
			slog.Warn("IPC connection closed while sending status ping", "error", err)
			ipcSetConnectionState(false) // Ensure state reflects disconnect
		} else {
			slog.Error("Failed to send status ping to service", "error", err)
		}
	} else {
		slog.Debug("Status ping sent successfully.")
	}
}

// --- Configuration Access ---

// setConfig safely updates the global configuration.
func setConfig(cfg *config.Config) {
	globalConfigMu.Lock()
	defer globalConfigMu.Unlock()
	globalConfig = cfg
}

// getConfig safely retrieves a copy of the global configuration.
func getConfig() config.Config {
	globalConfigMu.RLock()
	defer globalConfigMu.RUnlock()
	if globalConfig == nil {
		// Return an empty config if called before initialization
		// This should ideally not happen after initial setup succeeds.
		slog.Error("Attempted to get config before initialization or after setup failure!")
		return config.Config{} // Return zero value config
	}
	// Return a shallow copy for safety
	cfgCopy := *globalConfig
	// Make deep copies of slices/maps if they are modified elsewhere, e.g., proxy list
	// cfgCopy.Proxy.SomeSlice = append([]SomeType{}, globalConfig.Proxy.SomeSlice...)
	return cfgCopy
}

// --- Utility Functions ---

// isConnectionClosedErr checks for common network errors indicating closure.
func isConnectionClosedErr(err error) bool {
	if err == nil {
		return false
	}
	// Standard errors
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	// Check error strings for common messages
	errMsg := err.Error()
	if strings.Contains(errMsg, "use of closed network connection") ||
		strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "connection reset by peer") ||
		strings.Contains(errMsg, "forcibly closed by the remote host") || // Windows specific
		strings.Contains(errMsg, "socket is not connected") { // Can happen with unix sockets
		return true
	}
	// Unwrap net.OpError
	if opErr, ok := err.(*net.OpError); ok {
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
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

// isTimeoutError checks if an error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Check for context deadline exceeded wrapped in other errors
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// minDuration returns the smaller of two durations.
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// nativeEndian stores the system's byte order.
var nativeEndian binary.ByteOrder

// Initialize nativeEndian.
func init() {
	// Seed random number generator used for jitter
	// Use crypto/rand for better seeding in production, but math/rand is okay for simple jitter
	// rand.Seed(time.Now().UnixNano()) // Already done in proxy/proxy.go, avoid re-seeding
	rand.New(rand.NewSource(time.Now().UnixNano()))

	// Determine byte order
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = 0xABCD
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native byte order")
	}
}
