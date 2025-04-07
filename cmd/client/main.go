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
	"syscall"
	"time"
	"unsafe"

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

var (
	globalConfig       *config.Config
	globalConfigMu     sync.RWMutex
	globalKerbClient   *kerb.KerberosClient
	globalProxyMgr     *proxy.ProxyManager
	globalShutdownOnce sync.Once
	globalWg           sync.WaitGroup
	workerSemaphore    *semaphore.Weighted = semaphore.NewWeighted(100)
)

const (
	localListenPort = 3129
	localListenAddr = "127.0.0.1"
)

type clientFlags struct {
	socketPath     string
	showVersion    bool
	connectTimeout time.Duration
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "CLIENT PANIC: %v\n%s\n", r, string(debug.Stack()))
			os.Exit(1)
		}
	}()
	flags := parseFlags()
	setupLogging()
	if flags.showVersion {
		fmt.Printf("KernelGatekeeper Client %s, commit %s, built at %s\n", version, commit, date)
		return
	}

	slog.Info("Starting KernelGatekeeper Client (SockOps Model)")
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		globalShutdownOnce.Do(func() {
			slog.Info("Shutting down client...")
			cancel()
			globalWg.Wait()
			if globalProxyMgr != nil {
				globalProxyMgr.Close()
			}
			if globalKerbClient != nil {
				globalKerbClient.Close()
			}
			slog.Info("Client exited.")
		})
	}()

	var ipcConn net.Conn
	var err error
	for i := 0; i < 5; i++ {
		ipcConn, err = connectToService(flags.socketPath, flags.connectTimeout)
		if err == nil {
			break
		}
		slog.Warn("Failed connect to service IPC, retrying...", "attempt", i+1, "error", err)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			slog.Error("Context cancelled during initial service connection")
			os.Exit(1)
		}
	}
	if err != nil {
		slog.Error("Giving up connecting to service IPC. Exiting.", "error", err)
		os.Exit(1)
	}
	slog.Info("Connected to service IPC", "socket", flags.socketPath)

	if err := registerWithService(ipcConn); err != nil {
		slog.Error("Failed register with service", "error", err)
		ipcConn.Close()
		os.Exit(1)
	}

	initialConfig, err := getConfigOverIPC(ipcConn, flags.connectTimeout)
	if err != nil {
		slog.Error("Failed get config from service after registration", "error", err)
		ipcConn.Close()
		os.Exit(1)
	}
	setConfig(initialConfig)

	globalKerbClient, err = kerb.NewKerberosClient(&initialConfig.Kerberos)
	if err != nil {
		slog.Error("Kerberos init failed", "error", err)
	} else {
		slog.Info("Kerberos initialized")
	}
	globalProxyMgr, err = proxy.NewProxyManager(&initialConfig.Proxy)
	if err != nil {
		slog.Error("Proxy manager init failed", "error", err)
	} else {
		slog.Info("Proxy manager initialized")
	}

	listenAddress := fmt.Sprintf("%s:%d", localListenAddr, localListenPort)
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		slog.Error("Failed start local listener", "address", listenAddress, "error", err)
		ipcConn.Close()
		os.Exit(1)
	}
	defer listener.Close()
	slog.Info("Started local listener", "address", listenAddress)

	globalWg.Add(1)
	go listenIPCNotifications(ctx, ipcConn, listener, flags)
	globalWg.Add(1)
	go runBackgroundTasks(ctx, &globalWg, flags, ipcConn) // Pass ipcConn for config refresh

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("Client running. Waiting for connections and signals.")

	select {
	case sig := <-sigCh:
		slog.Info("Received signal, shutting down...", "signal", sig)
	case <-ctx.Done():
		slog.Info("Context cancelled, shutting down...")
	}
	cancel()
	listener.Close()
	ipcConn.Close()
}

func parseFlags() clientFlags {
	var flags clientFlags
	flag.StringVar(&flags.socketPath, "socket", "/var/run/kernelgatekeeper.sock", "Path to service UNIX socket")
	flag.BoolVar(&flags.showVersion, "version", false, "Show client version")
	flag.DurationVar(&flags.connectTimeout, "timeout", 5*time.Second, "Connection timeout to the service socket")
	flag.Parse()
	return flags
}

func setupLogging() {
	logLevel := os.Getenv("LOG_LEVEL")
	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level, AddSource: level <= slog.LevelDebug}))
	slog.SetDefault(logger)
}

func connectToService(socketPath string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("service socket %s not found", socketPath)
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("connection refused %s", socketPath)
		}
		if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			return nil, fmt.Errorf("timeout connecting %s", socketPath)
		}
		return nil, fmt.Errorf("dial service %s failed: %w", socketPath, err)
	}
	return conn, nil
}

func getConfigOverIPC(conn net.Conn, timeout time.Duration) (*config.Config, error) {
	cmd, err := ipc.NewCommand("get_config", nil)
	if err != nil {
		return nil, fmt.Errorf("create get_config cmd: %w", err)
	}
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(cmd); err != nil {
		if isConnectionClosedErr(err) {
			return nil, fmt.Errorf("IPC connection closed before sending get_config: %w", err)
		}
		return nil, fmt.Errorf("send get_config cmd: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	decoder := json.NewDecoder(conn)
	var resp ipc.Response
	if err := decoder.Decode(&resp); err != nil {
		conn.SetReadDeadline(time.Time{})
		if isConnectionClosedErr(err) {
			return nil, fmt.Errorf("IPC connection closed while waiting for get_config response: %w", err)
		}
		return nil, fmt.Errorf("decode get_config resp: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	if resp.Status != ipc.StatusOK {
		return nil, fmt.Errorf("service error: %s", resp.Error)
	}
	var data ipc.GetConfigData
	if err := ipc.DecodeData(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("decode config data from response: %w", err)
	}
	slog.Debug("Got config from service via IPC.")
	return &data.Config, nil
}

func registerWithService(ipcConn net.Conn) error {
	pid := os.Getpid()
	reqData := ipc.RegisterClientData{PID: pid}
	cmd, err := ipc.NewCommand("register_client", reqData)
	if err != nil {
		return fmt.Errorf("create register cmd: %w", err)
	}
	encoder := json.NewEncoder(ipcConn)
	if err := encoder.Encode(cmd); err != nil {
		if isConnectionClosedErr(err) {
			return fmt.Errorf("IPC connection closed before sending register_client: %w", err)
		}
		return fmt.Errorf("send register cmd: %w", err)
	}

	ipcConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(ipcConn)
	var resp ipc.Response
	if err := decoder.Decode(&resp); err != nil {
		ipcConn.SetReadDeadline(time.Time{})
		if isConnectionClosedErr(err) {
			return fmt.Errorf("IPC connection closed while waiting for register_client response: %w", err)
		}
		return fmt.Errorf("decode register resp: %w", err)
	}
	ipcConn.SetReadDeadline(time.Time{})

	if resp.Status != ipc.StatusOK {
		return fmt.Errorf("service registration failed: %s", resp.Error)
	}
	slog.Info("Client registered with service", "pid", pid)
	return nil
}

func listenIPCNotifications(ctx context.Context, initialIPCConn net.Conn, localListener net.Listener, flags clientFlags) {
	defer globalWg.Done()
	var ipcConn net.Conn = initialIPCConn
	var decoder *json.Decoder
	if ipcConn != nil {
		decoder = json.NewDecoder(ipcConn)
	}

	defer func() {
		if ipcConn != nil {
			ipcConn.Close()
		}
	}()

	slog.Info("Listening for IPC notifications...")
	reconnectTicker := time.NewTicker(10 * time.Second)
	defer reconnectTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("IPC listener stopping (context cancelled).")
			return
		default:
		}

		if ipcConn == nil {
			select {
			case <-reconnectTicker.C:
				slog.Info("Attempting IPC reconnect...")
				var err error
				ipcConn, err = connectToService(flags.socketPath, flags.connectTimeout)
				if err != nil {
					slog.Error("IPC reconnect failed, will retry...", "error", err)
					ipcConn = nil
					continue
				}
				if err := registerWithService(ipcConn); err != nil {
					slog.Error("IPC re-register failed after reconnect", "error", err)
					ipcConn.Close()
					ipcConn = nil
					continue
				}
				slog.Info("IPC reconnected and re-registered.")
				decoder = json.NewDecoder(ipcConn)
			case <-ctx.Done():
				return
			}
		}

		if decoder == nil {
			slog.Error("IPC decoder is nil despite connection existing, attempting reconnect")
			ipcConn.Close()
			ipcConn = nil
			continue
		}

		var cmd ipc.Command
		err := decoder.Decode(&cmd)
		if err != nil {
			slog.Warn("Error decoding IPC or connection lost", "error", err)
			ipcConn.Close()
			ipcConn = nil
			decoder = nil
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isConnectionClosedErr(err) {
				slog.Info("IPC connection closed, will attempt reconnect.")
			} else {
				slog.Warn("Unexpected decoding error, will attempt reconnect.", "error", err)
			}
			continue
		}

		if cmd.Command == "notify_accept" {
			var data ipc.NotifyAcceptData
			if err := ipc.DecodeData(cmd.Data, &data); err != nil {
				slog.Error("Decode notify_accept data failed", "error", err)
				continue
			}
			slog.Info("Received accept notification", "dst", data.DstIP, "port", data.DstPort)
			acceptedConn, err := localListener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					slog.Info("Local listener closed, stopping IPC listener.")
					return
				}
				slog.Error("Accept BPF connection failed", "error", err)
				continue
			}
			slog.Debug("Accepted connection from BPF sockmap", "local", acceptedConn.LocalAddr(), "remote", acceptedConn.RemoteAddr())
			if err := workerSemaphore.Acquire(ctx, 1); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					slog.Info("Worker semaphore acquire cancelled or timed out during shutdown")
				} else {
					slog.Error("Acquire worker semaphore failed", "error", err)
				}
				acceptedConn.Close()
				continue
			}
			globalWg.Add(1)
			go func(conn net.Conn, dest ipc.NotifyAcceptData) {
				defer workerSemaphore.Release(1)
				defer globalWg.Done()
				handleAcceptedConnection(conn, dest)
			}(acceptedConn, data)
		} else {
			slog.Warn("Received unexpected IPC command", "command", cmd.Command)
		}
	}
}

func handleAcceptedConnection(acceptedConn net.Conn, originalDest ipc.NotifyAcceptData) {
	defer acceptedConn.Close()
	targetAddr := net.JoinHostPort(originalDest.DstIP, strconv.Itoa(int(originalDest.DstPort)))
	slog.Info("Handling proxied connection", "orig_dst", targetAddr)
	effectiveProxyURL := globalProxyMgr.GetEffectiveProxyURL()
	if effectiveProxyURL == nil {
		slog.Error("No effective proxy URL available", "orig_dst", targetAddr)
		return
	}

	cfg := getConfig()
	proxyDialer := net.Dialer{Timeout: time.Duration(cfg.Proxy.ConnectionTimeout) * time.Second}
	proxyConn, err := proxyDialer.Dial("tcp", effectiveProxyURL.Host)
	if err != nil {
		slog.Error("Failed connect to real proxy", "proxy", effectiveProxyURL.Host, "error", err)
		return
	}
	defer proxyConn.Close()
	slog.Debug("Connected to real proxy", "proxy", effectiveProxyURL.Host)

	if err := establishConnectTunnel(proxyConn, targetAddr, globalKerbClient); err != nil {
		slog.Error("Failed establish CONNECT tunnel", "target", targetAddr, "proxy", effectiveProxyURL.Host, "error", err)
		return
	}
	slog.Debug("CONNECT tunnel established", "target", targetAddr)

	slog.Debug("Starting data relay", "target", targetAddr)
	err = relayDataBidirectionally(acceptedConn, proxyConn)
	if err != nil && !isConnectionClosedErr(err) {
		slog.Warn("Data relay ended with error", "target", targetAddr, "error", err)
	} else {
		slog.Debug("Data relay completed", "target", targetAddr)
	}
}

func establishConnectTunnel(proxyConn net.Conn, targetAddr string, krbClient *kerb.KerberosClient) error {
	slog.Debug("Establishing CONNECT tunnel", "target", targetAddr)
	connectReq := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: targetAddr}, Host: targetAddr, Header: make(http.Header)}
	connectReq.Header.Set("User-Agent", "KernelGatekeeper-Client/1.0")

	// Declare error variables needed later, before the krbClient check
	var kerr error
	var spnegoErr error
	var spnegoTransport http.RoundTripper

	if krbClient != nil {
		// Assign to the pre-declared kerr
		kerr = krbClient.CheckAndRefreshClient()
		if kerr != nil {
			slog.Warn("Kerberos ticket potentially invalid before CONNECT", "error", kerr)
			// Do not return here, allow attempt without SPNEGO maybe
		}

		baseTransport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("dial disabled for SPNEGO prep")
			},
		}
		// Assign to pre-declared spnegoTransport and spnegoErr
		spnegoTransport, spnegoErr = krbClient.CreateProxyTransport(baseTransport)
		if spnegoErr != nil {
			slog.Warn("Failed create SPNEGO transport for CONNECT", "error", spnegoErr)
			spnegoTransport = nil // Ensure it's nil if creation failed
		}
	}

	const maxAuthAttempts = 2
	var resp *http.Response
	cfg := getConfig()

	for attempt := 1; attempt <= maxAuthAttempts; attempt++ {
		currentReq := connectReq.Clone(context.Background())

		// Check spnegoErr here, not kerr
		if spnegoTransport != nil && spnegoErr == nil {
			prepCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			// Use a separate variable for RoundTrip error to avoid shadowing
			_, rtErr := spnegoTransport.RoundTrip(currentReq.WithContext(prepCtx))
			cancel()
			if rtErr != nil && !strings.Contains(rtErr.Error(), "dial disabled") {
				slog.Warn("SPNEGO prep error (ignoring dial disabled)", "error", rtErr)
			}
			slog.Debug("CONNECT headers after SPNEGO prep", "attempt", attempt, "headers", currentReq.Header)
			if currentReq.Header.Get("Proxy-Authorization") == "" && attempt > 1 {
				slog.Warn("SPNEGO did not add Proxy-Authorization header on retry")
			}
		}

		// Declare and use specific error variables for Write and ReadResponse
		var writeErr error
		writeErr = currentReq.Write(proxyConn)
		if writeErr != nil {
			if isConnectionClosedErr(writeErr) {
				return fmt.Errorf("proxy conn closed before CONNECT write (attempt %d): %w", attempt, writeErr)
			}
			return fmt.Errorf("send CONNECT failed (attempt %d): %w", attempt, writeErr)
		}

		deadline := time.Now().Add(time.Duration(cfg.Proxy.RequestTimeout) * time.Second)
		proxyConn.SetReadDeadline(deadline)
		proxyReader := bufio.NewReader(proxyConn)

		var readErr error
		resp, readErr = http.ReadResponse(proxyReader, currentReq)
		proxyConn.SetReadDeadline(time.Time{})

		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				return fmt.Errorf("timeout reading CONNECT resp (attempt %d): %w", attempt, readErr)
			}
			if errors.Is(readErr, io.EOF) || isConnectionClosedErr(readErr) {
				return fmt.Errorf("proxy closed conn unexpectedly after CONNECT write (attempt %d): %w", attempt, readErr)
			}
			return fmt.Errorf("read CONNECT resp failed (attempt %d): %w", attempt, readErr)
		}

		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			slog.Debug("CONNECT tunnel established successfully", "target", targetAddr)
			return nil
		}

		if resp.StatusCode == http.StatusProxyAuthRequired && attempt < maxAuthAttempts && spnegoTransport != nil {
			slog.Info("Received 407 Proxy Auth Required, will retry with SPNEGO", "attempt", attempt)
			resp.Body.Close()
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		// Define errMsg here for this specific failure case
		errMsg := fmt.Sprintf("proxy CONNECT failed (attempt %d): %s (%s)", attempt, resp.Status, strings.TrimSpace(string(bodyBytes)))
		return errors.New(errMsg)
	}

	// Define errMsg here for the "max attempts reached" case
	errMsg := fmt.Sprintf("failed establish CONNECT tunnel after %d attempts", maxAuthAttempts)
	if resp != nil { // resp might be non-nil from the last failed attempt
		errMsg = fmt.Sprintf("%s, last status: %s", errMsg, resp.Status)
	}
	return errors.New(errMsg)
}

func relayDataBidirectionally(conn1, conn2 net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)

	copyData := func(dst, src net.Conn, tag string) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		copied, err := io.CopyBuffer(dst, src, buf)
		slog.Debug("Relay copy finished", "tag", tag, "bytes", copied)
		if err != nil && !isConnectionClosedErr(err) {
			select {
			case errChan <- fmt.Errorf("%s copy failed: %w", tag, err):
			default:
			}
		}
		if tcpDst, ok := dst.(*net.TCPConn); ok {
			_ = tcpDst.CloseWrite() // Ignore error for CloseWrite
		} else {
			slog.Debug("Could not CloseWrite on destination (non-TCP or unsupported)", "tag", tag, "type", reflect.TypeOf(dst))
		}
	}

	go copyData(conn1, conn2, "proxy->client(bpf)")
	go copyData(conn2, conn1, "client(bpf)->proxy")

	wg.Wait()
	close(errChan)

	// Return the first non-nil error if any
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}

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
		strings.Contains(errMsg, "forcibly closed by the remote host") || // Windows specific
		strings.Contains(errMsg, "socket is not connected") {
		return true
	}
	if opErr, ok := err.(*net.OpError); ok {
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
			if errors.Is(sysErr.Err, syscall.EPIPE) || errors.Is(sysErr.Err, syscall.ECONNRESET) || errors.Is(sysErr.Err, syscall.ENOTCONN) {
				return true
			}
		}
		// Check for the specific string within OpError as well
		if opErr.Err != nil && opErr.Err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}

func runBackgroundTasks(ctx context.Context, wg *sync.WaitGroup, flags clientFlags, ipcConn net.Conn) {
	defer wg.Done()
	configRefreshTicker := time.NewTicker(15 * time.Minute)
	defer configRefreshTicker.Stop()
	kerbCheckTicker := time.NewTicker(5 * time.Minute)
	defer kerbCheckTicker.Stop()

	// Use a mutex to protect access to ipcConn, as it can be nilled by listenIPCNotifications
	var ipcConnMu sync.Mutex

	// Goroutine to handle potential niling of ipcConn by listener
	go func() {
		<-ctx.Done() // Wait for context cancellation
		ipcConnMu.Lock()
		if ipcConn != nil {
			// It's generally safer not to close the connection here,
			// let the main shutdown or the listener handle it.
			// ipcConn.Close()
		}
		ipcConn = nil // Ensure it's nil on shutdown
		ipcConnMu.Unlock()
	}()

	for {
		select {
		case <-configRefreshTicker.C:
			slog.Debug("Refreshing config from service...")

			ipcConnMu.Lock()
			currentIPCConn := ipcConn // Get current connection under lock
			ipcConnMu.Unlock()

			if currentIPCConn == nil { // Check if connection is still valid
				slog.Warn("Cannot refresh config, IPC connection is nil (likely disconnected).")
				continue // Skip refresh attempt
			}

			// Perform IPC operation with the captured connection reference
			newCfg, err := getConfigOverIPC(currentIPCConn, flags.connectTimeout)
			if err != nil {
				slog.Warn("Failed refresh config", "error", err)
				if isConnectionClosedErr(err) {
					// Don't close connection here, listener goroutine handles reconnects
					slog.Warn("Config refresh failed due to closed IPC connection.")
				}
				continue // Skip update if refresh failed
			}

			// Compare and apply the new config (no IPC needed here)
			currentCfg := getConfig()
			configChanged := !reflect.DeepEqual(currentCfg.Proxy, newCfg.Proxy) || !reflect.DeepEqual(currentCfg.Kerberos, newCfg.Kerberos)

			if configChanged {
				slog.Info("Config changed, re-initializing proxy/kerberos...")
				setConfig(newCfg) // Update global config

				// Re-init Proxy Manager
				if globalProxyMgr != nil {
					globalProxyMgr.Close()
				}
				newProxyMgr, proxyErr := proxy.NewProxyManager(&newCfg.Proxy) // Use separate error var
				if proxyErr != nil {
					slog.Error("Failed re-init proxy manager after config refresh", "error", proxyErr)
				} else {
					globalProxyMgr = newProxyMgr
					slog.Info("Proxy manager re-initialized.")
				}

				// Re-init or check Kerberos
				if globalKerbClient != nil {
					if krbErr := globalKerbClient.CheckAndRefreshClient(); krbErr != nil { // Use separate error var
						slog.Warn("Failed Kerberos refresh on config change", "error", krbErr)
					} else {
						slog.Info("Kerberos client refreshed/checked.")
					}
				} else {
					newKerbClient, krbErr := kerb.NewKerberosClient(&newCfg.Kerberos) // Use separate error var
					if krbErr != nil {
						slog.Error("Failed initial Kerberos init on config change", "error", krbErr)
					} else {
						globalKerbClient = newKerbClient
						slog.Info("Kerberos client initialized.")
					}
				}
			} else {
				slog.Debug("Configuration unchanged.")
			}
		case <-kerbCheckTicker.C:
			if globalKerbClient != nil {
				slog.Debug("Checking Kerberos ticket...")
				if err := globalKerbClient.CheckAndRefreshClient(); err != nil {
					slog.Warn("Periodic Kerberos check/refresh failed", "error", err)
				}
			}
		case <-ctx.Done():
			slog.Info("Background task runner stopping.")
			return
		}
	}
}

func setConfig(cfg *config.Config) {
	globalConfigMu.Lock()
	globalConfig = cfg
	globalConfigMu.Unlock()
}

func getConfig() config.Config {
	globalConfigMu.RLock()
	defer globalConfigMu.RUnlock()
	if globalConfig == nil {
		slog.Error("Attempted to get config before initialization")
		return config.Config{}
	}
	cfgCopy := *globalConfig
	return cfgCopy
}

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = 0xABCD
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("endian check failed")
	}
}
