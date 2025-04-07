// cmd/client/main.go
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
	"reflect" // Added for DeepEqual
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
	workerSemaphore    *semaphore.Weighted = semaphore.NewWeighted(100) // Limit concurrent handlers
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

	var err error
	var initialConfig *config.Config
	for i := 0; i < 5; i++ {
		initialConfig, err = getConfigFromServer(flags)
		if err == nil {
			break
		}
		slog.Warn("Failed get config, retrying...", "attempt", i+1, "error", err)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			slog.Error("Context cancelled during init")
			os.Exit(1)
		}
	}
	if err != nil {
		slog.Error("Giving up fetching config. Exiting.", "error", err)
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
		os.Exit(1)
	}
	defer listener.Close()
	slog.Info("Started local listener", "address", listenAddress)

	ipcConn, err := connectToService(flags.socketPath, flags.connectTimeout)
	if err != nil {
		slog.Error("Failed connect to service IPC", "socket", flags.socketPath, "error", err)
		os.Exit(1)
	}
	if err := registerWithService(ipcConn); err != nil {
		slog.Error("Failed register with service", "error", err)
		ipcConn.Close()
		os.Exit(1)
	}

	globalWg.Add(1)
	go listenIPCNotifications(ctx, ipcConn, listener, flags) // Pass flags for reconnect
	globalWg.Add(1)
	go runBackgroundTasks(ctx, &globalWg, flags)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("Client running. Waiting for connections and signals.")
	select {
	case sig := <-sigCh:
		slog.Info("Received signal, shutting down...", "signal", sig)
	case <-ctx.Done():
		slog.Info("Context cancelled, shutting down...")
	}
	cancel()         // Signal background tasks via context
	listener.Close() // Close listener to unblock accept
	ipcConn.Close()  // Close IPC
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

func getConfigFromServer(flags clientFlags) (*config.Config, error) {
	conn, err := connectToService(flags.socketPath, flags.connectTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cmd, err := ipc.NewCommand("get_config", nil)
	if err != nil {
		return nil, fmt.Errorf("create cmd: %w", err)
	}
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(cmd); err != nil {
		return nil, fmt.Errorf("send cmd: %w", err)
	}
	conn.SetReadDeadline(time.Now().Add(flags.connectTimeout))
	decoder := json.NewDecoder(conn)
	var resp ipc.Response
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode resp: %w", err)
	}
	if resp.Status != ipc.StatusOK {
		return nil, fmt.Errorf("service error: %s", resp.Error)
	}
	var data ipc.GetConfigData
	if err := ipc.DecodeData(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("decode data: %w", err)
	}
	slog.Debug("Got config from service.")
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
		return fmt.Errorf("send register cmd: %w", err)
	}
	ipcConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(ipcConn)
	var resp ipc.Response
	if err := decoder.Decode(&resp); err != nil {
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
	defer func() {
		if ipcConn != nil {
			ipcConn.Close()
		}
	}()
	slog.Info("Listening for IPC notifications...")
	for {
		select {
		case <-ctx.Done():
			slog.Info("IPC listener stopping (context cancelled).")
			return
		default:
		}
		if ipcConn == nil {
			slog.Info("Attempting IPC reconnect...")
			var err error
			ipcConn, err = connectToService(flags.socketPath, flags.connectTimeout)
			if err != nil {
				slog.Error("IPC reconnect failed, retrying...", "error", err)
				select {
				case <-time.After(10 * time.Second):
					continue
				case <-ctx.Done():
					return
				}
			}
			if err := registerWithService(ipcConn); err != nil {
				slog.Error("IPC re-register failed", "error", err)
				ipcConn.Close()
				ipcConn = nil
				time.Sleep(5 * time.Second)
				continue
			}
			slog.Info("IPC reconnected and re-registered.")
		}
		decoder := json.NewDecoder(ipcConn)
		var cmd ipc.Command
		err := decoder.Decode(&cmd)
		if err != nil {
			slog.Warn("Error decoding IPC or connection lost", "error", err)
			ipcConn.Close()
			ipcConn = nil
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				slog.Info("IPC connection closed, will reconnect.")
			} else {
				slog.Warn("Decoding error, reconnecting.")
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
					slog.Info("Local listener closed.")
					return
				}
				slog.Error("Accept BPF connection failed", "error", err)
				continue
			}
			slog.Debug("Accepted connection from BPF sockmap", "local", acceptedConn.LocalAddr(), "remote", acceptedConn.RemoteAddr())
			if err := workerSemaphore.Acquire(ctx, 1); err != nil {
				slog.Error("Acquire worker semaphore failed", "error", err)
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
		slog.Error("No effective proxy URL", "orig_dst", targetAddr)
		return
	}
	// Convert int seconds from config to time.Duration
	proxyDialer := net.Dialer{Timeout: time.Duration(getConfig().Proxy.ConnectionTimeout) * time.Second}
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
	if err != nil {
		slog.Warn("Data relay ended with error", "target", targetAddr, "error", err)
	} else {
		slog.Debug("Data relay completed", "target", targetAddr)
	}
}

func establishConnectTunnel(proxyConn net.Conn, targetAddr string, krbClient *kerb.KerberosClient) error {
	slog.Debug("Establishing CONNECT tunnel", "target", targetAddr)
	connectReq := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: targetAddr}, Host: targetAddr, Header: make(http.Header)}
	connectReq.Header.Set("User-Agent", "KernelGatekeeper-Client/1.0")
	var err error
	var spnegoTransport http.RoundTripper
	if krbClient != nil {
		// Call exported method
		if kerr := krbClient.CheckAndRefreshClient(); kerr != nil {
			slog.Warn("Kerberos ticket potentially invalid", "error", kerr)
		} else {
			// Note: The RoundTrip call here is a bit of a hack to pre-populate headers.
			// SPNEGO usually works on the response (407) from the proxy.
			// Using a nil dialer prevents actual connection attempts by the transport itself.
			baseTransport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// This dialer should *only* be used for the SPNEGO header generation,
					// not for the actual proxy connection (which is already established).
					return nil, errors.New("dial disabled for SPNEGO prep")
				},
			}
			spnegoTransport, err = krbClient.CreateProxyTransport(baseTransport)
			if err != nil {
				slog.Warn("Failed create SPNEGO transport", "error", err)
				spnegoTransport = nil
			}
		}
	}
	const maxAuthAttempts = 2
	var resp *http.Response
	for attempt := 1; attempt <= maxAuthAttempts; attempt++ {
		currentReq := connectReq.Clone(context.Background())
		if spnegoTransport != nil {
			prepCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			// Use the SPNEGO transport to *modify* the request headers
			_, rtErr := spnegoTransport.RoundTrip(currentReq.WithContext(prepCtx))
			cancel()
			// Expect "dial disabled" error as the transport's dialer is nilled.
			// Any other error during header preparation is potentially problematic.
			if rtErr != nil && !strings.Contains(rtErr.Error(), "dial disabled") {
				slog.Warn("SPNEGO prep error (ignoring dial disabled)", "error", rtErr)
			}
			slog.Debug("CONNECT headers after SPNEGO prep", "attempt", attempt, "headers", currentReq.Header)
			if currentReq.Header.Get("Proxy-Authorization") == "" && attempt > 1 {
				slog.Warn("SPNEGO did not add Proxy-Authorization header on retry")
			}
		}
		if err = currentReq.Write(proxyConn); err != nil {
			if isConnectionClosedErr(err) {
				return fmt.Errorf("proxy conn closed before CONNECT write: %w", err)
			}
			return fmt.Errorf("send CONNECT failed (attempt %d): %w", attempt, err)
		}
		// Convert int seconds from config to time.Duration
		deadline := time.Now().Add(time.Duration(getConfig().Proxy.RequestTimeout) * time.Second)
		proxyConn.SetReadDeadline(deadline)
		proxyReader := bufio.NewReader(proxyConn)
		resp, err = http.ReadResponse(proxyReader, currentReq)
		proxyConn.SetReadDeadline(time.Time{})
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return fmt.Errorf("timeout reading CONNECT resp (attempt %d): %w", attempt, err)
			}
			// If EOF happens before getting a response, especially on retry, proxy might have closed conn.
			if errors.Is(err, io.EOF) { // Removed check `&& resp == nil && attempt < maxAuthAttempts` as resp might be non-nil but incomplete
				return fmt.Errorf("proxy closed conn unexpectedly after CONNECT write (attempt %d): %w", attempt, err)
			}
			return fmt.Errorf("read CONNECT resp failed (attempt %d): %w", attempt, err)
		}
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp.StatusCode == http.StatusProxyAuthRequired && attempt < maxAuthAttempts && spnegoTransport != nil {
			slog.Info("Received 407 Proxy Auth Required, will retry with SPNEGO", "attempt", attempt)
			// The SPNEGO transport should handle the 407 response headers in the next RoundTrip call.
			// We just need to loop again.
			resp.Body.Close()
			// Potentially extract WWW-Authenticate header here if needed for debugging
			// wwwAuth := resp.Header.Get("Proxy-Authenticate")
			// slog.Debug("Received Proxy-Authenticate header", "header", wwwAuth)
			continue
		}
		// Handle other errors or final failure
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		errMsg := fmt.Sprintf("proxy CONNECT failed (attempt %d): %s (%s)", attempt, resp.Status, strings.TrimSpace(string(bodyBytes)))
		return errors.New(errMsg)
	}
	// If loop finishes without success
	errMsg := fmt.Sprintf("failed establish CONNECT tunnel after %d attempts", maxAuthAttempts)
	if resp != nil {
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
		// Use a larger buffer? Default is 32KB which should be fine.
		buf := make([]byte, 32*1024) // io.Copy uses 32KB buffer by default
		copied, err := io.CopyBuffer(dst, src, buf)
		slog.Debug("Relay copy finished", "tag", tag, "bytes", copied)
		if err != nil && !isConnectionClosedErr(err) {
			select {
			case errChan <- fmt.Errorf("%s copy failed: %w", tag, err):
			default: // Avoid blocking if channel is full (shouldn't happen with size 2)
			}
		}
		// Signal peer that we are done writing.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else if tcpDst, ok := dst.(*net.TCPConn); ok {
			tcpDst.CloseWrite()
		} else {
			// Fallback: Close the whole connection if CloseWrite isn't available.
			// This might prematurely close the read side if the peer is still sending.
			// dst.Close()
			slog.Debug("Could not CloseWrite on destination", "tag", tag, "type", reflect.TypeOf(dst))
		}
	}
	go copyData(conn1, conn2, "proxy->client(bpf)")
	go copyData(conn2, conn1, "client(bpf)->proxy")
	wg.Wait()
	close(errChan)
	// Return the first error encountered, if any
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
	// Check for standard closed connection errors
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	// Check for specific error strings that indicate a closed connection
	errMsg := err.Error()
	if strings.Contains(errMsg, "use of closed network connection") || strings.Contains(errMsg, "broken pipe") || strings.Contains(errMsg, "connection reset by peer") {
		return true
	}
	// Check OpError for closed connection specifically
	if opErr, ok := err.(*net.OpError); ok {
		if opErr.Err != nil {
			errMsg := opErr.Err.Error()
			if strings.Contains(errMsg, "use of closed network connection") {
				return true
			}
			// Check underlying syscall errors wrapped in OpError
			if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
				if errors.Is(sysErr.Err, syscall.EPIPE) || errors.Is(sysErr.Err, syscall.ECONNRESET) {
					return true
				}
			}
		}
	}
	return false
}

func runBackgroundTasks(ctx context.Context, wg *sync.WaitGroup, flags clientFlags) {
	defer wg.Done()
	configRefreshTicker := time.NewTicker(15 * time.Minute)
	defer configRefreshTicker.Stop()
	kerbCheckTicker := time.NewTicker(5 * time.Minute)
	defer kerbCheckTicker.Stop()
	for {
		select {
		case <-configRefreshTicker.C:
			slog.Debug("Refreshing config from service...")
			newCfg, err := getConfigFromServer(flags)
			if err != nil {
				slog.Warn("Failed refresh config", "error", err)
				continue
			}
			globalConfigMu.Lock()
			configChanged := globalConfig == nil || !reflect.DeepEqual(globalConfig.Proxy, newCfg.Proxy) || !reflect.DeepEqual(globalConfig.Kerberos, newCfg.Kerberos)
			if configChanged {
				// Only update if changed to avoid unnecessary re-init
				globalConfig = newCfg
			}
			globalConfigMu.Unlock()

			if configChanged {
				slog.Info("Config changed, re-initializing proxy/kerberos...")
				// Re-init Proxy Manager
				if globalProxyMgr != nil {
					globalProxyMgr.Close() // Close old manager first
				}
				newProxyMgr, err := proxy.NewProxyManager(&newCfg.Proxy)
				if err != nil {
					slog.Error("Failed re-init proxy manager", "error", err)
				} else {
					globalProxyMgr = newProxyMgr // Assign new manager
				}

				// Re-init or check Kerberos
				if globalKerbClient != nil {
					// Check if Kerberos config actually changed significantly
					// For now, always check/refresh if any config changed
					// Call exported method
					if err := globalKerbClient.CheckAndRefreshClient(); err != nil {
						slog.Warn("Failed Kerberos refresh on config change", "error", err)
					}
				} else {
					// Initialize Kerberos if it wasn't before
					newKerbClient, err := kerb.NewKerberosClient(&newCfg.Kerberos)
					if err != nil {
						slog.Error("Failed initial Kerberos init on config change", "error", err)
					} else {
						globalKerbClient = newKerbClient // Assign new client
					}
				}
			} else {
				slog.Debug("Configuration unchanged.")
			}
		case <-kerbCheckTicker.C:
			if globalKerbClient != nil {
				slog.Debug("Checking Kerberos ticket...")
				// Call exported method
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
		// Return a default config or handle error appropriately
		slog.Error("Attempted to get config before initialization")
		return config.Config{} // Return zero value config
	}
	// Return a deep copy to prevent race conditions if the caller modifies the config
	cfgCopy := *globalConfig
	// Deep copy slices/maps if necessary, though current fields are value types or pointers managed elsewhere
	// Example: cfgCopy.EBPF.TargetPorts = append([]int{}, globalConfig.EBPF.TargetPorts...)
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
