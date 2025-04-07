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

type Service struct {
	configPath  string
	config      *config.Config
	configMu    sync.RWMutex
	bpfManager  *ebpf.BPFManager
	ipcListener net.Listener
	ipcClients  struct {
		sync.RWMutex
		conns map[net.Conn]uint32
	}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("PANIC", "error", r, "stack", string(debug.Stack()))
			os.Exit(1)
		}
	}()

	configPath := flag.String("config", "/etc/kernelgatekeeper/config.yaml", "Path to config file")
	showVersion := flag.Bool("version", false, "Show service version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("KernelGatekeeper Service %s, commit %s, built at %s\n", version, commit, date)
		return
	}

	initialCfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Load config %s failed: %v\n", *configPath, err)
		os.Exit(1)
	}

	setupLogging(initialCfg.LogLevel, initialCfg.LogPath)
	slog.Info("KernelGatekeeper Service starting", "version", version, "commit", commit, "date", date)
	slog.Info("Using configuration file", "path", *configPath)

	svc := &Service{configPath: *configPath, config: initialCfg}
	svc.ipcClients.conns = make(map[net.Conn]uint32)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notificationChan := make(chan ebpf.NotificationTuple, 1024)

	if err := svc.initComponents(notificationChan); err != nil {
		slog.Error("Failed init components", "error", err)
		os.Exit(1)
	}

	defer svc.Close()

	svc.startBackgroundTasks(ctx, notificationChan)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	slog.Info("Service started. Listening for signals...")

	keepRunning := true
	for keepRunning {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("Received termination signal", "signal", sig)
				keepRunning = false
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), svc.config.ShutdownTimeout)
				svc.Shutdown(shutdownCtx)
				shutdownCancel()
				cancel()
			case syscall.SIGHUP:
				slog.Info("Received SIGHUP, reloading configuration...")
				if err := svc.reloadConfig(); err != nil {
					slog.Error("Failed reload config", "error", err)
				} else {
					slog.Info("Config reloaded.")
				}
			}
		case <-ctx.Done():
			slog.Info("Main context cancelled, initiating shutdown.")
			keepRunning = false
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), svc.config.ShutdownTimeout)
			svc.Shutdown(shutdownCtx)
			shutdownCancel()
		}
	}

	slog.Info("Waiting for background tasks to finish...")
	svc.wg.Wait()
	slog.Info("Service stopped.")
}

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
		level = slog.LevelInfo
	}

	var logWriter io.Writer = os.Stderr
	if logPath != "" {
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("Failed open log file, fallback stderr", "path", logPath, "error", err)
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

func (s *Service) initComponents(notificationChan chan ebpf.NotificationTuple) error {
	slog.Info("Initializing BPF Manager...")
	var err error
	s.bpfManager, err = ebpf.NewBPFManager(&s.config.EBPF, notificationChan)
	if err != nil {
		return fmt.Errorf("failed init BPF manager: %w", err)
	}
	slog.Info("BPF Manager initialized.")
	return nil
}

func (s *Service) startBackgroundTasks(ctx context.Context, notificationChan chan ebpf.NotificationTuple) {
	slog.Info("Starting background tasks...")
	if err := s.bpfManager.Start(ctx, &s.wg); err != nil {
		slog.Error("Failed start BPF manager tasks", "error", err)
	}

	s.wg.Add(1)
	go s.processBPFNotifications(ctx, notificationChan)

	if err := s.startIPCListener(ctx); err != nil {
		slog.Error("Failed start IPC listener", "error", err)
	}
	slog.Info("Background tasks started.")
}

func (s *Service) processBPFNotifications(ctx context.Context, notifChan <-chan ebpf.NotificationTuple) {
	defer s.wg.Done()
	slog.Info("Starting BPF notification processor...")

	for {
		select {
		case <-ctx.Done():
			slog.Info("BPF notification processor stopping (context cancelled).")
			return
		case notification, ok := <-notifChan:
			if !ok {
				slog.Info("BPF notification channel closed.")
				return
			}
			slog.Debug("Received BPF notification tuple", "tuple", notification)
			pid, err := s.bpfManager.GetConnectionPID(notification)
			if err != nil {
				slog.Warn("Could not get PID for connection tuple", "tuple", notification, "error", err)
				continue
			}
			uid, err := ebpf.GetUidFromPid(pid)
			if err != nil {
				slog.Warn("Could not get UID for PID", "pid", pid, "error", err)
				continue
			}
			s.ipcClients.RLock()
			clientConn := s.findClientConnByUID(uid)
			s.ipcClients.RUnlock()

			if clientConn == nil {
				slog.Debug("No registered client found for UID", "uid", uid, "pid", pid)
				continue
			}
			slog.Info("Found registered client for connection", "uid", uid, "pid", pid, "tuple", notification)
			ipcNotifData := ipc.NotifyAcceptData{
				SrcIP:    notification.SrcIP.String(),
				DstIP:    notification.DstIP.String(),
				SrcPort:  notification.SrcPort,
				DstPort:  notification.DstPort,
				Protocol: notification.Protocol,
			}
			ipcCmd, err := ipc.NewCommand("notify_accept", ipcNotifData)
			if err != nil {
				slog.Error("Failed create IPC notification command", "error", err)
				continue
			}
			s.sendToClient(clientConn, ipcCmd)
		}
	}
}

func (s *Service) findClientConnByUID(uid uint32) net.Conn {
	for conn, clientUID := range s.ipcClients.conns {
		if clientUID == uid {
			return conn
		}
	}
	return nil
}

func (s *Service) sendToClient(conn net.Conn, cmd *ipc.Command) {
	go func(c net.Conn, command *ipc.Command) {
		encoder := json.NewEncoder(c)
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		err := encoder.Encode(command)
		c.SetWriteDeadline(time.Time{})

		if err != nil {
			slog.Warn("Failed send command to client, removing client", "command", command.Command, "client_uid", s.getClientUID(c), "error", err)
			s.removeClientConn(c)
		} else {
			slog.Debug("Sent command to client", "command", command.Command, "client_uid", s.getClientUID(c))
		}
	}(conn, cmd)
}

func (s *Service) getClientUID(conn net.Conn) uint32 {
	if uid, ok := s.ipcClients.conns[conn]; ok {
		return uid
	}
	return 0
}

func (s *Service) startIPCListener(ctx context.Context) error {
	socketPath := s.getConfig().SocketPath
	dir := filepath.Dir(socketPath)

	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("mkdir IPC dir %s failed: %w", dir, err)
	}

	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove old IPC socket %s failed: %w", socketPath, err)
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen IPC socket %s failed: %w", socketPath, err)
	}
	s.ipcListener = l

	if err := os.Chmod(socketPath, 0666); err != nil { // Changed permission to 0666
		l.Close()
		return fmt.Errorf("chmod IPC socket %s to 0666 failed: %w", socketPath, err)
	}

	slog.Info("IPC listener started", "path", socketPath, "permissions", "0666")

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		slog.Info("Closing IPC listener due to context cancellation...")
		s.ipcListener.Close()
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.ipcListener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					slog.Info("IPC listener closed.")
					return
				}
				slog.Error("IPC accept failed", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				s.handleIPCConnection(c)
			}(conn)
		}
	}()
	return nil
}

func (s *Service) addClientConn(conn net.Conn, uid uint32) {
	s.ipcClients.Lock()
	defer s.ipcClients.Unlock()
	s.ipcClients.conns[conn] = uid
	slog.Debug("IPC client added", "remote_addr", conn.RemoteAddr(), "uid", uid, "total_clients", len(s.ipcClients.conns))
}

func (s *Service) removeClientConn(conn net.Conn) {
	s.ipcClients.Lock()
	uid, ok := s.ipcClients.conns[conn]
	delete(s.ipcClients.conns, conn)
	s.ipcClients.Unlock()
	conn.Close()

	if ok {
		slog.Info("IPC client removed", "remote_addr", conn.RemoteAddr(), "uid", uid, "total_clients", s.getClientCount())
	} else {
		slog.Debug("Attempted to remove non-existent or already removed IPC client", "remote_addr", conn.RemoteAddr())
	}
}

func (s *Service) getClientCount() int {
	s.ipcClients.RLock()
	defer s.ipcClients.RUnlock()
	return len(s.ipcClients.conns)
}

func (s *Service) handleIPCConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()
	slog.Debug("Handling new IPC connection", "client", clientAddr)
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var clientUID uint32
	registered := false

	defer func() {
		if registered {
			s.removeClientConn(conn)
		} else {
			conn.Close()
		}
		slog.Debug("Finished handling IPC connection", "client", clientAddr)
	}()

	for {
		var cmd ipc.Command
		err := decoder.Decode(&cmd)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				slog.Debug("IPC connection closed by client or server", "client", clientAddr)
			} else {
				slog.Error("Failed decode IPC command", "client", clientAddr, "error", err)
			}
			return
		}
		slog.Info("Received IPC command", "command", cmd.Command, "client", clientAddr)
		resp, err := s.processIPCCommand(conn, &cmd, &clientUID, &registered)
		if err != nil {
			resp = ipc.NewErrorResponse(err.Error())
		}
		if err := encoder.Encode(resp); err != nil {
			slog.Error("Failed encode IPC response", "client", clientAddr, "cmd", cmd.Command, "error", err)
			return
		}
	}
}

func (s *Service) processIPCCommand(conn net.Conn, cmd *ipc.Command, clientUID *uint32, registered *bool) (*ipc.Response, error) {
	switch cmd.Command {
	case "register_client":
		if *registered {
			return nil, errors.New("client already registered on this connection")
		}
		var data ipc.RegisterClientData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid register_client data: %w", err)
		}
		peerCred, err := getPeerCredFromConn(conn)
		if err != nil {
			slog.Error("Failed get peer credentials for registering client", "error", err)
			return nil, errors.New("cannot verify client credentials")
		}
		uid := peerCred.Uid
		*clientUID = uid
		*registered = true
		s.addClientConn(conn, uid)
		slog.Info("Client registered successfully", "uid", uid, "pid", data.PID)
		return ipc.NewOKResponse("Client registered successfully")

	case "get_config":
		if !*registered {
			return nil, errors.New("client not registered")
		}
		cfg := s.getConfig()
		return ipc.NewOKResponse(ipc.GetConfigData{Config: cfg})

	case "update_ports":
		if !*registered {
			return nil, errors.New("client not registered")
		}
		if !s.getConfig().EBPF.AllowDynamicPorts {
			return nil, errors.New("dynamic port updates disabled by configuration")
		}
		var data ipc.UpdatePortsData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid update_ports data: %w", err)
		}
		if s.bpfManager == nil {
			return nil, errors.New("BPF manager not ready")
		}
		if err := s.bpfManager.UpdateTargetPorts(data.Ports); err != nil {
			slog.Error("Failed update target ports via IPC", "error", err)
			return nil, fmt.Errorf("BPF update failed: %w", err)
		}
		s.configMu.Lock()
		s.config.EBPF.TargetPorts = data.Ports
		s.configMu.Unlock()
		slog.Info("Target ports updated via IPC", "ports", data.Ports, "client_uid", *clientUID)
		return ipc.NewOKResponse("Ports updated successfully")

	case "get_status":
		if !*registered {
			return nil, errors.New("client not registered")
		}
		return s.getStatusResponse()

	case "get_interfaces":
		if !*registered {
			return nil, errors.New("client not registered")
		}
		return s.getInterfacesResponse()

	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Command)
	}
}

func getPeerCredFromConn(conn net.Conn) (*unix.Ucred, error) {
	unixConn, ok := conn.(interface {
		File() (*os.File, error)
	})
	if !ok {
		return nil, errors.New("connection does not support File()")
	}
	file, err := unixConn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get File() from connection: %w", err)
	}
	defer file.Close()

	ucred, err := unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED failed: %w", err)
	}
	return ucred, nil
}

func (s *Service) getStatusResponse() (*ipc.Response, error) {
	cfg := s.getConfig()
	statusData := ipc.GetStatusData{
		Status:          "running",
		ActiveInterface: cfg.EBPF.Interface,
		ActivePorts:     cfg.EBPF.TargetPorts,
		LoadMode:        "sockops/skmsg",
		UptimeSeconds:   int64(time.Since(startTime).Seconds()),
		ServiceVersion:  version,
	}

	if s.bpfManager != nil {
		_, matched, err := s.bpfManager.GetStats()
		if err != nil {
			slog.Warn("Failed get eBPF stats for status response", "error", err)
		} else {
			statusData.MatchedConns = matched.Packets
			statusData.MatchedBytes = matched.Bytes
		}
	}
	return ipc.NewOKResponse(statusData)
}

func (s *Service) getInterfacesResponse() (*ipc.Response, error) {
	interfaces, err := ebpf.GetAvailableInterfaces()
	if err != nil {
		slog.Error("Failed get interfaces for response", "error", err)
		return nil, fmt.Errorf("interface list failed: %w", err)
	}
	currentInterface := s.getConfig().EBPF.Interface
	data := ipc.GetInterfacesData{Interfaces: interfaces, CurrentInterface: currentInterface}
	return ipc.NewOKResponse(data)
}

func (s *Service) getConfig() config.Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	cfgCopy := *s.config
	cfgCopy.EBPF.TargetPorts = append([]int{}, s.config.EBPF.TargetPorts...)
	return cfgCopy
}

func (s *Service) reloadConfig() error {
	slog.Info("Reloading configuration...", "path", s.configPath)
	newCfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return fmt.Errorf("load new config failed: %w", err)
	}

	s.configMu.Lock()
	oldCfg := s.config
	s.config = newCfg
	s.configMu.Unlock()

	setupLogging(newCfg.LogLevel, newCfg.LogPath)

	if s.bpfManager != nil {
		if newCfg.EBPF.AllowDynamicPorts && !equalIntSlice(oldCfg.EBPF.TargetPorts, newCfg.EBPF.TargetPorts) {
			slog.Info("Applying updated target ports from reloaded config...", "ports", newCfg.EBPF.TargetPorts)
			if err := s.bpfManager.UpdateTargetPorts(newCfg.EBPF.TargetPorts); err != nil {
				slog.Error("Failed update target ports on config reload", "error", err)
				s.configMu.Lock()
				s.config.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
				s.configMu.Unlock()
			}
		}
	} else {
		slog.Warn("Cannot apply BPF config changes on reload: BPF manager not initialized")
	}
	slog.Info("Configuration reload finished.")
	return nil
}

func (s *Service) Shutdown(ctx context.Context) {
	s.stopOnce.Do(func() {
		slog.Info("Initiating graceful shutdown...")
		if s.ipcListener != nil {
			slog.Debug("Closing IPC listener...")
			s.ipcListener.Close()
		}
		s.ipcClients.Lock()
		connsToClose := make([]net.Conn, 0, len(s.ipcClients.conns))
		for c := range s.ipcClients.conns {
			connsToClose = append(connsToClose, c)
		}
		s.ipcClients.Unlock()

		slog.Debug("Closing active IPC client connections...", "count", len(connsToClose))
		for _, c := range connsToClose {
			c.Close()
		}
		if s.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			if err := s.bpfManager.Close(); err != nil {
				slog.Error("Error closing BPF manager", "error", err)
			}
		}
		slog.Info("Shutdown sequence initiated. Waiting for tasks to complete...")
	})
}

func (s *Service) Close() {
	shutdownTimeout := 5 * time.Second
	if s.config != nil && s.config.ShutdownTimeout > 0 {
		shutdownTimeout = min(s.config.ShutdownTimeout, 10*time.Second)
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	s.Shutdown(ctx)
}

func equalIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	bMap := make(map[int]struct{}, len(b))
	for _, x := range b {
		bMap[x] = struct{}{}
	}
	for _, x := range a {
		if _, ok := bMap[x]; !ok {
			return false
		}
	}
	return true
}
