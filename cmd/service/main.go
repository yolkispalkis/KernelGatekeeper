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
	slog.Info("Waiting for background tasks...")
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
	opts := &slog.HandlerOptions{Level: level, AddSource: level <= slog.LevelDebug}
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
			slog.Debug("Received BPF notification from BPFManager", "tuple", notification)
			ipcNotifData := ipc.NotifyAcceptData{SrcIP: notification.SrcIP.String(), DstIP: notification.DstIP.String(), SrcPort: notification.SrcPort, DstPort: notification.DstPort, Protocol: notification.Protocol}
			ipcCmd, err := ipc.NewCommand("notify_accept", ipcNotifData)
			if err != nil {
				slog.Error("Failed create IPC notification", "error", err)
				continue
			}
			s.broadcastToClients(ipcCmd)
		}
	}
}

func (s *Service) broadcastToClients(cmd *ipc.Command) {
	s.ipcClients.RLock()
	defer s.ipcClients.RUnlock()
	if len(s.ipcClients.conns) == 0 {
		return
	}
	slog.Debug("Broadcasting IPC command", "command", cmd.Command, "clients", len(s.ipcClients.conns))
	activeConns := make([]net.Conn, 0, len(s.ipcClients.conns))
	for conn := range s.ipcClients.conns {
		activeConns = append(activeConns, conn)
	}

	for _, conn := range activeConns {
		go func(c net.Conn, command *ipc.Command) {
			encoder := json.NewEncoder(c)
			c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			err := encoder.Encode(command)
			c.SetWriteDeadline(time.Time{})
			if err != nil {
				slog.Warn("Failed send broadcast to client, removing", "command", command.Command, "error", err)
				s.removeClientConn(c)
			}
		}(conn, cmd)
	}
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
	if err := os.Chmod(socketPath, 0660); err != nil {
		l.Close()
		return fmt.Errorf("chmod IPC socket %s failed: %w", socketPath, err)
	}
	slog.Info("IPC listener started", "path", socketPath)
	s.wg.Add(1)
	go func() { defer s.wg.Done(); <-ctx.Done(); s.ipcListener.Close() }()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.ipcListener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					slog.Info("IPC listener closed")
					return
				}
				slog.Error("IPC accept failed", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			s.wg.Add(1)
			go func(c net.Conn) { defer s.wg.Done(); s.handleIPCConnection(c) }(conn)
		}
	}()
	return nil
}

func (s *Service) addClientConn(conn net.Conn, uid uint32) {
	s.ipcClients.Lock()
	defer s.ipcClients.Unlock()
	s.ipcClients.conns[conn] = uid
	slog.Debug("IPC client added", "addr", conn.RemoteAddr(), "uid", uid)
}

func (s *Service) removeClientConn(conn net.Conn) {
	s.ipcClients.Lock()
	uid, ok := s.ipcClients.conns[conn]
	delete(s.ipcClients.conns, conn)
	s.ipcClients.Unlock()

	if ok && s.bpfManager != nil {
		slog.Info("IPC client disconnected, unregistering from BPF", "uid", uid)
		if err := s.bpfManager.UnregisterClientProcess(uid); err != nil {
			slog.Error("Failed unregister client from BPF map", "uid", uid, "error", err)
		}
	}
	conn.Close()
	slog.Debug("IPC client removed", "addr", conn.RemoteAddr(), "uid", uid)
}

func (s *Service) handleIPCConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()
	slog.Debug("Handling IPC connection", "client", clientAddr)
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
	}()

	for {
		var cmd ipc.Command
		err := decoder.Decode(&cmd)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
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
			return nil, fmt.Errorf("invalid data: %w", err)
		}
		if s.bpfManager == nil {
			return nil, errors.New("BPF manager not ready")
		}
		peerCred, err := getPeerCredFromConn(conn)
		if err != nil {
			slog.Error("Failed get peer credentials", "error", err)
			return nil, errors.New("cannot verify client credentials")
		}
		uid := peerCred.Uid
		pid := uint64(data.PID)

		mapValue := ebpf.BpfClientProcessInfoT{PidTgid: (pid << 32) | pid}
		if err := s.bpfManager.RegisterClientProcess(uid, mapValue); err != nil {
			slog.Error("Failed register client in BPF", "uid", uid, "pid", pid, "error", err)
			return nil, fmt.Errorf("BPF map update failed: %w", err)
		}
		*clientUID = uid
		*registered = true
		s.addClientConn(conn, uid)
		slog.Info("Client registered", "uid", uid, "pid", pid)
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
			return nil, errors.New("dynamic port updates disabled")
		}
		var data ipc.UpdatePortsData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid data: %w", err)
		}
		if s.bpfManager == nil {
			return nil, errors.New("BPF manager not ready")
		}
		if err := s.bpfManager.UpdateTargetPorts(data.Ports); err != nil {
			slog.Error("Failed update target ports", "error", err)
			return nil, fmt.Errorf("BPF update failed: %w", err)
		}
		s.configMu.Lock()
		s.config.EBPF.TargetPorts = data.Ports
		s.configMu.Unlock()
		slog.Info("Target ports updated via IPC", "ports", data.Ports, "uid", *clientUID)
		return ipc.NewOKResponse(nil)

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
	file, err := conn.(interface{ File() (*os.File, error) }).File()
	if err != nil {
		return nil, fmt.Errorf("get File() failed: %w", err)
	}
	defer file.Close()

	return unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
}

func (s *Service) getStatusResponse() (*ipc.Response, error) {
	cfg := s.getConfig()
	statusData := ipc.GetStatusData{Status: "running", ActiveInterface: cfg.EBPF.Interface, ActivePorts: cfg.EBPF.TargetPorts, LoadMode: "sockops/skmsg", UptimeSeconds: int64(time.Since(startTime).Seconds()), ServiceVersion: version}
	if s.bpfManager != nil {
		total, matched, err := s.bpfManager.GetStats()
		if err != nil {
			slog.Warn("Failed get eBPF stats", "error", err)
		} else {
			statusData.TotalPackets = total.Packets
			statusData.TotalBytes = total.Bytes
			statusData.MatchedConns = matched.Packets
			statusData.MatchedBytes = matched.Bytes
		}
	}
	return ipc.NewOKResponse(statusData)
}

func (s *Service) getInterfacesResponse() (*ipc.Response, error) {
	interfaces, err := ebpf.GetAvailableInterfaces()
	if err != nil {
		slog.Error("Failed get interfaces", "error", err)
		return nil, fmt.Errorf("if list failed: %w", err)
	}
	data := ipc.GetInterfacesData{Interfaces: interfaces, CurrentInterface: s.getConfig().EBPF.Interface}
	return ipc.NewOKResponse(data)
}

func (s *Service) getConfig() config.Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	cfgCopy := *s.config
	return cfgCopy
}

func (s *Service) reloadConfig() error {
	slog.Info("Reloading configuration...", "path", s.configPath)
	newCfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return fmt.Errorf("load failed: %w", err)
	}
	s.configMu.Lock()
	oldCfg := s.config
	s.config = newCfg
	s.configMu.Unlock()
	setupLogging(newCfg.LogLevel, newCfg.LogPath)
	if s.bpfManager != nil {
		if newCfg.EBPF.AllowDynamicPorts && !equalIntSlice(oldCfg.EBPF.TargetPorts, newCfg.EBPF.TargetPorts) {
			slog.Info("Applying updated target ports...", "ports", newCfg.EBPF.TargetPorts)
			if err := s.bpfManager.UpdateTargetPorts(newCfg.EBPF.TargetPorts); err != nil {
				slog.Error("Failed update ports on reload", "error", err)
				s.configMu.Lock()
				s.config.EBPF.TargetPorts = oldCfg.EBPF.TargetPorts
				s.configMu.Unlock()
			}
		}

	} else {
		return errors.New("BPF manager not initialized, cannot apply BPF config changes")
	}
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
		for _, c := range connsToClose {
			c.Close()
		}
		if s.bpfManager != nil {
			slog.Debug("Closing BPF manager...")
			s.bpfManager.Close()
		}
		slog.Info("Shutdown sequence initiated.")
	})
}
func (s *Service) Close() {
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	s.Shutdown(ctx)
}
func equalIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
