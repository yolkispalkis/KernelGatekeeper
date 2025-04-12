package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/clientcore"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/common" // Import common
	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/kerb"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/logging"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/proxy"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/signals"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type clientFlags struct {
	configPath     string
	socketPath     string
	showVersion    bool
	connectTimeout time.Duration
	logLevel       string
}

func main() {
	var globalShutdownOnce sync.Once
	ctx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "CLIENT PANIC: %v\n%s\n", r, string(debug.Stack()))
			signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
			time.Sleep(1 * time.Second)
			os.Exit(1)
		}
	}()

	flags := parseFlags()
	if flags.showVersion {
		fmt.Printf("KernelGatekeeper Client %s, commit %s, built at %s\n", version, commit, date)
		return
	}

	cfg, err := config.LoadConfig(flags.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Failed to load configuration %s: %v\n", flags.configPath, err)
		os.Exit(1)
	}

	logLvl := cfg.LogLevel
	if flags.logLevel != "" {
		logLvl = flags.logLevel
	}
	logging.Setup(logLvl, "", os.Stderr)
	slog.Info("Starting KernelGatekeeper Client (Getsockopt Model)", "version", version, "pid", os.Getpid())
	slog.Info("Using configuration file", "path", flags.configPath)

	signals.SetupHandler(ctx, rootCancel, &globalShutdownOnce)

	// FIX: Pass cfg to NewStateManager (assuming the incompatible type error was due to import cycle)
	// The error message "cannot use cfg (...) as *invalid type value" strongly suggests the type was unresolved due to the cycle.
	// Assuming NewStateManager takes *config.Config
	stateManager := clientcore.NewStateManager(cfg)

	kClient, kerr := kerb.NewKerberosClient(&cfg.Kerberos)
	if kerr != nil {
		slog.Error("Failed to initialize Kerberos client", "error", kerr)

	} else {
		stateManager.SetKerberosClient(kClient)
		slog.Info("Kerberos client initialized.")
	}

	pMgr, perr := proxy.NewProxyManager(&cfg.Proxy)
	if perr != nil {
		slog.Error("Failed to initialize Proxy Manager", "error", perr)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		if kClient != nil {
			kClient.Close()
		}
		os.Exit(1)
	}
	stateManager.SetProxyManager(pMgr)
	slog.Info("Proxy Manager initialized.")

	localListener := clientcore.NewLocalListener(cfg.ClientListenerPort)
	if err := localListener.Start(); err != nil {
		slog.Error("Failed to start local listener", "address", localListener.Addr(), "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		stateManager.Cleanup()
		os.Exit(1)
	}
	defer localListener.Close()

	ipcSocketPath := flags.socketPath
	if ipcSocketPath == "" {
		ipcSocketPath = common.DefaultSocketPath // Use common
	}
	ipcManager := clientcore.NewIPCManager(ctx, stateManager, ipcSocketPath, flags.connectTimeout)

	connectionHandler := clientcore.NewConnectionHandler(stateManager)

	ipcManager.Run()

	if err := ipcManager.WaitForInitialConnection(flags.connectTimeout + 5*time.Second); err != nil {
		slog.Error("Failed to establish initial connection to service", "error", err)

		ipcManager.Stop()
		localListener.Close()
		stateManager.Cleanup()
		os.Exit(1)
	}
	slog.Info("Successfully connected to service IPC.")

	backgroundTasks := clientcore.NewBackgroundTasks(ctx, stateManager, ipcManager)
	backgroundTasks.Run()

	slog.Info("Client initialization complete. Ready to accept proxied connections.")

	acceptLoopWg := sync.WaitGroup{}
	acceptLoopWg.Add(1)
	go func() {
		defer acceptLoopWg.Done()
		runAcceptLoop(ctx, localListener.GetListener(), connectionHandler, stateManager)
	}()

	<-ctx.Done()
	slog.Info("Shutdown initiated. Waiting for connections, IPC, and background tasks...")

	localListener.Close()
	acceptLoopWg.Wait()
	slog.Debug("Accept loop finished.")

	ipcManager.Stop()
	stateManager.Cleanup()

	slog.Info("Client exited gracefully.")
}

func runAcceptLoop(ctx context.Context, listener net.Listener, handler *clientcore.ConnectionHandler, stateMgr *clientcore.StateManager) {
	slog.Info("Starting accept loop for redirected connections...")
	defer slog.Info("Accept loop stopped.")

	for {
		conn, err := listener.Accept()
		if err != nil {

			select {
			case <-ctx.Done():
				slog.Info("Accept loop exiting due to context cancellation.")
				return
			default:
			}

			if errors.Is(err, net.ErrClosed) {
				slog.Info("Listener closed, stopping accept loop.")
				return
			}
			slog.Error("Failed to accept connection", "error", err)

			time.Sleep(100 * time.Millisecond)
			continue
		}

		go handler.HandleIncomingConnection(ctx, conn)
	}
}

func parseFlags() clientFlags {
	var flags clientFlags

	defaultConfigPath := "/etc/kernelgatekeeper/config.yaml"
	homeDir, err := os.UserHomeDir()
	if err == nil {
		userConfigPath := filepath.Join(homeDir, ".config", "kernelgatekeeper", "config.yaml")
		if _, statErr := os.Stat(userConfigPath); statErr == nil {
			defaultConfigPath = userConfigPath
		}
	}

	flag.StringVar(&flags.configPath, "config", defaultConfigPath, "Path to client config file")
	flag.StringVar(&flags.socketPath, "socket", common.DefaultSocketPath, "Path to service UNIX socket") // Use common
	flag.BoolVar(&flags.showVersion, "version", false, "Show client version")
	flag.DurationVar(&flags.connectTimeout, "timeout", 10*time.Second, "Connection timeout to the service socket")
	flag.StringVar(&flags.logLevel, "loglevel", "", "Override log level (debug, info, warn, error)")
	flag.Parse()
	return flags
}

func init() {
	clientcore.ClientVersion = version
}
