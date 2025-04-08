package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/clientcore"
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

	// --- Load Initial Configuration Locally ---
	cfg, err := config.LoadConfig(flags.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Failed to load configuration %s: %v\n", flags.configPath, err)
		os.Exit(1)
	}

	// --- Logging Setup ---
	logLvl := cfg.LogLevel // Use config value first
	if flags.logLevel != "" {
		logLvl = flags.logLevel // Override with flag if set
	}
	logging.Setup(logLvl, "", os.Stderr) // Client logs to stderr
	slog.Info("Starting KernelGatekeeper Client (SockOps Model)", "version", version, "pid", os.Getpid())
	slog.Info("Using configuration file", "path", flags.configPath)

	// --- Signal Handling ---
	signals.SetupHandler(ctx, rootCancel, &globalShutdownOnce)

	// --- Initialize Core Components based on Local Config ---
	stateManager := clientcore.NewStateManager(cfg) // Pass loaded config

	kClient, kerr := kerb.NewKerberosClient(&cfg.Kerberos) // Initialize Kerberos locally
	if kerr != nil {
		slog.Error("Failed to initialize Kerberos client", "error", kerr)
		// Continue without Kerberos? Or exit? Decide based on requirements.
		// For now, log error and continue, proxy might fail later if auth needed.
	} else {
		stateManager.SetKerberosClient(kClient) // Store in state manager
		slog.Info("Kerberos client initialized.")
	}

	pMgr, perr := proxy.NewProxyManager(&cfg.Proxy) // Initialize Proxy Manager locally
	if perr != nil {
		slog.Error("Failed to initialize Proxy Manager", "error", perr)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		if kClient != nil {
			kClient.Close()
		}
		os.Exit(1) // Proxy manager failure is critical
	}
	stateManager.SetProxyManager(pMgr) // Store in state manager
	slog.Info("Proxy Manager initialized.")

	// --- Start Local Listener Early ---
	localListener := clientcore.NewLocalListener()
	if err := localListener.Start(); err != nil {
		slog.Error("Failed to start local listener", "address", localListener.Addr(), "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		stateManager.Cleanup()
		os.Exit(1)
	}
	defer localListener.Close()

	// --- Initialize IPC Manager ---
	// Use socket path from flags or default (config value is ignored here)
	ipcSocketPath := flags.socketPath
	if ipcSocketPath == "" {
		ipcSocketPath = config.DefaultSocketPath
	}
	ipcManager := clientcore.NewIPCManager(ctx, stateManager, ipcSocketPath, flags.connectTimeout)

	// --- Setup Connection Handler & Set Callbacks BEFORE Run() ---
	connectionHandler := clientcore.NewConnectionHandler(stateManager)
	ipcManager.SetAcceptCallback(connectionHandler.HandleBPFAccept)
	ipcManager.SetListenerCallback(localListener.GetListener)
	slog.Debug("IPC callbacks registered.")

	// --- Start IPC Manager (Connects and listens for notifications) ---
	ipcManager.Run()

	// --- Wait for Initial IPC Connection (Necessary for receiving notifications) ---
	if err := ipcManager.WaitForInitialConnection(flags.connectTimeout + 5*time.Second); err != nil {
		slog.Error("Failed to establish initial connection to service", "error", err)
		// No need to trigger shutdown here, signals handler will catch ctx cancellation eventually
		ipcManager.Stop()
		localListener.Close()
		stateManager.Cleanup()
		os.Exit(1)
	}
	slog.Info("Successfully connected to service IPC for notifications.")

	// --- Start Background Tasks (Kerberos Check, Ping) ---
	// No config refresh needed via IPC anymore.
	backgroundTasks := clientcore.NewBackgroundTasks(ctx, stateManager, ipcManager)
	backgroundTasks.Run()

	slog.Info("Client initialization complete. Ready to accept proxied connections.")

	// --- Wait for Shutdown Signal ---
	<-ctx.Done()
	slog.Info("Shutdown initiated. Waiting for background tasks and connections to complete...")

	// --- Graceful Shutdown ---
	localListener.Close()  // Stop accepting new BPF connections
	ipcManager.Stop()      // Stop IPC manager loops & close connection
	stateManager.Cleanup() // Waits for connection handlers & background tasks via WaitGroup

	slog.Info("Client exited gracefully.")
}

func parseFlags() clientFlags {
	var flags clientFlags
	// Try common config locations
	defaultConfigPath := "/etc/kernelgatekeeper/config.yaml"
	homeDir, err := os.UserHomeDir()
	if err == nil {
		userConfigPath := filepath.Join(homeDir, ".config", "kernelgatekeeper", "config.yaml")
		if _, statErr := os.Stat(userConfigPath); statErr == nil {
			defaultConfigPath = userConfigPath // Prefer user config if it exists
		}
	}

	flag.StringVar(&flags.configPath, "config", defaultConfigPath, "Path to client config file")
	flag.StringVar(&flags.socketPath, "socket", config.DefaultSocketPath, "Path to service UNIX socket")
	flag.BoolVar(&flags.showVersion, "version", false, "Show client version")
	flag.DurationVar(&flags.connectTimeout, "timeout", 10*time.Second, "Connection timeout to the service socket")
	flag.StringVar(&flags.logLevel, "loglevel", "", "Override log level (debug, info, warn, error)")
	flag.Parse()
	return flags
}

// Inject version info into connect_tunnel.go (replace placeholder)
func init() {
	clientcore.ClientVersion = version
}
