package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/clientcore"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/logging"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/signals"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type clientFlags struct {
	socketPath     string
	showVersion    bool
	connectTimeout time.Duration
}

func main() {
	var globalShutdownOnce sync.Once
	ctx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel() // Ensure context is always cancelled

	// --- Panic Recovery ---
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "CLIENT PANIC: %v\n%s\n", r, string(debug.Stack()))
			signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
			time.Sleep(1 * time.Second)
			os.Exit(1)
		}
	}()

	// --- Flag Parsing ---
	flags := parseFlags()
	if flags.showVersion {
		fmt.Printf("KernelGatekeeper Client %s, commit %s, built at %s\n", version, commit, date)
		return
	}

	// --- Logging Setup ---
	logging.Setup(os.Getenv("LOG_LEVEL"), "", os.Stderr) // Client logs to stderr
	slog.Info("Starting KernelGatekeeper Client (SockOps Model)", "version", version, "pid", os.Getpid())

	// --- Signal Handling ---
	signals.SetupHandler(ctx, rootCancel, &globalShutdownOnce)

	// --- Core Component Initialization ---
	stateManager := clientcore.NewStateManager(nil) // Config comes from service

	// --- Start Local Listener Early ---
	// This needs to be ready before BPF might try to connect to it.
	localListener := clientcore.NewLocalListener()
	if err := localListener.Start(); err != nil {
		slog.Error("Failed to start local listener", "address", localListener.Addr(), "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		stateManager.Cleanup() // Cleanup anything initialized so far
		os.Exit(1)
	}
	defer localListener.Close() // Ensure listener is closed on exit

	// --- Initialize IPC Manager ---
	ipcManager := clientcore.NewIPCManager(ctx, stateManager, flags.socketPath, flags.connectTimeout)

	// --- Setup Connection Handler & Set Callbacks BEFORE Run() ---
	// Callbacks must be set before the IPC manager starts listening for notifications.
	connectionHandler := clientcore.NewConnectionHandler(stateManager)
	ipcManager.SetAcceptCallback(connectionHandler.HandleBPFAccept) // Register BPF accept handler
	ipcManager.SetListenerCallback(localListener.GetListener)       // Provide listener access for accept
	slog.Debug("IPC callbacks registered.")

	// --- Start IPC Manager ---
	// This will start trying to connect and eventually listen for IPC messages.
	ipcManager.Run()

	// --- Wait for Initial IPC Connection ---
	// This ensures we have a line to the service before proceeding with setup.
	if err := ipcManager.WaitForInitialConnection(flags.connectTimeout + 5*time.Second); err != nil {
		slog.Error("Failed to establish initial connection to service", "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		ipcManager.Stop()
		localListener.Close()
		stateManager.Cleanup()
		os.Exit(1)
	}

	// --- Perform Initial Setup (Get Config, Init Kerberos/Proxy) ---
	// This now happens after IPC is connected and callbacks are set.
	// Run setup in a goroutine managed by the state manager.
	go stateManager.PerformInitialSetup(ipcManager)
	if err := stateManager.WaitForInitialSetup(); err != nil {
		slog.Error("Failed during initial setup after connecting to service", "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		ipcManager.Stop()
		localListener.Close()
		stateManager.Cleanup() // Cleanup resources initialized before failure
		os.Exit(1)
	}

	// --- Start Background Tasks (Config Refresh, Kerberos Check) ---
	// These can start after initial setup is complete.
	backgroundTasks := clientcore.NewBackgroundTasks(ctx, stateManager, ipcManager)
	stateManager.SetBackgroundTasks(backgroundTasks) // Link for config refresh notifications
	backgroundTasks.Run()

	slog.Info("Client initialization complete. Ready to accept proxied connections.")

	// --- Wait for Shutdown Signal ---
	<-ctx.Done()
	slog.Info("Shutdown initiated. Waiting for background tasks and connections to complete...")

	// --- Graceful Shutdown ---
	// Order matters: stop accepting new, stop IPC, wait for handlers/tasks.
	localListener.Close()  // Stop accepting new BPF connections
	ipcManager.Stop()      // Stop IPC manager loops & close connection
	stateManager.Cleanup() // Waits for connection handlers & background tasks via WaitGroup

	slog.Info("Client exited gracefully.")
}

func parseFlags() clientFlags {
	var flags clientFlags
	flag.StringVar(&flags.socketPath, "socket", config.DefaultSocketPath, "Path to service UNIX socket")
	flag.BoolVar(&flags.showVersion, "version", false, "Show client version")
	flag.DurationVar(&flags.connectTimeout, "timeout", 10*time.Second, "Connection timeout to the service socket")
	flag.Parse()
	return flags
}

// Inject version info into connect_tunnel.go (replace placeholder)
func init() {
	clientcore.ClientVersion = version
}
