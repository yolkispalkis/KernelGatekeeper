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

	"github.com/yolki/kernelgatekeeper/pkg/clientcore"
	"github.com/yolki/kernelgatekeeper/pkg/config"
	"github.com/yolki/kernelgatekeeper/pkg/logging"
	"github.com/yolki/kernelgatekeeper/pkg/signals"
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
			// Potentially wait shortly for cleanup, but exit reliably
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
	// Log to stderr by default for client
	logging.Setup(os.Getenv("LOG_LEVEL"), "", os.Stderr)
	slog.Info("Starting KernelGatekeeper Client (SockOps Model)", "version", version, "pid", os.Getpid())

	// --- Signal Handling ---
	signals.SetupHandler(ctx, rootCancel, &globalShutdownOnce)

	// --- Core Component Initialization ---
	stateManager := clientcore.NewStateManager(nil) // Initial config comes from service

	ipcManager := clientcore.NewIPCManager(ctx, stateManager, flags.socketPath, flags.connectTimeout)
	ipcManager.Run() // Start connection management goroutine

	// --- Wait for Initial IPC Connection ---
	if err := ipcManager.WaitForInitialConnection(flags.connectTimeout + 5*time.Second); err != nil {
		slog.Error("Failed to establish initial connection to service", "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		ipcManager.Stop()
		stateManager.Cleanup()
		os.Exit(1)
	}

	// --- Perform Initial Setup (Get Config, Init Kerberos/Proxy) ---
	// Run setup in a goroutine managed by the state manager
	go stateManager.PerformInitialSetup(ipcManager)
	if err := stateManager.WaitForInitialSetup(); err != nil {
		slog.Error("Failed during initial setup after connecting to service", "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		ipcManager.Stop()
		stateManager.Cleanup() // Cleanup resources initialized before failure
		os.Exit(1)
	}

	// --- Start Local Listener ---
	localListener := clientcore.NewLocalListener()
	if err := localListener.Start(); err != nil {
		slog.Error("Failed to start local listener", "address", localListener.Addr(), "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		ipcManager.Stop()
		stateManager.Cleanup()
		os.Exit(1)
	}
	defer localListener.Close()

	// --- Setup Connection Handler & IPC Callbacks ---
	connectionHandler := clientcore.NewConnectionHandler(stateManager)
	ipcManager.SetAcceptCallback(connectionHandler.HandleBPFAccept) // Register callback
	ipcManager.SetListenerCallback(localListener.GetListener)       // Provide listener access

	// --- Start Background Tasks ---
	backgroundTasks := clientcore.NewBackgroundTasks(ctx, stateManager, ipcManager)
	stateManager.SetBackgroundTasks(backgroundTasks) // Link for config refresh notifications
	backgroundTasks.Run()

	slog.Info("Client initialization complete. Ready to accept proxied connections.")

	// --- Wait for Shutdown Signal ---
	<-ctx.Done()
	slog.Info("Shutdown initiated. Waiting for background tasks and connections to complete...")

	// --- Graceful Shutdown ---
	localListener.Close() // Stop accepting new connections
	ipcManager.Stop()     // Stop IPC manager loops & close connection
	// stateManager.Cleanup() will wait for all goroutines added via stateManager.AddWaitGroup
	// (Connection handlers, background tasks)
	stateManager.Cleanup()

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
	clientcore.clientVersion = version
}
