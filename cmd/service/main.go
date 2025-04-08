package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/logging"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/servicecore"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/signals"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var globalShutdownOnce sync.Once
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// --- Panic Recovery ---
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "SERVICE PANIC: %v\n%s\n", r, string(debug.Stack()))
			slog.Error("PANIC", "error", r, "stack", string(debug.Stack()))
			signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
			time.Sleep(1 * time.Second) // Allow some time for shutdown signal
			os.Exit(1)
		}
	}()

	// --- Flag Parsing ---
	configPath := flag.String("config", "/etc/kernelgatekeeper/config.yaml", "Path to config file")
	showVersion := flag.Bool("version", false, "Show service version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("KernelGatekeeper Service %s, commit %s, built at %s\n", version, commit, date)
		return
	}

	// --- Load Initial Configuration ---
	cfgPath := "/etc/kernelgatekeeper/config.yaml"
	if configPath != nil && *configPath != "" {
		cfgPath = *configPath
	}
	initialCfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Failed to load initial configuration %s: %v\n", cfgPath, err)
		os.Exit(1)
	}

	// --- Logging Setup ---
	logging.Setup(initialCfg.LogLevel, initialCfg.LogPath, os.Stderr)
	slog.Info("KernelGatekeeper Service starting", "version", version, "commit", commit, "date", date, "pid", os.Getpid())
	slog.Info("Using configuration file", "path", cfgPath)

	// --- Signal Handling (Termination) ---
	signals.SetupHandler(rootCtx, rootCancel, &globalShutdownOnce)

	// --- Core Component Initialization ---
	stateManager, err := servicecore.NewStateManager(cfgPath, initialCfg)
	if err != nil {
		slog.Error("FATAL: Failed to initialize service state manager", "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		os.Exit(1)
	}

	// --- Start Background Tasks (BPF Reader, Stats, etc.) ---
	if err := stateManager.StartBackgroundTasks(rootCtx); err != nil {
		// StartBackgroundTasks returns fatal errors immediately
		slog.Error("FATAL: Failed during background task startup", "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		// Attempt cleanup, though BPF manager might be in a bad state
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		stateManager.Shutdown(shutdownCtx)
		shutdownCancel()
		stateManager.Wait()
		os.Exit(1)
	}

	// --- Setup and Start IPC ---
	ipcHandler := servicecore.NewIpcHandler(stateManager)
	ipcListener, err := servicecore.NewIpcListener(initialCfg, ipcHandler, &stateManager.wg) // Pass WaitGroup ref
	if err != nil {
		slog.Error("FATAL: Failed to start IPC listener", "error", err)
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		// Attempt cleanup
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		stateManager.Shutdown(shutdownCtx)
		shutdownCancel()
		stateManager.Wait()
		os.Exit(1)
	}
	stateManager.SetIPCListener(ipcListener.listener) // Store the listener in state for shutdown
	ipcListener.Run(rootCtx)                          // Start accepting connections

	// --- Handle HUP Signal for Config Reload ---
	hupChan := make(chan os.Signal, 1)
	signal.Notify(hupChan, syscall.SIGHUP)
	defer signal.Stop(hupChan)
	defer close(hupChan)

	slog.Info("Service successfully started. Listening for signals and connections...")

	// --- Main Event Loop ---
	keepRunning := true
	for keepRunning {
		select {
		case <-rootCtx.Done():
			slog.Info("Main context cancelled, initiating shutdown.")
			keepRunning = false
		case <-hupChan:
			slog.Info("Received SIGHUP, reloading configuration...")
			if err := stateManager.ReloadConfig(); err != nil {
				slog.Error("Failed to reload configuration", "error", err)
			} else {
				slog.Info("Configuration reloaded successfully.")
				// Logging is already re-set inside ReloadConfig
			}
		case initErr := <-stateManager.GetFatalErrorChannel():
			// Check if channel was closed (shutdown already happening)
			if initErr != nil {
				slog.Error("Received fatal error from initialization, shutting down", "error", initErr)
				signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
				keepRunning = false
			} else {
				slog.Debug("Fatal error channel closed.")
			}
		}
	}

	// --- Graceful Shutdown ---
	shutdownTimeout := stateManager.GetConfig().ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = 30 * time.Second // Fallback
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	stateManager.Shutdown(shutdownCtx) // Initiate shutdown sequence

	slog.Info("Waiting for background tasks to finish...")
	stateManager.Wait() // Wait for all goroutines added via stateManager.AddWaitGroup

	slog.Info("Service stopped.")
}
