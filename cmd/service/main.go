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
	// Ensure root context is always cancelled on exit, signaling all derived contexts.
	defer rootCancel()

	// --- Panic Recovery ---
	defer func() {
		if r := recover(); r != nil {
			// Log panic to stderr and attempt structured logging
			fmt.Fprintf(os.Stderr, "SERVICE PANIC: %v\n%s\n", r, string(debug.Stack()))
			slog.Error("FATAL: Service panicked", "error", r, "stack", string(debug.Stack()))
			// Attempt to trigger graceful shutdown, might fail if panic is severe
			signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
			time.Sleep(1 * time.Second) // Give signals a moment
			os.Exit(1)                  // Exit with error code
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
	// Use provided path or default
	cfgPath := "/etc/kernelgatekeeper/config.yaml"
	if configPath != nil && *configPath != "" {
		cfgPath = *configPath
	}
	initialCfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		// Log to stderr as logger isn't set up yet
		fmt.Fprintf(os.Stderr, "FATAL: Failed to load initial configuration %s: %v\n", cfgPath, err)
		os.Exit(1)
	}

	// --- Logging Setup ---
	// Use config values for log level and path
	logging.Setup(initialCfg.LogLevel, initialCfg.LogPath, os.Stderr)
	slog.Info("KernelGatekeeper Service starting", "version", version, "commit", commit, "date", date, "pid", os.Getpid())
	slog.Info("Using configuration file", "path", cfgPath)

	// --- Signal Handling (Termination & Reload) ---
	// Setup SIGINT/SIGTERM handler
	signals.SetupHandler(rootCtx, rootCancel, &globalShutdownOnce)

	// Setup SIGHUP handler for config reload
	hupChan := make(chan os.Signal, 1)
	signal.Notify(hupChan, syscall.SIGHUP)
	defer signal.Stop(hupChan) // Ensure channel stop on exit
	defer close(hupChan)       // Ensure channel close on exit

	// --- Core Component Initialization ---
	// StateManager now initializes BPF Manager internally
	stateManager, err := servicecore.NewStateManager(cfgPath, initialCfg)
	if err != nil {
		slog.Error("FATAL: Failed to initialize service state manager", "error", err)
		// No stateManager to cleanup yet, just exit.
		os.Exit(1)
	}

	// --- Start Background Tasks (BPF Reader, Stats Logger, BPF Processor) ---
	// StartBackgroundTasks returns fatal errors immediately if BPF init fails.
	if err := stateManager.StartBackgroundTasks(rootCtx); err != nil {
		slog.Error("FATAL: Failed during background task startup", "error", err)
		// Attempt cleanup, though BPF manager might be in a bad state
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		stateManager.Shutdown(shutdownCtx) // Initiate cleanup
		shutdownCancel()
		stateManager.Wait() // Wait for any started goroutines (might be none)
		os.Exit(1)
	}

	// --- Setup and Start IPC ---
	// Create the handler (which uses the state manager)
	ipcHandler := servicecore.NewIpcHandler(stateManager)
	// Create the listener (passes WaitGroup for handler goroutines)
	ipcListener, err := servicecore.NewIpcListener(initialCfg, ipcHandler, stateManager.WG())
	if err != nil {
		slog.Error("FATAL: Failed to start IPC listener", "error", err)
		// Trigger shutdown to stop background tasks before exiting
		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
		// Attempt cleanup
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second) // Slightly longer timeout
		stateManager.Shutdown(shutdownCtx)
		shutdownCancel()
		stateManager.Wait()
		os.Exit(1)
	}
	// Store listener reference in StateManager for graceful shutdown
	stateManager.SetIPCListener(ipcListener.Listener())
	// Start accepting connections (non-blocking)
	ipcListener.Run(rootCtx)

	slog.Info("Service successfully started. Listening for signals and connections...")

	// --- Main Event Loop ---
	keepRunning := true
	for keepRunning {
		select {
		case <-rootCtx.Done(): // Shutdown requested via SIGINT/SIGTERM
			slog.Info("Shutdown signal received, terminating main loop.")
			keepRunning = false

		case <-hupChan: // Config reload requested via SIGHUP
			slog.Info("Received SIGHUP, attempting to reload configuration...")
			if reloadErr := stateManager.ReloadConfig(); reloadErr != nil {
				slog.Error("Failed to reload configuration", "error", reloadErr)
			} else {
				slog.Info("Configuration reload process completed successfully.")
				// Logging is already re-set inside ReloadConfig
			}

		case initErr := <-stateManager.GetFatalErrorChannel(): // Fatal error from background tasks
			// Check if channel was closed (shutdown already happening) or error received
			if initErr != nil {
				slog.Error("Received fatal error from background task, shutting down", "error", initErr)
				signals.TriggerShutdown(&globalShutdownOnce, rootCancel) // Ensure shutdown is triggered
				keepRunning = false
			} else {
				// Channel closed, likely during shutdown sequence
				slog.Debug("Fatal error channel closed.")
				// If context isn't done yet, trigger shutdown for safety
				if rootCtx.Err() == nil {
					signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
				}
				keepRunning = false
			}
		}
	}

	// --- Graceful Shutdown ---
	// Get shutdown timeout from potentially reloaded config
	shutdownTimeout := stateManager.GetConfig().ShutdownTimeout
	if shutdownTimeout <= 0 {
		slog.Warn("Invalid shutdown timeout configured, using default.", "configured", shutdownTimeout, "default", 30*time.Second)
		shutdownTimeout = 30 * time.Second // Fallback
	}
	slog.Info("Starting graceful shutdown...", "timeout", shutdownTimeout)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Initiate the shutdown sequence in StateManager
	stateManager.Shutdown(shutdownCtx)

	slog.Info("Waiting for all background tasks and handlers to complete...")
	stateManager.Wait() // Wait for all goroutines managed by the WaitGroup

	slog.Info("Service stopped.")
}
