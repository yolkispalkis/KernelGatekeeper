// FILE: cmd/service/main.go
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

	defer func() {
		if r := recover(); r != nil {

			fmt.Fprintf(os.Stderr, "SERVICE PANIC: %v\n%s\n", r, string(debug.Stack()))
			slog.Error("FATAL: Service panicked", "error", r, "stack", string(debug.Stack()))

			signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
			time.Sleep(1 * time.Second)
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

	cfgPath := "/etc/kernelgatekeeper/config.yaml"
	if configPath != nil && *configPath != "" {
		cfgPath = *configPath
	}
	initialCfg, err := config.LoadConfig(cfgPath)
	if err != nil {

		fmt.Fprintf(os.Stderr, "FATAL: Failed to load initial configuration %s: %v\n", cfgPath, err)
		os.Exit(1)
	}

	logging.Setup(initialCfg.LogLevel, initialCfg.LogPath, os.Stderr)
	slog.Info("KernelGatekeeper Service starting", "version", version, "commit", commit, "date", date, "pid", os.Getpid())
	slog.Info("Using configuration file", "path", cfgPath)

	signals.SetupHandler(rootCtx, rootCancel, &globalShutdownOnce)

	hupChan := make(chan os.Signal, 1)
	signal.Notify(hupChan, syscall.SIGHUP)
	defer signal.Stop(hupChan)
	defer close(hupChan)

	stateManager, err := servicecore.NewStateManager(cfgPath, initialCfg)
	if err != nil {
		slog.Error("FATAL: Failed to initialize service state manager", "error", err)

		os.Exit(1)
	}

	if err := stateManager.StartBackgroundTasks(rootCtx); err != nil {
		slog.Error("FATAL: Failed during background task startup", "error", err)

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		stateManager.Shutdown(shutdownCtx)
		shutdownCancel()
		stateManager.Wait()
		os.Exit(1)
	}

	ipcHandler := servicecore.NewIpcHandler(stateManager)

	ipcListener, err := servicecore.NewIpcListener(initialCfg, ipcHandler, stateManager.WG())
	if err != nil {
		slog.Error("FATAL: Failed to start IPC listener", "error", err)

		signals.TriggerShutdown(&globalShutdownOnce, rootCancel)

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		stateManager.Shutdown(shutdownCtx)
		shutdownCancel()
		stateManager.Wait()
		os.Exit(1)
	}

	stateManager.SetIPCListener(ipcListener.Listener())

	ipcListener.Run(rootCtx)

	slog.Info("Service successfully started. Listening for signals and connections...")

	keepRunning := true
	for keepRunning {
		select {
		case <-rootCtx.Done():
			slog.Info("Shutdown signal received, terminating main loop.")
			keepRunning = false

		case <-hupChan:
			slog.Info("Received SIGHUP, attempting to reload configuration...")
			if reloadErr := stateManager.ReloadConfig(); reloadErr != nil {
				slog.Error("Failed to reload configuration", "error", reloadErr)
			} else {
				slog.Info("Configuration reload process completed successfully.")

			}

		case initErr := <-stateManager.GetFatalErrorChannel():

			if initErr != nil {
				slog.Error("Received fatal error from background task, shutting down", "error", initErr)
				signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
				keepRunning = false
			} else {

				slog.Debug("Fatal error channel closed.")

				if rootCtx.Err() == nil {
					signals.TriggerShutdown(&globalShutdownOnce, rootCancel)
				}
				keepRunning = false
			}
		}
	}

	shutdownTimeout := stateManager.GetConfig().ShutdownTimeout
	if shutdownTimeout <= 0 {
		slog.Warn("Invalid shutdown timeout configured, using default.", "configured", shutdownTimeout, "default", 30*time.Second)
		shutdownTimeout = 30 * time.Second
	}
	slog.Info("Starting graceful shutdown...", "timeout", shutdownTimeout)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	stateManager.Shutdown(shutdownCtx)

	slog.Info("Waiting for all background tasks and handlers to complete...")
	stateManager.Wait()

	slog.Info("Service stopped.")
}
