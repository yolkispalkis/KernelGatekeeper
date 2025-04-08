package signals

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func SetupHandler(ctx context.Context, cancel context.CancelFunc, shutdownOnce *sync.Once) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-sigCh:
			slog.Info("Received signal, initiating shutdown...", "signal", sig)
			TriggerShutdown(shutdownOnce, cancel)
		case <-ctx.Done():
			slog.Debug("Signal handler context done, stopping listener.")
		}
		signal.Stop(sigCh)
		close(sigCh)
	}()
}

func TriggerShutdown(shutdownOnce *sync.Once, cancel context.CancelFunc) {
	shutdownOnce.Do(func() {
		slog.Info("Triggering application shutdown...")
		if cancel != nil {
			cancel()
		}
	})
}
