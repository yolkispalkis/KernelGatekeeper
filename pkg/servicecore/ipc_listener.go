// FILE: pkg/servicecore/ipc_listener.go
package servicecore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

type IpcListener struct {
	socketPath string
	listener   net.Listener
	handler    *IpcHandler
	wg         *sync.WaitGroup
}

func NewIpcListener(cfg *config.Config, handler *IpcHandler, wg *sync.WaitGroup) (*IpcListener, error) {
	socketPath := cfg.SocketPath
	if socketPath == "" {
		return nil, errors.New("IPC socket path is not configured")
	}

	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create IPC directory %s: %w", dir, err)
	}

	if _, err := os.Stat(socketPath); err == nil {
		slog.Info("Removing existing IPC socket file", "path", socketPath)
		if err := os.Remove(socketPath); err != nil {
			slog.Warn("Failed to remove existing IPC socket, continuing...", "path", socketPath, "error", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to stat IPC socket path %s: %w", socketPath, err)
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on IPC socket %s: %w", socketPath, err)
	}

	if err := os.Chmod(socketPath, 0666); err != nil {
		l.Close()
		os.Remove(socketPath)
		return nil, fmt.Errorf("failed to chmod IPC socket %s to 0666: %w", socketPath, err)
	}

	slog.Info("IPC listener started", "path", socketPath, "permissions", "0666")

	return &IpcListener{
		socketPath: socketPath,
		listener:   l,
		handler:    handler,
		wg:         wg,
	}, nil
}

func (il *IpcListener) Run(ctx context.Context) {

	il.wg.Add(1)
	go func() {
		defer il.wg.Done()
		<-ctx.Done()
		slog.Info("Closing IPC listener due to context cancellation...")
		il.Close()
	}()

	il.wg.Add(1)
	go func() {
		defer il.wg.Done()
		for {
			conn, err := il.listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					slog.Info("IPC listener closed, stopping accept loop.")
					return
				}
				slog.Error("IPC accept failed", "error", err)
				select {
				case <-time.After(100 * time.Millisecond):
					continue
				case <-ctx.Done():
					return
				}
			}

			il.wg.Add(1)
			go func(c net.Conn) {
				defer il.wg.Done()
				il.handler.HandleConnection(ctx, c)
			}(conn)
		}
	}()
}

func (il *IpcListener) Close() error {
	if il.listener != nil {
		err := il.listener.Close()
		il.listener = nil

		return err
	}
	return nil
}

func (il *IpcListener) Listener() net.Listener {
	return il.listener
}
