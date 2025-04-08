package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	baseReconnectDelay = 1 * time.Second
	maxReconnectDelay  = 60 * time.Second
	statusPingInterval = 1 * time.Minute // Needed for IPC listener timeout
)

type IPCManager struct {
	socketPath       string
	connectTimeout   time.Duration
	conn             atomic.Pointer[net.Conn]
	state            atomic.Int32  // 0 = disconnected, 1 = connected
	stateChan        chan bool     // Signals connection state changes
	stateManager     *StateManager // Still needed for WaitGroup and ActiveConnections for Ping
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	acceptCallback   func(ctx context.Context, conn net.Conn, originalDest ipc.NotifyAcceptData) // Callback for notify_accept
	listenerCallback func() net.Listener                                                         // Callback to get local listener
}

func NewIPCManager(ctx context.Context, stateMgr *StateManager, socketPath string, timeout time.Duration) *IPCManager {
	mgrCtx, mgrCancel := context.WithCancel(ctx)
	return &IPCManager{
		socketPath:     socketPath,
		connectTimeout: timeout,
		stateChan:      make(chan bool, 1),
		stateManager:   stateMgr, // Pass StateManager
		ctx:            mgrCtx,
		cancel:         mgrCancel,
	}
}

func (m *IPCManager) SetAcceptCallback(cb func(ctx context.Context, conn net.Conn, originalDest ipc.NotifyAcceptData)) {
	m.acceptCallback = cb
}

func (m *IPCManager) SetListenerCallback(cb func() net.Listener) {
	m.listenerCallback = cb
}

func (m *IPCManager) Run() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer slog.Info("IPC connection manager stopped.")
		m.manageConnection()
	}()
}

func (m *IPCManager) Stop() {
	m.cancel()
	m.wg.Wait()
	conn := m.conn.Load()
	if conn != nil && *conn != nil {
		(*conn).Close()
	}
}

func (m *IPCManager) IsConnected() bool {
	return m.state.Load() == 1
}

func (m *IPCManager) GetConnection() net.Conn {
	connPtr := m.conn.Load()
	if connPtr == nil {
		return nil
	}
	return *connPtr
}

func (m *IPCManager) WaitForInitialConnection(timeout time.Duration) error {
	slog.Info("Waiting for initial connection to service...")
	select {
	case isConnected := <-m.stateChan:
		if !isConnected {
			// Check context error first
			if m.ctx.Err() != nil {
				return fmt.Errorf("shutdown initiated before initial connection completed: %w", m.ctx.Err())
			}
			return errors.New("initial connection to service failed")
		}
		slog.Info("Successfully connected to service IPC.")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for initial service connection after %s", timeout)
	case <-m.ctx.Done():
		return fmt.Errorf("shutdown initiated before initial connection completed: %w", m.ctx.Err())
	}
}

func (m *IPCManager) manageConnection() {
	var currentDelay time.Duration = 0
	var attempt int = 0

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(currentDelay):
			attempt++
			slog.Info("Attempting to connect to service IPC...", "attempt", attempt, "socket", m.socketPath)
			conn, err := net.DialTimeout("unix", m.socketPath, m.connectTimeout)

			if err != nil {
				logMsg := "Failed to connect to service IPC"
				// Check context error before logging reconnect details
				if m.ctx.Err() != nil {
					logMsg = "Connection attempt cancelled during shutdown"
					slog.Info(logMsg, "error", err)
					m.setConnectionState(false, nil) // Ensure state reflects disconnect on shutdown path
					return                           // Exit loop on shutdown
				}
				slog.Warn(logMsg, "error", err)
				m.setConnectionState(false, nil)

				currentDelay = time.Duration(math.Pow(2, float64(common.Min(attempt, 6)))) * baseReconnectDelay
				jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
				currentDelay = common.MinDuration(currentDelay+jitter, maxReconnectDelay)
				slog.Info("Will retry IPC connection", "delay", currentDelay)
				continue
			}

			slog.Info("Successfully connected to service IPC", "socket", m.socketPath)
			attempt = 0
			currentDelay = 0
			m.setConnectionState(true, &conn)

			if err := m.registerWithService(conn); err != nil {
				slog.Error("Failed to register with service after connection", "error", err)
				conn.Close()
				m.setConnectionState(false, nil)
				currentDelay = baseReconnectDelay // Retry quickly after registration failure
				continue
			}
			slog.Info("Client registered with service", "pid", os.Getpid())

			listenerWg := sync.WaitGroup{}
			listenerWg.Add(1)
			go func(currentConn net.Conn) {
				defer listenerWg.Done()
				m.listenIPCNotifications(currentConn)
			}(conn)

			m.waitForConnectionClose(conn)
			listenerWg.Wait()

			// Check context error before logging reconnect
			if m.ctx.Err() != nil {
				slog.Info("IPC connection closed during shutdown.")
				m.setConnectionState(false, nil) // Ensure state is disconnected on shutdown
				return                           // Exit loop on shutdown
			}

			slog.Warn("IPC connection lost. Preparing to reconnect...")
			m.setConnectionState(false, nil)
			currentDelay = baseReconnectDelay // Reset delay for immediate retry
		}
	}
}

func (m *IPCManager) setConnectionState(connected bool, newConn *net.Conn) {
	newState := int32(0)
	if connected {
		newState = 1
	}

	oldConnPtr := m.conn.Swap(newConn)
	if oldConnPtr != nil && *oldConnPtr != nil {
		(*oldConnPtr).Close()
	}

	oldState := m.state.Swap(newState)
	if oldState != newState {
		select {
		case m.stateChan <- connected:
		default: // Avoid blocking if channel buffer is full (e.g., rapid connect/disconnect)
		}
	}
}

func (m *IPCManager) waitForConnectionClose(conn net.Conn) {
	if conn == nil {
		return
	}
	probeTicker := time.NewTicker(30 * time.Second)
	defer probeTicker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return // Stop probing on shutdown
		case <-probeTicker.C:
			// Simple check if connection is still valid (without full read probe)
			if m.GetConnection() != conn {
				slog.Debug("IPC connection changed during probing, stopping probe for old connection.")
				return
			}
			// Optional: Add a minimal write probe (e.g., send a known no-op command or byte)
			// Be careful not to interfere with normal IPC traffic.
			// For now, rely on read errors in listenIPCNotifications and connection change detection.
		}
	}
}

func (m *IPCManager) registerWithService(conn net.Conn) error {
	if conn == nil {
		return errors.New("cannot register with nil IPC connection")
	}
	pid := os.Getpid()
	reqData := ipc.RegisterClientData{PID: pid}
	cmd, err := ipc.NewCommand("register_client", reqData)
	if err != nil {
		return fmt.Errorf("failed to create register command: %w", err)
	}

	encoder := json.NewEncoder(conn)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = encoder.Encode(cmd)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		if common.IsConnectionClosedErr(err) {
			return fmt.Errorf("IPC connection closed before sending register_client: %w", err)
		}
		return fmt.Errorf("failed to send register command: %w", err)
	}

	decoder := json.NewDecoder(conn)
	var resp ipc.Response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = decoder.Decode(&resp)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		if common.IsConnectionClosedErr(err) {
			return fmt.Errorf("IPC connection closed while waiting for register_client response: %w", err)
		}
		if common.IsTimeoutError(err) {
			return fmt.Errorf("timeout waiting for register_client response: %w", err)
		}
		return fmt.Errorf("failed to decode register response: %w", err)
	}

	if resp.Status != ipc.StatusOK {
		return fmt.Errorf("service registration failed: %s", resp.Error)
	}
	return nil
}

// Removed GetConfigFromService

func (m *IPCManager) SendIPCCommand(cmd *ipc.Command) error {
	conn := m.GetConnection()
	if conn == nil {
		return errors.New("cannot send command, IPC disconnected")
	}
	encoder := json.NewEncoder(conn)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := encoder.Encode(cmd)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		if common.IsConnectionClosedErr(err) {
			// Connection closed, trigger reconnect logic by setting state
			m.setConnectionState(false, nil)
			return fmt.Errorf("IPC connection closed while sending command %s: %w", cmd.Command, err)
		}
		return fmt.Errorf("failed to send command %s: %w", cmd.Command, err)
	}
	return nil
}

func (m *IPCManager) listenIPCNotifications(conn net.Conn) {
	slog.Info("Starting IPC notification listener for connection.")
	decoder := json.NewDecoder(conn)

	for {
		// Check context before attempting to read
		select {
		case <-m.ctx.Done():
			slog.Info("Stopping IPC notification listener due to context cancellation.")
			return
		default:
		}

		// Check if the connection we are listening on is still the active one
		if conn == nil || m.GetConnection() != conn {
			slog.Info("IPC connection changed or closed, stopping listener for this specific connection.")
			return
		}

		var cmd ipc.Command
		if err := conn.SetReadDeadline(time.Now().Add(statusPingInterval + 30*time.Second)); err != nil {
			if !common.IsConnectionClosedErr(err) {
				slog.Warn("Error setting read deadline for IPC notification listener", "error", err)
			}
			// Don't return immediately, let Decode handle the error
		}
		err := decoder.Decode(&cmd)
		_ = conn.SetReadDeadline(time.Time{}) // Clear deadline immediately

		if err != nil {
			// Check context again after Decode returns
			if m.ctx.Err() != nil {
				slog.Info("Stopping IPC notification listener due to context cancellation during/after decode.")
				return
			}
			logMsg := "IPC error while reading notifications."
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) {
				logMsg = "IPC connection closed while reading notifications."
			} else if common.IsTimeoutError(err) {
				logMsg = "IPC connection timed out waiting for notifications/ping."
			}
			slog.Warn(logMsg, "error", err)
			// Let manageConnection handle reconnect logic by returning from this listener.
			// Close the connection locally to ensure manageConnection notices.
			conn.Close()
			m.setConnectionState(false, nil) // Reflect disconnect
			return
		}

		switch cmd.Command {
		case "notify_accept":
			if m.acceptCallback == nil {
				slog.Error("Received 'notify_accept' but no handler is registered")
				continue
			}
			currentListener := m.listenerCallback()
			if currentListener == nil {
				slog.Error("Received 'notify_accept' but local listener is not available")
				continue
			}

			var data ipc.NotifyAcceptData
			if err := ipc.DecodeData(cmd.Data, &data); err != nil {
				slog.Error("Failed to decode notify_accept data", "error", err)
				continue
			}
			slog.Info("Received 'notify_accept' from service", "src", data.SrcIP, "dport", data.DstPort, "orig_dst", data.DstIP)

			// Add to waitgroup *before* starting goroutine
			m.stateManager.AddWaitGroup(1)
			go func(d ipc.NotifyAcceptData, listenerToUse net.Listener) {
				defer m.stateManager.WaitGroupDone() // Use StateManager's WaitGroup

				// Context check inside the goroutine
				if m.ctx.Err() != nil {
					slog.Info("Accept goroutine cancelled before Accept()", "error", m.ctx.Err())
					return
				}

				if tcpListener, ok := listenerToUse.(*net.TCPListener); ok {
					acceptDeadline := time.Now().Add(5 * time.Second)
					if err := tcpListener.SetDeadline(acceptDeadline); err != nil {
						if !common.IsConnectionClosedErr(err) { // Don't warn if listener is already closing
							slog.Warn("Failed to set accept deadline on local listener", "error", err)
						}
						// Don't return immediately, let Accept handle the error
					}
					defer tcpListener.SetDeadline(time.Time{}) // Ensure deadline is cleared
				}

				acceptedConn, acceptErr := listenerToUse.Accept()
				if acceptErr != nil {
					// Check context error first during accept failure
					if m.ctx.Err() != nil {
						slog.Info("Accept goroutine cancelled during Accept()", "error", m.ctx.Err())
						return
					}
					if errors.Is(acceptErr, net.ErrClosed) {
						slog.Info("Local listener closed while attempting to accept BPF connection (likely shutdown).")
					} else if common.IsTimeoutError(acceptErr) {
						slog.Error("Timeout accepting connection from BPF sockmap", "error", acceptErr)
					} else {
						slog.Error("Failed to accept connection from BPF sockmap", "error", acceptErr)
					}
					return // Don't proceed if accept failed
				}
				slog.Debug("Accepted connection from BPF sockmap", "local", acceptedConn.LocalAddr(), "remote", acceptedConn.RemoteAddr())

				// Pass the accepted connection and original destination data to the handler callback
				// Use the manager's context which might be cancelled
				m.acceptCallback(m.ctx, acceptedConn, d)

			}(data, currentListener)

		// Removed config_updated case
		default:
			slog.Warn("Received unknown command from service via IPC", "command", cmd.Command)
		}
	}
}
