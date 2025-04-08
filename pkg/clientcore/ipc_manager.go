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
	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
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
	state            atomic.Int32 // 0 = disconnected, 1 = connected
	stateChan        chan bool    // Signals connection state changes
	stateManager     *StateManager
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
		stateManager:   stateMgr,
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
				slog.Warn("Failed to connect to service IPC", "error", err)
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
				currentDelay = baseReconnectDelay
				continue
			}
			slog.Info("Client registered with service", "pid", os.Getpid())

			// Start listening for notifications on this connection
			listenerWg := sync.WaitGroup{}
			listenerWg.Add(1)
			go func(currentConn net.Conn) {
				defer listenerWg.Done()
				m.listenIPCNotifications(currentConn)
			}(conn)

			// Wait for disconnect or context cancellation
			m.waitForConnectionClose(conn)
			listenerWg.Wait() // Ensure listener goroutine exits

			slog.Warn("IPC connection lost. Preparing to reconnect...")
			m.setConnectionState(false, nil)
			currentDelay = baseReconnectDelay
		}
	}
}

func (m *IPCManager) setConnectionState(connected bool, newConn *net.Conn) {
	newState := int32(0)
	if connected {
		newState = 1
	}

	// Close old connection before storing new one
	oldConnPtr := m.conn.Swap(newConn)
	if oldConnPtr != nil && *oldConnPtr != nil {
		(*oldConnPtr).Close()
	}

	// Update atomic state and notify channel
	oldState := m.state.Swap(newState)
	if oldState != newState {
		select {
		case m.stateChan <- connected:
		default:
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
			return
		case <-probeTicker.C:
			one := make([]byte, 1)
			if err := conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
				if !common.IsConnectionClosedErr(err) {
					slog.Warn("Error setting read deadline for IPC probe", "error", err)
				}
				return
			}
			_, err := conn.Read(one)
			_ = conn.SetReadDeadline(time.Time{})

			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || common.IsTimeoutError(err) || common.IsConnectionClosedErr(err) {
					slog.Debug("IPC connection probe detected closure or error", "error", err)
					return
				}
				slog.Warn("IPC connection probe encountered unexpected error", "error", err)
			}
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
		return fmt.Errorf("failed to decode register response: %w", err)
	}

	if resp.Status != ipc.StatusOK {
		return fmt.Errorf("service registration failed: %s", resp.Error)
	}
	return nil
}

// GetConfigFromService fetches configuration using the current connection.
func (m *IPCManager) GetConfigFromService() (*config.Config, error) {
	conn := m.GetConnection()
	if conn == nil {
		return nil, errors.New("cannot get config, not connected to service")
	}

	cmd, err := ipc.NewCommand("get_config", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get_config command: %w", err)
	}

	encoder := json.NewEncoder(conn)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = encoder.Encode(cmd)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		if common.IsConnectionClosedErr(err) {
			return nil, fmt.Errorf("IPC connection closed before sending get_config: %w", err)
		}
		return nil, fmt.Errorf("failed to send get_config command: %w", err)
	}

	decoder := json.NewDecoder(conn)
	var resp ipc.Response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	err = decoder.Decode(&resp)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		if common.IsConnectionClosedErr(err) {
			return nil, fmt.Errorf("IPC connection closed while waiting for get_config response: %w", err)
		}
		return nil, fmt.Errorf("failed to decode get_config response: %w", err)
	}

	if resp.Status != ipc.StatusOK {
		return nil, fmt.Errorf("service returned error for get_config: %s", resp.Error)
	}

	var data ipc.GetConfigData
	if err := ipc.DecodeData(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to decode config data from response: %w", err)
	}

	slog.Debug("Successfully retrieved config from service via IPC.")
	return &data.Config, nil
}

// SendIPCCommand sends a command to the service.
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
			m.setConnectionState(false, nil) // Reflect disconnect
			return fmt.Errorf("IPC connection closed while sending command %s: %w", cmd.Command, err)
		}
		return fmt.Errorf("failed to send command %s: %w", cmd.Command, err)
	}
	return nil
}

func (m *IPCManager) listenIPCNotifications(conn net.Conn) {
	slog.Info("Starting IPC notification listener for connection.")
	decoder := json.NewDecoder(conn)
	// localListener is retrieved inside the loop now if needed

	for {
		select {
		case <-m.ctx.Done():
			slog.Info("Stopping IPC notification listener due to context cancellation.")
			return
		default:
		}

		if conn == nil || m.GetConnection() != conn {
			slog.Info("IPC connection changed or closed, stopping listener for this connection.")
			return // Exit if connection changed or is nil
		}

		var cmd ipc.Command
		// Use a longer timeout for general listening
		if err := conn.SetReadDeadline(time.Now().Add(statusPingInterval + 30*time.Second)); err != nil {
			if !common.IsConnectionClosedErr(err) {
				slog.Warn("Error setting read deadline for IPC notification listener", "error", err)
			}
			return // Assume connection is bad
		}
		err := decoder.Decode(&cmd)
		_ = conn.SetReadDeadline(time.Time{})

		if err != nil {
			if m.ctx.Err() != nil {
				return // Exit if context cancelled during decode
			}
			logMsg := "IPC error while reading notifications."
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) {
				logMsg = "IPC connection closed while reading notifications."
			} else if common.IsTimeoutError(err) {
				logMsg = "IPC connection timed out waiting for notifications."
			}
			slog.Warn(logMsg, "error", err)
			// Let manageConnection handle reconnect logic. Stop this listener.
			return // Exit this listener goroutine
		}

		switch cmd.Command {
		case "notify_accept":
			if m.acceptCallback == nil {
				slog.Error("Received 'notify_accept' but no handler is registered")
				continue
			}
			// Get the listener instance for this specific notification *before* the goroutine
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

			// Spawn a goroutine to handle the accept and callback
			// Pass the retrieved listener instance to the goroutine
			go func(d ipc.NotifyAcceptData, listenerToUse net.Listener) {
				if tcpListener, ok := listenerToUse.(*net.TCPListener); ok {
					acceptDeadline := time.Now().Add(5 * time.Second)
					if err := tcpListener.SetDeadline(acceptDeadline); err != nil {
						slog.Warn("Failed to set accept deadline on local listener", "error", err)
					}
					defer tcpListener.SetDeadline(time.Time{})
				}

				acceptedConn, acceptErr := listenerToUse.Accept()
				if acceptErr != nil {
					if errors.Is(acceptErr, net.ErrClosed) {
						slog.Info("Local listener closed while attempting to accept BPF connection (likely shutdown).")
					} else if netErr, ok := acceptErr.(net.Error); ok && netErr.Timeout() {
						slog.Error("Timeout accepting connection from BPF sockmap", "error", acceptErr)
					} else if !errors.Is(acceptErr, context.Canceled) { // Avoid logging error on clean shutdown
						slog.Error("Failed to accept connection from BPF sockmap", "error", acceptErr)
					}
					return
				}
				slog.Debug("Accepted connection from BPF sockmap", "local", acceptedConn.LocalAddr(), "remote", acceptedConn.RemoteAddr())

				// Pass the accepted connection and original destination data to the handler callback
				m.acceptCallback(m.ctx, acceptedConn, d)

			}(data, currentListener) // Pass the listener instance

		case "config_updated":
			slog.Info("Received 'config_updated' notification from service. Triggering refresh.")
			// Use the StateManager to access the BackgroundTasks interface
			bgTasks := m.stateManager.GetBackgroundTasks()
			if bgTasks != nil {
				// Run refresh in a goroutine to avoid blocking the IPC listener
				m.stateManager.AddWaitGroup(1) // Add to waitgroup for graceful shutdown
				go func() {
					defer m.stateManager.WaitGroupDone()
					bgTasks.RefreshConfiguration()
				}()
			} else {
				slog.Error("Cannot refresh configuration: background task runner not available via StateManager")
			}
		default:
			slog.Warn("Received unknown command from service via IPC", "command", cmd.Command)
		}
	}
}
