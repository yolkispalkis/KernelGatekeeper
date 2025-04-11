// FILE: pkg/clientcore/ipc_manager.go
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
	statusPingInterval = 1 * time.Minute
)

type IPCManager struct {
	socketPath     string
	connectTimeout time.Duration
	conn           atomic.Pointer[net.Conn]
	state          atomic.Int32
	stateChan      chan bool
	stateManager   *StateManager
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
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

				if m.ctx.Err() != nil {
					logMsg = "Connection attempt cancelled during shutdown"
					slog.Info(logMsg, "error", err)
					m.setConnectionState(false, nil)
					return
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
				currentDelay = baseReconnectDelay
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

			if m.ctx.Err() != nil {
				slog.Info("IPC connection closed during shutdown.")
				m.setConnectionState(false, nil)
				return
			}

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

	oldConnPtr := m.conn.Swap(newConn)
	if oldConnPtr != nil && *oldConnPtr != nil {
		(*oldConnPtr).Close()
	}

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

			if m.GetConnection() != conn {
				slog.Debug("IPC connection changed during probing, stopping probe for old connection.")
				return
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

		select {
		case <-m.ctx.Done():
			slog.Info("Stopping IPC notification listener due to context cancellation.")
			return
		default:
		}

		if conn == nil || m.GetConnection() != conn {
			slog.Info("IPC connection changed or closed, stopping listener for this specific connection.")
			return
		}

		var cmd ipc.Command
		if err := conn.SetReadDeadline(time.Now().Add(statusPingInterval + 30*time.Second)); err != nil {
			if !common.IsConnectionClosedErr(err) {
				slog.Warn("Error setting read deadline for IPC notification listener", "error", err)
			}

		}
		err := decoder.Decode(&cmd)
		_ = conn.SetReadDeadline(time.Time{})

		if err != nil {

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

			conn.Close()
			m.setConnectionState(false, nil)
			return
		}

		switch cmd.Command {

		default:
			slog.Warn("Received unknown command from service via IPC", "command", cmd.Command)
		}
	}
}
