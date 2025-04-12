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
	state          atomic.Int32 // 0 = disconnected, 1 = connected
	stateChan      chan bool    // Signals initial connection state change
	firstConnect   atomic.Bool  // Tracks if the initial state change has been sent
	stateManager   *StateManager
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

func NewIPCManager(ctx context.Context, stateMgr *StateManager, socketPath string, timeout time.Duration) *IPCManager {
	mgrCtx, mgrCancel := context.WithCancel(ctx)
	im := &IPCManager{
		socketPath:     socketPath,
		connectTimeout: timeout,
		stateChan:      make(chan bool, 1),
		stateManager:   stateMgr,
		ctx:            mgrCtx,
		cancel:         mgrCancel,
	}
	im.firstConnect.Store(true) // Indicate we are waiting for the *first* connection state signal
	return im
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
	connPtr := m.conn.Load()
	if connPtr != nil && *connPtr != nil {
		(*connPtr).Close()
	}
	m.wg.Wait()
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
			// This means the first attempt failed definitively before timeout or cancellation
			if m.ctx.Err() != nil {
				return fmt.Errorf("shutdown initiated before initial connection completed: %w", m.ctx.Err())
			}
			// Check if manageConnection exited early due to unrecoverable error (though unlikely now)
			return errors.New("initial connection attempt failed")
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
			m.setConnectionState(false, nil) // Ensure state is updated on shutdown
			return
		case <-time.After(currentDelay):
			// Attempt connection
		}

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

			// Calculate next delay
			backoffFactor := math.Pow(2, float64(common.Min(attempt, 6))) // Limit exponent to avoid large powers
			currentDelay = time.Duration(backoffFactor) * baseReconnectDelay
			jitter := time.Duration(rand.Intn(1000)) * time.Millisecond // Add jitter up to 1s
			currentDelay = common.MinDuration(currentDelay+jitter, maxReconnectDelay)
			slog.Info("Will retry IPC connection", "delay", currentDelay)
			continue // Retry after delay
		}

		// Connection successful
		slog.Info("Successfully connected to service IPC", "socket", m.socketPath)
		attempt = 0      // Reset attempt counter
		currentDelay = 0 // Reset delay for next attempt if needed

		// Set state and store connection
		m.setConnectionState(true, &conn)

		// Register with the service
		if err := m.registerWithService(conn); err != nil {
			slog.Error("Failed to register with service after connection", "error", err)
			conn.Close() // Close the connection as registration failed
			m.setConnectionState(false, nil)
			currentDelay = baseReconnectDelay // Short delay before retrying connection
			continue
		}
		slog.Info("Client registered with service", "pid", os.Getpid())

		// Start listener for this connection
		listenerWg := sync.WaitGroup{}
		listenerCtx, listenerCancel := context.WithCancel(m.ctx) // Context for this specific listener
		listenerWg.Add(1)
		go func(currentConn net.Conn) {
			defer listenerWg.Done()
			defer listenerCancel() // Cancel listenerCtx when listener exits
			m.listenIPCNotifications(listenerCtx, currentConn)
		}(conn)

		// Wait for this connection to close or the manager to stop
		<-listenerCtx.Done() // Wait for listener to exit (due to error or shutdown)
		listenerWg.Wait()    // Ensure goroutine finishes

		if m.ctx.Err() != nil {
			slog.Info("IPC connection handler stopped during shutdown.")
			m.setConnectionState(false, nil) // Ensure state is updated
			return                           // Exit manageConnection loop
		}

		// Connection closed unexpectedly
		slog.Warn("IPC connection lost. Preparing to reconnect...")
		m.setConnectionState(false, nil)  // Update state, conn will be closed by setConnectionState
		currentDelay = baseReconnectDelay // Short delay before reconnecting
	}
}

func (m *IPCManager) setConnectionState(connected bool, newConn *net.Conn) {
	newState := int32(0)
	if connected {
		newState = 1
	}

	// Atomically swap the connection pointer and close the old one
	oldConnPtr := m.conn.Swap(newConn)
	if oldConnPtr != nil && *oldConnPtr != nil {
		(*oldConnPtr).Close() // Close the previous connection if it existed
	}

	// Atomically update the state
	oldState := m.state.Swap(newState)

	// Signal the first connection state change attempt
	if m.firstConnect.CompareAndSwap(true, false) {
		select {
		case m.stateChan <- connected:
			if !connected {
				slog.Warn("First connection attempt failed.")
			}
		default:
			// Channel might be blocked if WaitForInitialConnection already timed out or cancelled
			slog.Warn("Could not send initial connection state; channel likely blocked.")
		}
		// Don't close stateChan here, WaitForInitialConnection needs it
	} else if oldState != newState {
		// Log subsequent state changes (optional)
		if connected {
			slog.Info("IPC connection re-established.")
		} else {
			slog.Warn("IPC connection lost (detected by setConnectionState).")
		}
	}
}

// registerWithService performs the initial registration handshake.
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

	// Set write deadline
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(cmd)
	conn.SetWriteDeadline(time.Time{}) // Clear deadline

	if err != nil {
		if common.IsConnectionClosedErr(err) || common.IsTimeoutError(err) {
			return fmt.Errorf("IPC connection error sending register_client: %w", err)
		}
		return fmt.Errorf("failed to send register command: %w", err)
	}

	// Set read deadline for response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(conn)
	var resp ipc.Response
	err = decoder.Decode(&resp)
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	if err != nil {
		if common.IsConnectionClosedErr(err) || common.IsTimeoutError(err) {
			return fmt.Errorf("IPC connection error waiting for register_client response: %w", err)
		}
		return fmt.Errorf("failed to decode register response: %w", err)
	}

	if resp.Status != ipc.StatusOK {
		return fmt.Errorf("service registration failed: %s", resp.Error)
	}
	return nil
}

// SendIPCCommand sends a command over the current connection.
func (m *IPCManager) SendIPCCommand(cmd *ipc.Command) error {
	conn := m.GetConnection()
	if conn == nil {
		return errors.New("cannot send command, IPC disconnected")
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	encoder := json.NewEncoder(conn)
	err := encoder.Encode(cmd)
	conn.SetWriteDeadline(time.Time{})

	if err != nil {
		if common.IsConnectionClosedErr(err) || common.IsTimeoutError(err) {
			// If send fails due to connection issue, trigger reconnect logic
			slog.Warn("IPC send failed, connection likely closed", "command", cmd.Command, "error", err)
			conn.Close()                     // Ensure the problematic connection is closed
			m.setConnectionState(false, nil) // Update state to trigger reconnect
			return fmt.Errorf("IPC connection closed while sending command %s: %w", cmd.Command, err)
		}
		return fmt.Errorf("failed to send command %s: %w", cmd.Command, err)
	}
	return nil
}

// listenIPCNotifications reads incoming messages (notifications) for a specific connection.
func (m *IPCManager) listenIPCNotifications(ctx context.Context, conn net.Conn) {
	slog.Info("Starting IPC notification listener for connection.")
	decoder := json.NewDecoder(conn)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping IPC notification listener due to context cancellation.")
			return
		default:
		}

		// Check if the connection we are listening on is still the active one
		if m.GetConnection() != conn {
			slog.Info("IPC connection changed, stopping listener for this specific old connection.")
			return
		}

		var cmd ipc.Command
		// Set read deadline for keep-alive/ping check
		if err := conn.SetReadDeadline(time.Now().Add(statusPingInterval + 30*time.Second)); err != nil {
			// Log non-closed errors when setting deadline
			if !common.IsConnectionClosedErr(err) {
				slog.Warn("Error setting read deadline for IPC notification listener", "error", err)
			}
			// Continue to attempt decode even if setting deadline fails
		}

		err := decoder.Decode(&cmd)
		_ = conn.SetReadDeadline(time.Time{}) // Clear deadline after read attempt

		if err != nil {
			logMsg := "Error reading IPC notifications"
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) {
				logMsg = "IPC connection closed while reading notifications."
			} else if common.IsTimeoutError(err) {
				logMsg = "IPC connection timed out waiting for notifications/ping."
			} else {
				logMsg = "Unexpected error reading IPC notifications."
			}

			// Log appropriately based on context state
			if ctx.Err() != nil {
				slog.Info("Stopping IPC notification listener due to context cancellation during/after decode.", "read_error", err)
			} else {
				slog.Warn(logMsg, "error", err)
			}

			// Connection error occurred, ensure state reflects disconnection
			conn.Close()                     // Ensure connection is closed
			m.setConnectionState(false, nil) // Trigger reconnect logic if this wasn't a planned shutdown
			return
		}

		// Process received command (currently, client expects no commands from service)
		switch cmd.Command {
		case "pong": // Example: Handle keep-alive pings if service sends them
			slog.Debug("Received pong from service")
		default:
			slog.Warn("Received unknown command/notification from service via IPC", "command", cmd.Command)
		}
	}
}
