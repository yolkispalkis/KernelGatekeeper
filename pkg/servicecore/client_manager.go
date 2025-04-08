package servicecore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	clientStatusTTL = 150 * time.Second // How long client status reports are considered valid (2.5 * ping interval)
)

// ClientState holds information about a connected client.
type ClientState struct {
	UID         uint32             // User ID from socket credentials
	PID         uint32             // Process ID from socket credentials
	ReportedPID int                // Process ID reported by client during registration (for comparison)
	Conn        net.Conn           // The actual connection object
	Registered  time.Time          // Timestamp of successful registration
	LastPing    time.Time          // Timestamp of the last received ping_status
	LastStatus  ipc.PingStatusData // Last status data received from the client
}

type ClientManager struct {
	clients map[net.Conn]*ClientState // Map connection object to its state
	mu      sync.RWMutex              // Protects the clients map
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		clients: make(map[net.Conn]*ClientState),
	}
}

// AddClientConn registers a new client connection after verifying credentials.
func (cm *ClientManager) AddClientConn(conn net.Conn, reportedPID int) (*ClientState, error) {
	if conn == nil {
		return nil, errors.New("cannot add nil connection")
	}

	peerCred, err := getPeerCredFromConn(conn)
	if err != nil {
		// Log the specific error for better debugging
		remoteAddr := "unknown"
		if conn.RemoteAddr() != nil {
			remoteAddr = conn.RemoteAddr().String()
		}
		slog.Error("Failed to get peer credentials for registering client", "remote_addr", remoteAddr, "error", err)
		// Don't just return fmt.Errorf, return a more specific error maybe?
		return nil, fmt.Errorf("security check failed: could not get peer credentials: %w", err)
	}

	uid := peerCred.Uid
	credentialPID := peerCred.Pid // This is the trustworthy PID

	// Log difference but proceed using credentialPID
	if int32(reportedPID) != credentialPID {
		slog.Warn("Client reported PID differs from socket credential PID",
			"reported_pid", reportedPID, "credential_pid", credentialPID, "uid", uid, "remote_addr", conn.RemoteAddr())
	} else {
		slog.Debug("Client reported PID matches socket credential PID", "pid", credentialPID, "uid", uid)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Double-check if connection somehow already exists (shouldn't happen often)
	if existingState, exists := cm.clients[conn]; exists {
		slog.Warn("Client connection already exists in map during add? Replacing.",
			"remote_addr", conn.RemoteAddr(), "existing_uid", existingState.UID, "existing_pid", existingState.PID)
		// No need to explicitly delete, will be overwritten
	}

	newState := &ClientState{
		UID:         uid,
		PID:         uint32(credentialPID),
		ReportedPID: reportedPID,
		Conn:        conn,
		Registered:  time.Now(),
		LastPing:    time.Now(), // Set initial LastPing on registration
	}
	cm.clients[conn] = newState
	clientCount := len(cm.clients)

	slog.Info("IPC client registered and added", "remote_addr", conn.RemoteAddr(), "uid", uid, "pid", credentialPID, "total_clients", clientCount)
	return newState, nil
}

// RemoveClientConn removes a client and closes its connection.
func (cm *ClientManager) RemoveClientConn(conn net.Conn) {
	if conn == nil {
		return
	}

	cm.mu.Lock()
	state, ok := cm.clients[conn]
	if ok {
		delete(cm.clients, conn) // Remove from map first
	}
	clientCount := len(cm.clients) // Get count after removal
	cm.mu.Unlock()                 // Unlock before potentially slow Close()

	if ok {
		slog.Info("IPC client removed", "remote_addr", conn.RemoteAddr(), "uid", state.UID, "pid", state.PID, "total_clients", clientCount)
		// Close the connection outside the lock
		if err := conn.Close(); err != nil {
			// Avoid logging errors if the connection was already closed
			if !errors.Is(err, net.ErrClosed) && !common.IsConnectionClosedErr(err) {
				slog.Warn("Error closing removed IPC client connection", "remote_addr", conn.RemoteAddr(), "error", err)
			}
		}
	} else {
		// Only log if it wasn't found, no need to close again if ok=false
		slog.Debug("Attempted to remove non-existent or already removed IPC client", "remote_addr", conn.RemoteAddr())
	}
}

// FindClientConnByUID finds the *first* active connection associated with a given UID.
// Note: Multiple connections from the same UID are possible but usually indicate an issue.
func (cm *ClientManager) FindClientConnByUID(uid uint32) net.Conn {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for conn, state := range cm.clients {
		if state.UID == uid {
			// TODO: Add logic here to potentially return the *newest* connection
			// based on Registered time if multiple exist for the same UID?
			// For now, return the first match.
			return conn
		}
	}
	return nil
}

// GetClientCount returns the number of currently connected and registered clients.
func (cm *ClientManager) GetClientCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.clients)
}

// GetClientState returns the state associated with a specific connection object.
func (cm *ClientManager) GetClientState(conn net.Conn) *ClientState {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	// Returns nil if not found, which is the desired behavior
	state := cm.clients[conn]
	return state
}

// UpdateClientStatus updates the last ping time and status data for a client.
// Returns true if the client was found and updated, false otherwise.
func (cm *ClientManager) UpdateClientStatus(conn net.Conn, status ipc.PingStatusData) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if state, ok := cm.clients[conn]; ok {
		state.LastPing = time.Now()
		state.LastStatus = status
		slog.Debug("Updated client status from ping", "uid", state.UID, "pid", state.PID, "active_conns", status.ActiveConnections)
		return true
	}
	slog.Warn("Received ping status for unknown or disconnected client", "remote_addr", conn.RemoteAddr())
	return false // Client not found (might have disconnected)
}

// GetAllClientDetails retrieves basic info and last known Kerberos status for all clients.
func (cm *ClientManager) GetAllClientDetails() ([]ipc.ClientInfo, map[uint32]ipc.ClientKerberosStatus) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	clientDetails := make([]ipc.ClientInfo, 0, len(cm.clients))
	// Map UID -> Last Known Kerberos Status
	clientKerberosStates := make(map[uint32]ipc.ClientKerberosStatus)
	now := time.Now()

	for _, state := range cm.clients {
		// Add basic info regardless of ping status
		clientDetails = append(clientDetails, ipc.ClientInfo{PID: state.PID, UID: state.UID})

		// Only include Kerberos status if the last ping is recent enough
		if !state.LastPing.IsZero() && now.Sub(state.LastPing) < clientStatusTTL {
			// Check if we actually have Kerberos data from the last ping
			// The KerberosStatus struct itself could be non-nil but empty if client had no ticket
			clientKerberosStates[state.UID] = state.LastStatus.KerberosStatus
		} else if !state.LastPing.IsZero() {
			slog.Debug("Kerberos status for client expired", "uid", state.UID, "pid", state.PID, "last_ping", state.LastPing)
			// Optionally, represent expired status explicitly?
			// clientKerberosStates[state.UID] = ipc.ClientKerberosStatus{ Initialized: false, TgtTimeLeft: "Expired/Stale" }
		} else {
			slog.Debug("No recent ping status available for client", "uid", state.UID, "pid", state.PID)
			// Optionally, represent unknown status explicitly?
			// clientKerberosStates[state.UID] = ipc.ClientKerberosStatus{ Initialized: false, TgtTimeLeft: "Unknown" }
		}
	}
	return clientDetails, clientKerberosStates
}

// CloseAllClients closes all managed client connections gracefully.
// Uses the provided context for potential timeout on waiting for goroutines.
func (cm *ClientManager) CloseAllClients(ctx context.Context) {
	cm.mu.Lock()
	// Create a copy of connections to close to avoid holding the lock during Close()
	connsToClose := make([]net.Conn, 0, len(cm.clients))
	slog.Info("Closing all client connections", "count", len(cm.clients))
	for c, s := range cm.clients {
		connsToClose = append(connsToClose, c)
		slog.Debug("Marking client connection for closure", "uid", s.UID, "pid", s.PID)
	}
	cm.clients = make(map[net.Conn]*ClientState) // Clear the map while holding the lock
	cm.mu.Unlock()

	if len(connsToClose) == 0 {
		slog.Debug("No active client connections to close.")
		return
	}

	closeWg := sync.WaitGroup{}
	closeWg.Add(len(connsToClose))

	for _, conn := range connsToClose {
		go func(c net.Conn) {
			defer closeWg.Done()
			if err := c.Close(); err != nil {
				// Log errors only if not related to already closed connections
				if !errors.Is(err, net.ErrClosed) && !common.IsConnectionClosedErr(err) {
					remoteAddr := "unknown"
					if c.RemoteAddr() != nil {
						remoteAddr = c.RemoteAddr().String()
					}
					slog.Warn("Error closing client connection during shutdown", "remote_addr", remoteAddr, "error", err)
				}
			}
		}(conn)
	}

	// Wait for all close operations to complete, with a timeout from the context
	closeDone := make(chan struct{})
	go func() {
		closeWg.Wait()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		slog.Debug("Finished closing all client connections.")
	case <-ctx.Done():
		slog.Warn("Timeout waiting for all client connections to close during shutdown.")
	}
}

// getPeerCredFromConn retrieves the UID/PID of the peer connected via a UNIX socket.
func getPeerCredFromConn(conn net.Conn) (*unix.Ucred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		// Check if the underlying connection provides a File descriptor
		fileConn, okFile := conn.(interface{ File() (*os.File, error) })
		if !okFile {
			return nil, fmt.Errorf("connection type %T does not support peer credentials", conn)
		}

		// Warning: Getting the File duplicates the FD. We MUST close it.
		file, err := fileConn.File()
		if err != nil {
			return nil, fmt.Errorf("failed to get file descriptor from connection: %w", err)
		}
		defer file.Close() // Ensure the duplicated FD is closed

		fdInt := int(file.Fd())
		slog.Debug("Attempting getsockopt SO_PEERCRED on file descriptor", "fd", fdInt)
		ucred, err := unix.GetsockoptUcred(fdInt, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return nil, fmt.Errorf("getsockopt SO_PEERCRED failed on fd %d: %w", fdInt, err)
		}
		if ucred == nil {
			// Should not happen if err is nil, but check defensively
			return nil, fmt.Errorf("getsockopt SO_PEERCRED on fd %d returned nil credentials without error", fdInt)
		}
		slog.Debug("Successfully obtained peer credentials via File()", "fd", fdInt, "uid", ucred.Uid, "pid", ucred.Pid)
		return ucred, nil
	}

	// Preferred method using SyscallConn for net.UnixConn
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get SyscallConn from UnixConn: %w", err)
	}

	var ucred *unix.Ucred
	var controlErr error
	var sockoptErr error // Capture the error from getsockopt specifically

	// The Control func provides access to the raw file descriptor
	controlErr = rawConn.Control(func(fd uintptr) {
		slog.Debug("Attempting getsockopt SO_PEERCRED via SyscallConn", "fd", int(fd))
		ucred, sockoptErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})

	if controlErr != nil {
		return nil, fmt.Errorf("rawConn.Control error getting peer credentials: %w", controlErr)
	}
	if sockoptErr != nil {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED failed: %w", sockoptErr)
	}
	if ucred == nil {
		// Defensive check: should be redundant if sockoptErr is nil
		return nil, errors.New("getsockopt SO_PEERCRED returned nil credentials without error via SyscallConn")
	}

	slog.Debug("Successfully obtained peer credentials via SyscallConn", "uid", ucred.Uid, "pid", ucred.Pid)
	return ucred, nil
}
