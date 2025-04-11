// FILE: pkg/servicecore/client_manager.go
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
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	clientStatusTTL = 150 * time.Second
)

type ClientState struct {
	UID         uint32
	PID         uint32
	ReportedPID int
	Conn        net.Conn
	Registered  time.Time
	LastPing    time.Time
	LastStatus  ipc.PingStatusData
}

type ClientManager struct {
	clients    map[net.Conn]*ClientState
	mu         sync.RWMutex
	bpfManager *ebpf.BPFManager
}

func NewClientManager(bpfMgr *ebpf.BPFManager) *ClientManager {
	return &ClientManager{
		clients:    make(map[net.Conn]*ClientState),
		bpfManager: bpfMgr,
	}
}

func (cm *ClientManager) AddClientConn(conn net.Conn, reportedPID int) (*ClientState, error) {
	if conn == nil {
		return nil, errors.New("cannot add nil connection")
	}

	// Get credentials from the connection
	peerCred, err := getPeerCredFromConn(conn)
	if err != nil {
		// Log error getting credentials
		remoteAddr := "unknown"
		if conn.RemoteAddr() != nil {
			remoteAddr = conn.RemoteAddr().String()
		}
		slog.Error("Failed to get peer credentials for registering client", "remote_addr", remoteAddr, "error", err)
		// Return error - critical for security/mapping
		return nil, fmt.Errorf("security check failed: could not get peer credentials: %w", err)
	}

	uid := peerCred.Uid
	credentialPID := peerCred.Pid // Use PID from credentials as the source of truth

	// Compare reported PID with credential PID (optional logging)
	if int32(reportedPID) != credentialPID {
		slog.Warn("Client reported PID differs from socket credential PID",
			"reported_pid", reportedPID, "credential_pid", credentialPID, "uid", uid, "remote_addr", conn.RemoteAddr())
		// Decide if this is an error or just a warning. For now, warning.
	} else {
		slog.Debug("Client reported PID matches socket credential PID", "pid", credentialPID, "uid", uid)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if this connection already exists (should not happen ideally)
	if existingState, exists := cm.clients[conn]; exists {
		slog.Warn("Client connection already exists in map during add? Replacing.",
			"remote_addr", conn.RemoteAddr(), "existing_uid", existingState.UID, "existing_pid", existingState.PID)
		// Consider removing the old PID from BPF exclusion first?
		// If cm.bpfManager != nil { cm.bpfManager.RemoveExcludedPID(existingState.PID) }
	}

	// Create the new state using the credential PID
	newState := &ClientState{
		UID:         uid,
		PID:         uint32(credentialPID),
		ReportedPID: reportedPID, // Store reported PID for reference/logging
		Conn:        conn,
		Registered:  time.Now(),
		LastPing:    time.Now(), // Initialize last ping time
	}
	cm.clients[conn] = newState
	clientCount := len(cm.clients)

	// Add the credential PID to BPF exclusion map
	if cm.bpfManager != nil {
		if err := cm.bpfManager.AddExcludedPID(newState.PID); err != nil {
			slog.Error("Failed to add client PID to BPF exclusion map", "pid", newState.PID, "error", err)
			// If adding to BPF fails, registration fails. Remove the client state.
			delete(cm.clients, conn)
			return nil, fmt.Errorf("failed to update BPF exclusion map: %w", err)
		}
	} else {
		slog.Warn("BPFManager not available, cannot exclude client PID from redirection", "pid", newState.PID)
	}

	slog.Info("IPC client registered and added", "remote_addr", conn.RemoteAddr(), "uid", uid, "pid", credentialPID, "total_clients", clientCount)
	return newState, nil
}

func (cm *ClientManager) RemoveClientConn(conn net.Conn) {
	if conn == nil {
		return
	}

	cm.mu.Lock()
	state, ok := cm.clients[conn]
	if ok {
		delete(cm.clients, conn)
	}
	clientCount := len(cm.clients)
	cm.mu.Unlock()

	if ok {
		slog.Info("IPC client removed", "remote_addr", conn.RemoteAddr(), "uid", state.UID, "pid", state.PID, "total_clients", clientCount)
		// Remove PID from BPF exclusion map
		if cm.bpfManager != nil {
			if err := cm.bpfManager.RemoveExcludedPID(state.PID); err != nil {
				slog.Error("Failed to remove client PID from BPF exclusion map", "pid", state.PID, "error", err)
				// Continue cleanup even if BPF removal fails
			}
		} else {
			slog.Warn("BPFManager not available, cannot remove client PID from exclusion map", "pid", state.PID)
		}
		// Close the connection
		if err := conn.Close(); err != nil {
			// Avoid logging expected errors on already closed connections
			if !errors.Is(err, net.ErrClosed) && !common.IsConnectionClosedErr(err) {
				slog.Warn("Error closing removed IPC client connection", "remote_addr", conn.RemoteAddr(), "error", err)
			}
		}
	} else {
		// Connection might have been removed already, or was never added
		slog.Debug("Attempted to remove non-existent or already removed IPC client", "remote_addr", conn.RemoteAddr())
	}
}

func (cm *ClientManager) GetClientCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.clients)
}

// GetClientState retrieves the state associated with a connection.
func (cm *ClientManager) GetClientState(conn net.Conn) *ClientState {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	// Returns nil if not found, which is the desired behavior
	state := cm.clients[conn]
	return state
}

// FindClientConnByUID searches for an active client connection by its UID.
// Returns the connection if found, otherwise nil.
func (cm *ClientManager) FindClientConnByUID(uid uint32) net.Conn {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for conn, state := range cm.clients {
		if state.UID == uid {
			return conn // Found the client's connection
		}
	}
	return nil // Not found
}

// UpdateClientStatus updates the last ping time and status for a client.
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
	return false
}

// GetAllClientDetails returns info for all currently connected clients.
func (cm *ClientManager) GetAllClientDetails() ([]ipc.ClientInfo, map[uint32]ipc.ClientKerberosStatus) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	clientDetails := make([]ipc.ClientInfo, 0, len(cm.clients))
	// Use UID as key for Kerberos status map, as one user might have multiple client instances (though unlikely)
	clientKerberosStates := make(map[uint32]ipc.ClientKerberosStatus)
	now := time.Now()

	for _, state := range cm.clients {
		// Add basic info
		clientDetails = append(clientDetails, ipc.ClientInfo{PID: state.PID, UID: state.UID})

		// Add Kerberos status if the last ping was recent enough
		if !state.LastPing.IsZero() && now.Sub(state.LastPing) < clientStatusTTL {
			// Only add if status is initialized or has useful info?
			// For now, add whatever the client sent last.
			clientKerberosStates[state.UID] = state.LastStatus.KerberosStatus
		} else if !state.LastPing.IsZero() {
			slog.Debug("Kerberos status for client expired", "uid", state.UID, "pid", state.PID, "last_ping", state.LastPing)
			// Optionally add an entry indicating expired status?
			// clientKerberosStates[state.UID] = ipc.ClientKerberosStatus{ Initialized: false, TgtTimeLeft: "Expired (TTL)" }
		} else {
			slog.Debug("No recent ping status available for client", "uid", state.UID, "pid", state.PID)
			// Optionally add an entry indicating unknown status?
			// clientKerberosStates[state.UID] = ipc.ClientKerberosStatus{ Initialized: false, TgtTimeLeft: "Unknown (No Ping)" }
		}
	}
	return clientDetails, clientKerberosStates
}

// CloseAllClients closes all managed client connections.
func (cm *ClientManager) CloseAllClients(ctx context.Context) {
	cm.mu.Lock()
	// Create copies of connections and PIDs to avoid holding lock during close/BPF operations
	connsToClose := make([]net.Conn, 0, len(cm.clients))
	pidsToRemove := make([]uint32, 0, len(cm.clients))
	slog.Info("Closing all client connections", "count", len(cm.clients))
	for c, s := range cm.clients {
		connsToClose = append(connsToClose, c)
		pidsToRemove = append(pidsToRemove, s.PID)
		slog.Debug("Marking client connection for closure", "uid", s.UID, "pid", s.PID)
	}
	// Clear the map while still holding the lock
	cm.clients = make(map[net.Conn]*ClientState)
	cm.mu.Unlock() // Release lock before closing connections and interacting with BPF

	// Remove PIDs from BPF map
	if cm.bpfManager != nil {
		for _, pid := range pidsToRemove {
			if err := cm.bpfManager.RemoveExcludedPID(pid); err != nil {
				slog.Error("Failed to remove client PID from BPF exclusion map during shutdown", "pid", pid, "error", err)
			}
		}
	} else {
		slog.Warn("BPFManager not available during shutdown, cannot remove client PIDs from exclusion map")
	}

	if len(connsToClose) == 0 {
		slog.Debug("No active client connections to close.")
		return
	}

	// Close connections concurrently
	closeWg := sync.WaitGroup{}
	closeWg.Add(len(connsToClose))

	for _, conn := range connsToClose {
		go func(c net.Conn) {
			defer closeWg.Done()
			if err := c.Close(); err != nil {
				// Log only unexpected errors
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

	// Wait for all closes to complete, with timeout from context
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

// getPeerCredFromConn extracts UID/PID from a Unix domain socket connection.
func getPeerCredFromConn(conn net.Conn) (*unix.Ucred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		// Fallback for non-UnixConn types (e.g., TCP connection proxied through systemd socket activation)
		// Try to get the underlying file descriptor
		fileConn, okFile := conn.(interface{ File() (*os.File, error) })
		if !okFile {
			return nil, fmt.Errorf("connection type %T does not support peer credentials", conn)
		}

		file, err := fileConn.File()
		if err != nil {
			return nil, fmt.Errorf("failed to get file descriptor from connection: %w", err)
		}
		defer file.Close()

		fdInt := int(file.Fd())
		slog.Debug("Attempting getsockopt SO_PEERCRED on file descriptor", "fd", fdInt)
		ucred, err := unix.GetsockoptUcred(fdInt, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return nil, fmt.Errorf("getsockopt SO_PEERCRED failed on fd %d: %w", fdInt, err)
		}
		if ucred == nil {
			// This case should ideally not happen if getsockopt returns no error
			return nil, fmt.Errorf("getsockopt SO_PEERCRED on fd %d returned nil credentials without error", fdInt)
		}
		slog.Debug("Successfully obtained peer credentials via File()", "fd", fdInt, "uid", ucred.Uid, "pid", ucred.Pid)
		return ucred, nil
	}

	// Preferred method for UnixConn
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get SyscallConn from UnixConn: %w", err)
	}

	var ucred *unix.Ucred
	var controlErr error
	var sockoptErr error

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
		// This case should ideally not happen if getsockopt returns no error
		return nil, errors.New("getsockopt SO_PEERCRED returned nil credentials without error via SyscallConn")
	}

	slog.Debug("Successfully obtained peer credentials via SyscallConn", "uid", ucred.Uid, "pid", ucred.Pid)
	return ucred, nil
}
