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

	"github.com/yolki/kernelgatekeeper/pkg/common"
	"github.com/yolki/kernelgatekeeper/pkg/ipc"
)

const (
	clientStatusTTL = 150 * time.Second // How long client status reports are considered valid
)

type ClientState struct {
	UID        uint32
	PID        uint32
	LastPing   time.Time
	LastStatus ipc.PingStatusData
	conn       net.Conn // Store the connection here
}

type ClientManager struct {
	clients map[net.Conn]*ClientState
	mu      sync.RWMutex
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		clients: make(map[net.Conn]*ClientState),
	}
}

func (cm *ClientManager) AddClientConn(conn net.Conn, reportedPID int) (*ClientState, error) {
	peerCred, err := getPeerCredFromConn(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer credentials for registering client: %w", err)
	}
	uid := peerCred.Uid
	credentialPID := peerCred.Pid

	if int32(reportedPID) != credentialPID {
		slog.Warn("Client reported PID differs from socket credential PID",
			"reported_pid", reportedPID, "credential_pid", credentialPID, "uid", uid)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, exists := cm.clients[conn]; exists {
		slog.Warn("Client connection already exists in map during add? Removing old.", "remote_addr", conn.RemoteAddr())
		delete(cm.clients, conn)
	}

	newState := &ClientState{
		UID:      uid,
		PID:      uint32(credentialPID),
		LastPing: time.Now(),
		conn:     conn, // Store connection in state
	}
	cm.clients[conn] = newState
	clientCount := len(cm.clients)
	slog.Info("IPC client registered and added", "remote_addr", conn.RemoteAddr(), "uid", uid, "pid", credentialPID, "total_clients", clientCount)
	return newState, nil
}

func (cm *ClientManager) RemoveClientConn(conn net.Conn) {
	cm.mu.Lock()
	state, ok := cm.clients[conn]
	if ok {
		delete(cm.clients, conn)
	}
	clientCount := len(cm.clients)
	cm.mu.Unlock() // Unlock before Close

	if ok {
		slog.Info("IPC client removed", "remote_addr", conn.RemoteAddr(), "uid", state.UID, "pid", state.PID, "total_clients", clientCount)
	} else {
		slog.Debug("Attempted to remove non-existent or already removed IPC client", "remote_addr", conn.RemoteAddr())
	}
	if err := conn.Close(); err != nil {
		if !errors.Is(err, net.ErrClosed) && !common.IsConnectionClosedErr(err) {
			slog.Warn("Error closing removed IPC client connection", "remote_addr", conn.RemoteAddr(), "error", err)
		}
	}
}

func (cm *ClientManager) FindClientConnByUID(uid uint32) net.Conn {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for conn, state := range cm.clients {
		if state.UID == uid {
			return conn
		}
	}
	return nil
}

func (cm *ClientManager) GetClientCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.clients)
}

func (cm *ClientManager) GetClientState(conn net.Conn) *ClientState {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	state, _ := cm.clients[conn]
	return state // Returns nil if not found
}

func (cm *ClientManager) UpdateClientStatus(conn net.Conn, status ipc.PingStatusData) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if state, ok := cm.clients[conn]; ok {
		state.LastPing = time.Now()
		state.LastStatus = status
		return true
	}
	return false // Client not found (might have disconnected)
}

func (cm *ClientManager) GetAllClientDetails() ([]ipc.ClientInfo, map[uint32]ipc.ClientKerberosStatus) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	clientDetails := make([]ipc.ClientInfo, 0, len(cm.clients))
	clientKerberosStates := make(map[uint32]ipc.ClientKerberosStatus)
	now := time.Now()

	for _, state := range cm.clients {
		clientDetails = append(clientDetails, ipc.ClientInfo{PID: state.PID, UID: state.UID})
		if !state.LastPing.IsZero() && now.Sub(state.LastPing) < clientStatusTTL {
			clientKerberosStates[state.UID] = state.LastStatus.KerberosStatus
		}
	}
	return clientDetails, clientKerberosStates
}

func (cm *ClientManager) CloseAllClients(ctx context.Context) {
	cm.mu.Lock()
	connsToClose := make([]net.Conn, 0, len(cm.clients))
	for c := range cm.clients {
		connsToClose = append(connsToClose, c)
	}
	cm.clients = make(map[net.Conn]*ClientState) // Clear map
	cm.mu.Unlock()

	closeWg := sync.WaitGroup{}
	closeWg.Add(len(connsToClose))
	for _, c := range connsToClose {
		go func(connToClose net.Conn) {
			defer closeWg.Done()
			if err := connToClose.Close(); err != nil {
				if !errors.Is(err, net.ErrClosed) && !common.IsConnectionClosedErr(err) {
					slog.Warn("Error closing client connection during shutdown", "remote_addr", connToClose.RemoteAddr(), "error", err)
				}
			}
		}(c)
	}

	closeDone := make(chan struct{})
	go func() {
		closeWg.Wait()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		slog.Debug("Finished closing client connections.")
	case <-ctx.Done():
		slog.Warn("Timeout waiting for client connections to close during shutdown.")
	}
}

func getPeerCredFromConn(conn net.Conn) (*unix.Ucred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		fileConn, ok := conn.(interface{ File() (*os.File, error) })
		if !ok {
			return nil, fmt.Errorf("connection type %T does not support peer credentials", conn)
		}
		file, err := fileConn.File()
		if err != nil {
			return nil, fmt.Errorf("failed to get file descriptor from connection: %w", err)
		}
		defer file.Close()

		ucred, err := unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return nil, fmt.Errorf("getsockopt SO_PEERCRED failed on file descriptor %d: %w", file.Fd(), err)
		}
		return ucred, nil
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get SyscallConn from UnixConn: %w", err)
	}
	var ucred *unix.Ucred
	var controlErr, sockoptErr error

	controlErr = rawConn.Control(func(fd uintptr) {
		ucred, sockoptErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})

	if controlErr != nil {
		return nil, fmt.Errorf("rawConn.Control error getting peer credentials: %w", controlErr)
	}
	if sockoptErr != nil {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED failed: %w", sockoptErr)
	}
	if ucred == nil {
		return nil, errors.New("getsockopt SO_PEERCRED returned nil credentials without error")
	}
	return ucred, nil
}
