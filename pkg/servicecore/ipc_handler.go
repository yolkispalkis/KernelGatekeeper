package servicecore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil" // Keep for getInterfacesResponse
	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	ipcWriteTimeout    = 2 * time.Second
	ipcReadIdleTimeout = 90 * time.Second // Increased timeout as client only sends pings periodically
)

type IpcHandler struct {
	stateManager *StateManager // Access state (clients, bpf manager for status)
}

func NewIpcHandler(stateMgr *StateManager) *IpcHandler {
	return &IpcHandler{
		stateManager: stateMgr,
	}
}

func (h *IpcHandler) HandleConnection(ctx context.Context, conn net.Conn) {
	clientAddrStr := "unknown"
	if conn.RemoteAddr() != nil {
		clientAddrStr = conn.RemoteAddr().String()
	}
	logCtx := slog.With("client_addr", clientAddrStr)
	logCtx.Info("Handling new IPC connection")

	clientManager := h.stateManager.GetClientManager()
	var clientInfo *ClientState // Track state for this specific connection

	defer func() {
		if clientInfo != nil {
			logCtx.Info("Removing client state due to IPC connection closure", "uid", clientInfo.UID, "pid", clientInfo.PID)
			clientManager.RemoveClientConn(conn) // This also closes the connection
		} else {
			logCtx.Info("Closing unregistered IPC connection")
			conn.Close() // Ensure close even if not registered
		}
		logCtx.Debug("Finished handling IPC connection")
	}()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		select {
		case <-ctx.Done():
			logCtx.Info("Closing IPC handler due to service shutdown.")
			return
		default:
		}

		var cmd ipc.Command
		// Set read deadline for detecting idle/dead clients
		conn.SetReadDeadline(time.Now().Add(ipcReadIdleTimeout))
		err := decoder.Decode(&cmd)
		conn.SetReadDeadline(time.Time{}) // Clear deadline immediately after read attempt

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) {
				logCtx.Info("IPC connection closed by client or network.")
			} else if common.IsTimeoutError(err) {
				logCtx.Warn("IPC connection read timeout (idle/no ping). Closing connection.", "timeout", ipcReadIdleTimeout)
			} else {
				logCtx.Error("Failed to decode IPC command", "error", err)
			}
			return // Exit handler for this connection
		}

		// Fetch current state on each command, as it might have been added/removed
		clientInfo = clientManager.GetClientState(conn)

		logCtxCmd := logCtx.With("command", cmd.Command)
		if clientInfo != nil {
			logCtxCmd = logCtxCmd.With("uid", clientInfo.UID, "pid", clientInfo.PID)
		}

		logCtxCmd.Debug("Received IPC command")

		var resp *ipc.Response
		var procErr error

		// Check registration status *after* receiving the command
		isRegistered := clientInfo != nil
		requiresRegistration := cmd.Command != "register_client" // Only register_client is allowed before registration

		if requiresRegistration && !isRegistered {
			procErr = errors.New("client not registered")
			logCtxCmd.Warn("Command rejected: client not registered")
			resp = ipc.NewErrorResponse(procErr.Error())
		} else {
			// Pass the pointer to allow processIPCCommand to update it upon registration
			resp, procErr = h.processIPCCommand(conn, &cmd, &clientInfo)
			if procErr != nil {
				resp = ipc.NewErrorResponse(procErr.Error()) // Use helper for consistent error response
				logCtxCmd.Error("Error processing IPC command", "error", procErr)
			} else if resp == nil {
				// This case should ideally not happen if processIPCCommand always returns a response or error
				logCtxCmd.Error("Internal error: processIPCCommand returned nil response and nil error")
				resp = ipc.NewErrorResponse("internal server error processing command")
			}
		}

		// Send response if one was generated
		if resp != nil {
			conn.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
			encodeErr := encoder.Encode(resp)
			conn.SetWriteDeadline(time.Time{}) // Clear deadline

			if encodeErr != nil {
				logCtxCmd.Error("Failed to send IPC response", "error", encodeErr)
				// Don't return immediately, let the loop try reading the next command,
				// but the connection is likely broken. RemoveClientConn will be called in defer.
				return // Exit handler on write failure
			}
			logCtxCmd.Debug("Sent IPC response", "status", resp.Status)
		} else {
			// Should only happen for commands that don't inherently require a response (none currently)
			logCtxCmd.Debug("No response generated for command")
		}
	}
}

// processIPCCommand handles the logic for each command.
// It takes a pointer to the clientInfo pointer (*ClientState) so it can update
// the caller's clientInfo variable when registration occurs.
func (h *IpcHandler) processIPCCommand(conn net.Conn, cmd *ipc.Command, clientInfoPtr **ClientState) (*ipc.Response, error) {
	currentClientInfo := *clientInfoPtr // Dereference to get the current *ClientState
	clientManager := h.stateManager.GetClientManager()

	switch cmd.Command {
	case "register_client":
		if currentClientInfo != nil {
			// Log the attempt but return success? Or error?
			// Let's return an error to prevent unexpected state changes.
			slog.Warn("IPC client attempted to register again on the same connection", "uid", currentClientInfo.UID, "pid", currentClientInfo.PID)
			return nil, errors.New("client already registered on this connection")
		}

		var data ipc.RegisterClientData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid register_client data: %w", err)
		}

		// AddClientConn handles getting peer credentials
		newState, err := clientManager.AddClientConn(conn, data.PID)
		if err != nil {
			slog.Error("Failed to add client connection during registration", "reported_pid", data.PID, "error", err)
			return nil, fmt.Errorf("client registration failed: %w", err) // Propagate error
		}
		*clientInfoPtr = newState // IMPORTANT: Update the clientInfo in the HandleConnection scope

		return ipc.NewOKResponse("Client registered successfully")

	// Removed get_config

	// Removed update_ports

	case "get_status":
		// This command doesn't require registration? If yes, HandleConnection check is sufficient.
		// If it requires registration, add check here:
		// if currentClientInfo == nil {
		//     return nil, errors.New("get_status requires registration")
		// }
		return h.getStatusResponse() // Call helper function

	case "get_interfaces":
		// Same registration consideration as get_status
		return h.getInterfacesResponse() // Call helper function

	case "ping_status":
		if currentClientInfo == nil {
			return nil, errors.New("ping_status requires registration")
		}
		var data ipc.PingStatusData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid ping_status data: %w", err)
		}
		// UpdateClientStatus returns false if client was removed between read and processing
		if !clientManager.UpdateClientStatus(conn, data) {
			return nil, errors.New("client disconnected before status ping could be processed")
		}
		// No data needed in OK response for ping
		return ipc.NewOKResponse(nil)

	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Command)
	}
}

// getStatusResponse retrieves status information.
func (h *IpcHandler) getStatusResponse() (*ipc.Response, error) {
	cfg := h.stateManager.GetConfig() // Get current config
	clientManager := h.stateManager.GetClientManager()
	bpfMgr := h.stateManager.GetBpfManager()
	startTime := h.stateManager.GetStartTime()
	serviceVersion := "dev" // TODO: Inject actual version

	clientDetails, clientKerberosStates := clientManager.GetAllClientDetails()
	clientCount := len(clientDetails)

	statusData := ipc.GetStatusData{
		Status:               "running", // Assume running unless BPF fails
		ActiveInterface:      cfg.EBPF.Interface,
		ActivePorts:          cfg.EBPF.TargetPorts, // Reflect currently configured ports
		LoadMode:             cfg.EBPF.LoadMode,
		UptimeSeconds:        int64(time.Since(startTime).Seconds()),
		ServiceVersion:       serviceVersion,
		ConnectedClients:     clientCount,
		ClientDetails:        clientDetails,
		ClientKerberosStates: clientKerberosStates, // Include Kerberos status from pings
	}

	if bpfMgr != nil {
		_, matched, err := bpfMgr.GetStats() // Get stats from BPF manager cache
		if err != nil {
			slog.Warn("Failed to get eBPF stats for status response", "error", err)
			statusData.Status = "degraded (bpf stats error)" // More specific status
		} else {
			statusData.MatchedConns = matched.Packets
		}
	} else {
		slog.Warn("BPF manager not available for status response")
		statusData.Status = "degraded (bpf manager unavailable)"
	}

	// Check notification channel utilization
	notifChan := h.stateManager.GetNotificationChannel()
	if notifChan != nil && cap(notifChan) > 0 {
		usage := float64(len(notifChan)) / float64(cap(notifChan))
		if usage > 0.8 { // Example threshold
			slog.Warn("High BPF notification channel usage detected", "usage", usage)
			if statusData.Status == "running" { // Append warning if not already degraded
				statusData.Status = "warning (high channel usage)"
			}
		}
	}

	return ipc.NewOKResponse(statusData)
}

// getInterfacesResponse retrieves available network interfaces.
func (h *IpcHandler) getInterfacesResponse() (*ipc.Response, error) {
	interfaces, err := bpfutil.GetAvailableInterfaces()
	if err != nil {
		slog.Error("Failed to get network interfaces for response", "error", err)
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	// Get current interface from config held by state manager
	currentInterface := h.stateManager.GetConfig().EBPF.Interface
	data := ipc.GetInterfacesData{Interfaces: interfaces, CurrentInterface: currentInterface}
	return ipc.NewOKResponse(data)
}
