// FILE: pkg/servicecore/ipc_handler.go
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

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	ipcWriteTimeout    = 2 * time.Second
	ipcReadIdleTimeout = 90 * time.Second
)

type IpcHandler struct {
	stateManager *StateManager
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
	var clientInfo *ClientState

	defer func() {
		if clientInfo != nil {
			logCtx.Info("Removing client state due to IPC connection closure", "uid", clientInfo.UID, "pid", clientInfo.PID)
			clientManager.RemoveClientConn(conn)
		} else {
			logCtx.Info("Closing unregistered IPC connection")
			conn.Close()
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

		// Set read deadline for idle timeout
		conn.SetReadDeadline(time.Now().Add(ipcReadIdleTimeout))
		err := decoder.Decode(&cmd)
		// Clear deadline immediately after read attempt
		conn.SetReadDeadline(time.Time{})

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) {
				logCtx.Info("IPC connection closed by client or network.")
			} else if common.IsTimeoutError(err) {
				logCtx.Warn("IPC connection read timeout (idle/no ping). Closing connection.", "timeout", ipcReadIdleTimeout)
			} else {
				logCtx.Error("Failed to decode IPC command", "error", err)
			}
			return
		}

		clientInfo = clientManager.GetClientState(conn)

		logCtxCmd := logCtx.With("command", cmd.Command)
		if clientInfo != nil {
			logCtxCmd = logCtxCmd.With("uid", clientInfo.UID, "pid", clientInfo.PID)
		}

		logCtxCmd.Debug("Received IPC command")

		var resp *ipc.Response
		var procErr error

		isRegistered := clientInfo != nil
		requiresRegistration := cmd.Command != "register_client"

		if requiresRegistration && !isRegistered {
			procErr = errors.New("client not registered")
			logCtxCmd.Warn("Command rejected: client not registered")
			resp = ipc.NewErrorResponse(procErr.Error())
		} else {

			resp, procErr = h.processIPCCommand(conn, &cmd, &clientInfo)
			if procErr != nil {
				// Ensure response is error type if processing failed
				if resp == nil || resp.Status != ipc.StatusError {
					resp = ipc.NewErrorResponse(procErr.Error())
				}
				logCtxCmd.Error("Error processing IPC command", "error", procErr)
			} else if resp == nil {
				// Should ideally not happen if processIPCCommand is well-behaved
				logCtxCmd.Error("Internal error: processIPCCommand returned nil response and nil error")
				resp = ipc.NewErrorResponse("internal server error processing command")
			}
		}

		if resp != nil {
			conn.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
			encodeErr := encoder.Encode(resp)
			conn.SetWriteDeadline(time.Time{})

			if encodeErr != nil {
				logCtxCmd.Error("Failed to send IPC response", "error", encodeErr)
				// If we can't send response, likely connection is dead, terminate handler
				return
			}
			logCtxCmd.Debug("Sent IPC response", "status", resp.Status)
		} else {
			// Some commands might not require a response (though currently all do)
			logCtxCmd.Debug("No response generated for command")
		}
	}
}

func (h *IpcHandler) processIPCCommand(conn net.Conn, cmd *ipc.Command, clientInfoPtr **ClientState) (*ipc.Response, error) {
	currentClientInfo := *clientInfoPtr
	clientManager := h.stateManager.GetClientManager()

	switch cmd.Command {
	case "register_client":
		if currentClientInfo != nil {
			// Client trying to register again on the same connection
			slog.Warn("IPC client attempted to register again on the same connection", "uid", currentClientInfo.UID, "pid", currentClientInfo.PID)
			return nil, errors.New("client already registered on this connection")
		}

		var data ipc.RegisterClientData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid register_client data: %w", err)
		}

		newState, err := clientManager.AddClientConn(conn, data.PID)
		if err != nil {
			slog.Error("Failed to add client connection during registration", "reported_pid", data.PID, "error", err)
			return nil, fmt.Errorf("client registration failed: %w", err)
		}
		*clientInfoPtr = newState // Update the caller's pointer

		return ipc.NewOKResponse("Client registered successfully")

	case "get_status":
		// No need to check registration here, status is public?
		// Or maybe require registration? Let's allow without for now.
		return h.getStatusResponse()

	case "ping_status":
		if currentClientInfo == nil {
			return nil, errors.New("ping_status requires registration")
		}
		var data ipc.PingStatusData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid ping_status data: %w", err)
		}

		// Update status, check if client still exists
		if !clientManager.UpdateClientStatus(conn, data) {
			// Client might have disconnected between read and update
			return nil, errors.New("client disconnected before status ping could be processed")
		}
		// Respond with simple OK, no data needed
		return ipc.NewOKResponse(nil)

	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Command)
	}
}

func (h *IpcHandler) getStatusResponse() (*ipc.Response, error) {
	cfg := h.stateManager.GetConfig()
	clientManager := h.stateManager.GetClientManager()
	bpfMgr := h.stateManager.GetBpfManager()
	startTime := h.stateManager.GetStartTime()
	serviceVersion := "dev" // TODO: Inject version properly

	clientDetails, clientKerberosStates := clientManager.GetAllClientDetails()
	clientCount := len(clientDetails)

	statusData := ipc.GetStatusData{
		Status:               "running",
		ActivePorts:          cfg.EBPF.TargetPorts,
		LoadMode:             cfg.EBPF.LoadMode,
		UptimeSeconds:        int64(time.Since(startTime).Seconds()),
		ServiceVersion:       serviceVersion,
		ConnectedClients:     clientCount,
		ClientDetails:        clientDetails,
		ClientKerberosStates: clientKerberosStates,
	}

	if bpfMgr != nil {
		// FIX: Use the implemented GetStats method
		stats, err := bpfMgr.GetStats()
		if err != nil {
			// GetStats from cache shouldn't error, but handle defensively
			slog.Warn("Failed to get eBPF stats for status response", "error", err)
			statusData.Status = "degraded (bpf stats error)"
		} else {
			statusData.TotalRedirected = stats.Redirected
			statusData.TotalGetsockoptOK = stats.GetsockoptOk
			statusData.TotalGetsockoptFail = stats.GetsockoptFail
		}
	} else {
		slog.Warn("BPF manager not available for status response")
		statusData.Status = "degraded (bpf manager unavailable)"
	}

	return ipc.NewOKResponse(statusData)
}
