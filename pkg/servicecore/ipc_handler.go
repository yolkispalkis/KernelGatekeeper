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

	"github.com/yolki/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolki/kernelgatekeeper/pkg/common"
	"github.com/yolki/kernelgatekeeper/pkg/ipc"
)

const (
	ipcWriteTimeout    = 2 * time.Second
	ipcReadIdleTimeout = 90 * time.Second
)

type IpcHandler struct {
	stateManager *StateManager // Access state (config, bpf, clients)
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
			clientManager.RemoveClientConn(conn)
		} else {
			conn.Close() // Ensure close even if not registered
			logCtx.Info("Closing unregistered IPC connection")
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
		conn.SetReadDeadline(time.Now().Add(ipcReadIdleTimeout))
		err := decoder.Decode(&cmd)
		conn.SetReadDeadline(time.Time{})

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) {
				logCtx.Info("IPC connection closed by client or network.")
			} else if common.IsTimeoutError(err) {
				logCtx.Warn("IPC connection read timeout. Closing connection.", "timeout", ipcReadIdleTimeout)
			} else {
				logCtx.Error("Failed to decode IPC command", "error", err)
			}
			return // Exit handler
		}

		// Refresh clientInfo in case state changed (e.g., removed by another goroutine)
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
			// Pass clientInfo pointer to allow update on registration
			resp, procErr = h.processIPCCommand(conn, &cmd, &clientInfo)
			if procErr != nil {
				resp = ipc.NewErrorResponse(procErr.Error())
				logCtxCmd.Error("Error processing IPC command", "error", procErr)
			} else if resp == nil {
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
				return // Connection likely broken
			}
			logCtxCmd.Debug("Sent IPC response", "status", resp.Status)
		} else {
			logCtxCmd.Warn("No response generated for command")
		}
	}
}

func (h *IpcHandler) processIPCCommand(conn net.Conn, cmd *ipc.Command, clientInfoPtr **ClientState) (*ipc.Response, error) {
	currentClientInfo := *clientInfoPtr
	clientManager := h.stateManager.GetClientManager()

	switch cmd.Command {
	case "register_client":
		if currentClientInfo != nil {
			return nil, errors.New("client already registered on this connection")
		}

		var data ipc.RegisterClientData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid register_client data: %w", err)
		}

		newState, err := clientManager.AddClientConn(conn, data.PID)
		if err != nil {
			slog.Error("Failed to add client connection during registration", "error", err)
			return nil, fmt.Errorf("client registration failed: %w", err)
		}
		*clientInfoPtr = newState // Update caller's pointer

		return ipc.NewOKResponse("Client registered successfully")

	case "get_config":
		cfg := h.stateManager.GetConfig()
		return ipc.NewOKResponse(ipc.GetConfigData{Config: *cfg})

	case "update_ports":
		cfg := h.stateManager.GetConfig()
		if !cfg.EBPF.AllowDynamicPorts {
			return nil, errors.New("dynamic port updates disabled by configuration")
		}

		var data ipc.UpdatePortsData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid update_ports data: %w", err)
		}
		bpfMgr := h.stateManager.GetBpfManager()
		if bpfMgr == nil {
			return nil, errors.New("BPF manager is not ready")
		}

		if err := bpfMgr.UpdateTargetPorts(data.Ports); err != nil {
			uid := uint32(0)
			if currentClientInfo != nil {
				uid = currentClientInfo.UID
			}
			slog.Error("Failed to update target ports via IPC", "error", err, "client_uid", uid)
			return nil, fmt.Errorf("BPF map update failed: %w", err)
		}

		// Directly update the config held by state manager (under lock)
		// Note: This bypasses ReloadConfig logic. Consider if ReloadConfig should handle this.
		smConfig := h.stateManager.config.Load()
		smConfig.EBPF.TargetPorts = data.Ports // Need to ensure this is safe or use atomic swap
		h.stateManager.config.Store(smConfig)  // Update the atomic pointer

		uid := uint32(0)
		if currentClientInfo != nil {
			uid = currentClientInfo.UID
		}
		slog.Info("Target ports updated via IPC", "ports", data.Ports, "client_uid", uid)
		return ipc.NewOKResponse("Ports updated successfully")

	case "get_status":
		return h.getStatusResponse()

	case "get_interfaces":
		return h.getInterfacesResponse()

	case "ping_status":
		var data ipc.PingStatusData
		if err := ipc.DecodeData(cmd.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid ping_status data: %w", err)
		}
		if !clientManager.UpdateClientStatus(conn, data) {
			return nil, errors.New("client disconnected before status ping could be processed")
		}
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
	serviceVersion := "dev" // Inject actual version

	clientDetails, clientKerberosStates := clientManager.GetAllClientDetails()
	clientCount := len(clientDetails)

	statusData := ipc.GetStatusData{
		Status:               "running",
		ActiveInterface:      cfg.EBPF.Interface,
		ActivePorts:          cfg.EBPF.TargetPorts,
		LoadMode:             cfg.EBPF.LoadMode,
		UptimeSeconds:        int64(time.Since(startTime).Seconds()),
		ServiceVersion:       serviceVersion,
		ConnectedClients:     clientCount,
		ClientDetails:        clientDetails,
		ClientKerberosStates: clientKerberosStates,
	}

	if bpfMgr != nil {
		_, matched, err := bpfMgr.GetStats()
		if err != nil {
			slog.Warn("Failed to get eBPF stats for status response", "error", err)
			statusData.Status = "degraded"
		} else {
			statusData.MatchedConns = matched.Packets
		}
	} else {
		statusData.Status = "degraded"
	}

	return ipc.NewOKResponse(statusData)
}

func (h *IpcHandler) getInterfacesResponse() (*ipc.Response, error) {
	interfaces, err := bpfutil.GetAvailableInterfaces()
	if err != nil {
		slog.Error("Failed to get network interfaces for response", "error", err)
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	currentInterface := h.stateManager.GetConfig().EBPF.Interface
	data := ipc.GetInterfacesData{Interfaces: interfaces, CurrentInterface: currentInterface}
	return ipc.NewOKResponse(data)
}
