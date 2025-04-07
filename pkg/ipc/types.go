package ipc

import (
	"encoding/json"
	"fmt"

	"github.com/yolki/kernelgatekeeper/pkg/config"
)

// Command represents a command sent over the IPC channel.
type Command struct {
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Response represents a response sent over the IPC channel.
type Response struct {
	Status string          `json:"status"`
	Error  string          `json:"error,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

const (
	StatusOK    = "ok"
	StatusError = "error"
)

// --- Command Data Payloads ---

// RegisterClientData is sent by the client to register with the service.
type RegisterClientData struct {
	PID int `json:"pid"` // PID of the client process
}

// UpdatePortsData is sent by the client to update the BPF target ports (if allowed).
type UpdatePortsData struct {
	Ports []int `json:"ports"` // List of target ports
}

// PingStatusData is sent periodically by the client to the service.
type PingStatusData struct {
	ActiveConnections int64                `json:"active_connections"` // Number of currently proxied connections by this client
	KerberosStatus    ClientKerberosStatus `json:"kerberos_status"`    // Status of the client's Kerberos ticket
}

// --- Response Data Payloads ---

// GetConfigData is sent by the service in response to a get_config command.
type GetConfigData struct {
	Config config.Config `json:"config"`
}

// ClientKerberosStatus holds information about a client's Kerberos context.
type ClientKerberosStatus struct {
	Initialized         bool   `json:"initialized"`
	Principal           string `json:"principal,omitempty"`
	Realm               string `json:"realm,omitempty"`
	TgtExpiry           string `json:"tgt_expiry,omitempty"` // RFC3339 format or "N/A"
	TgtTimeLeft         string `json:"tgt_time_left,omitempty"`
	EffectiveCcachePath string `json:"effective_ccache_path,omitempty"`
}

// ClientInfo holds basic information about a connected client.
type ClientInfo struct {
	PID uint32 `json:"pid"`
	UID uint32 `json:"uid"`
}

// GetStatusData is sent by the service in response to a get_status command.
type GetStatusData struct {
	Status          string `json:"status"`           // e.g., "running", "degraded"
	ActiveInterface string `json:"active_interface"` // Informational
	ActivePorts     []int  `json:"active_ports"`
	LoadMode        string `json:"load_mode"`     // e.g., "sockops/skmsg"
	MatchedConns    uint64 `json:"matched_conns"` // Total connections matched by BPF sockops
	// Removed MatchedBytes as it wasn't implemented in BPF stats
	UptimeSeconds        int64                           `json:"uptime_seconds"`
	ServiceVersion       string                          `json:"service_version"`
	ConnectedClients     int                             `json:"connected_clients"`
	ClientDetails        []ClientInfo                    `json:"client_details,omitempty"`         // List of connected clients
	ClientKerberosStates map[uint32]ClientKerberosStatus `json:"client_kerberos_states,omitempty"` // Map[UID]KerberosStatus
	// TotalActiveProxyConnections int64 // Requires summing from client pings, maybe add later
}

// GetInterfacesData is sent by the service in response to a get_interfaces command.
type GetInterfacesData struct {
	Interfaces       []string `json:"interfaces"`
	CurrentInterface string   `json:"current_interface"` // Informational
}

// --- Service -> Client Notification Payloads ---

// NotifyAcceptData is sent by the service to notify a client about a connection needing proxying.
type NotifyAcceptData struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"` // Typically syscall.IPPROTO_TCP
}

// --- Helper Functions ---

// NewCommand creates a new Command structure.
func NewCommand(command string, data interface{}) (*Command, error) {
	var rawData json.RawMessage
	var err error
	if data != nil {
		rawData, err = json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal command data for '%s': %w", command, err)
		}
	}
	return &Command{Command: command, Data: rawData}, nil
}

// NewResponse creates a new Response structure.
func NewResponse(status string, data interface{}, errMsg string) (*Response, error) {
	resp := &Response{Status: status, Error: errMsg}
	// Only marshal data if status is OK and data is not nil
	if status == StatusOK && data != nil {
		rawData, err := json.Marshal(data)
		if err != nil {
			// If data marshalling fails for an OK response, make it an error response
			resp.Status = StatusError
			resp.Error = fmt.Sprintf("failed to marshal OK response data: %v", err)
			resp.Data = nil // Ensure data is nil on error
			// Return the error itself as well
			return resp, fmt.Errorf("failed to marshal OK response data: %w", err)
		}
		resp.Data = rawData
	}
	// If status is Error, ensure Data is nil
	if status == StatusError {
		resp.Data = nil
	}
	return resp, nil
}

// NewOKResponse creates a success response.
func NewOKResponse(data interface{}) (*Response, error) {
	return NewResponse(StatusOK, data, "")
}

// NewErrorResponse creates an error response.
func NewErrorResponse(errMsg string) *Response {
	// Error responses should never fail creation internally
	resp, _ := NewResponse(StatusError, nil, errMsg)
	return resp
}

// DecodeData unmarshals the raw data from a Command or Response into a target struct.
func DecodeData(rawData json.RawMessage, target interface{}) error {
	// Allow empty/null data
	if len(rawData) == 0 || string(rawData) == "null" {
		// Ensure the target is settable to its zero value if necessary,
		// although typically the caller handles nil data cases.
		// Consider if target needs explicit zeroing here if rawData is empty.
		return nil // Treat empty/null data as success (no data to decode)
	}
	if target == nil {
		return fmt.Errorf("target interface for decoding cannot be nil")
	}
	if err := json.Unmarshal(rawData, target); err != nil {
		return fmt.Errorf("failed to unmarshal data payload: %w", err)
	}
	return nil
}

// Helper to convert Kerberos status for IPC
func ClientKerberosStatusToIPC(kStatus map[string]interface{}) ClientKerberosStatus {
	ipcStatus := ClientKerberosStatus{}
	if v, ok := kStatus["initialized"].(bool); ok {
		ipcStatus.Initialized = v
	}
	if v, ok := kStatus["principal"].(string); ok {
		ipcStatus.Principal = v
	}
	if v, ok := kStatus["realm"].(string); ok {
		ipcStatus.Realm = v
	}
	if v, ok := kStatus["tgt_expiry"].(string); ok {
		ipcStatus.TgtExpiry = v
	}
	if v, ok := kStatus["tgt_time_left"].(string); ok {
		ipcStatus.TgtTimeLeft = v
	}
	if v, ok := kStatus["effective_ccache_path"].(string); ok {
		ipcStatus.EffectiveCcachePath = v
	}
	return ipcStatus
}
