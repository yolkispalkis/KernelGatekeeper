package ipc

import (
	"encoding/json"
	"fmt"

	// Import time for ClientKerberosStatus formatting example
	"github.com/yolki/kernelgatekeeper/pkg/config"
	// Import kerb package if ClientKerberosStatusToIPC needs its types
	// "github.com/yolki/kernelgatekeeper/pkg/kerb"
)

// Command represents a command sent over the IPC channel between client and service.
type Command struct {
	Command string          `json:"command"`        // Name of the command (e.g., "register_client", "get_config")
	Data    json.RawMessage `json:"data,omitempty"` // Payload data specific to the command
}

// Response represents a response sent over the IPC channel.
type Response struct {
	Status string          `json:"status"`          // Status of the operation ("ok" or "error")
	Error  string          `json:"error,omitempty"` // Error message if status is "error"
	Data   json.RawMessage `json:"data,omitempty"`  // Payload data specific to the response (if status is "ok")
}

// Constants for response status field.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// --- Command Data Payloads ---

// RegisterClientData is sent by the client to register with the service.
type RegisterClientData struct {
	PID int `json:"pid"` // PID of the client process (used for logging/correlation by service)
}

// UpdatePortsData is sent by the client to update the BPF target ports (if allowed).
type UpdatePortsData struct {
	Ports []int `json:"ports"` // List of target ports BPF should intercept
}

// PingStatusData is sent periodically by the client to the service to report its status.
type PingStatusData struct {
	ActiveConnections int64                `json:"active_connections"` // Number of currently proxied connections handled by this client
	KerberosStatus    ClientKerberosStatus `json:"kerberos_status"`    // Status of the client's Kerberos ticket cache
}

// --- Response Data Payloads ---

// GetConfigData is sent by the service in response to a get_config command.
type GetConfigData struct {
	Config config.Config `json:"config"` // The current service configuration relevant to the client
}

// ClientKerberosStatus holds information about a client's Kerberos context for status reporting.
type ClientKerberosStatus struct {
	Initialized         bool   `json:"initialized"`                     // Whether the client's Kerberos context is initialized
	Principal           string `json:"principal,omitempty"`             // Client's Kerberos principal (e.g., user@REALM)
	Realm               string `json:"realm,omitempty"`                 // Client's Kerberos realm
	TgtExpiry           string `json:"tgt_expiry,omitempty"`            // Expiry time of the TGT (RFC3339 format or "N/A")
	TgtTimeLeft         string `json:"tgt_time_left,omitempty"`         // Human-readable time left until TGT expiry (e.g., "1h2m3s")
	EffectiveCcachePath string `json:"effective_ccache_path,omitempty"` // Path to the credential cache being used
}

// ClientInfo holds basic information about a connected client, reported by the service.
type ClientInfo struct {
	PID uint32 `json:"pid"` // Process ID of the connected client
	UID uint32 `json:"uid"` // User ID of the connected client (obtained via socket credentials)
}

// GetStatusData is sent by the service in response to a get_status command.
type GetStatusData struct {
	Status               string                          `json:"status"`                           // Overall service status (e.g., "running", "degraded")
	ActiveInterface      string                          `json:"active_interface"`                 // Informational: Interface hint from config (sockops uses cgroup)
	ActivePorts          []int                           `json:"active_ports"`                     // Current list of ports targeted by BPF
	LoadMode             string                          `json:"load_mode"`                        // BPF load mode from config (e.g., "sockops")
	MatchedConns         uint64                          `json:"matched_conns"`                    // Total connections matched by BPF sockops since service start
	UptimeSeconds        int64                           `json:"uptime_seconds"`                   // Service uptime in seconds
	ServiceVersion       string                          `json:"service_version"`                  // Version of the running service
	ConnectedClients     int                             `json:"connected_clients"`                // Number of currently registered clients
	ClientDetails        []ClientInfo                    `json:"client_details,omitempty"`         // List of connected clients (PID, UID)
	ClientKerberosStates map[uint32]ClientKerberosStatus `json:"client_kerberos_states,omitempty"` // Map[UID]KerberosStatus reported by clients via ping_status
}

// GetInterfacesData is sent by the service in response to a get_interfaces command.
type GetInterfacesData struct {
	Interfaces       []string `json:"interfaces"`        // List of potentially usable network interface names
	CurrentInterface string   `json:"current_interface"` // Informational: Interface hint from config
}

// --- Service -> Client Notification Payloads ---

// NotifyAcceptData is sent by the service to notify a client about a connection needing proxying.
// Note: DstIP and DstPort here refer to the *original* destination the application tried to connect to,
// captured by the connect4 BPF hook.
type NotifyAcceptData struct {
	SrcIP    string `json:"src_ip"`   // Source IP of the original connection
	DstIP    string `json:"dst_ip"`   // ORIGINAL Destination IP that the application intended to reach
	SrcPort  uint16 `json:"src_port"` // Source Port of the original connection
	DstPort  uint16 `json:"dst_port"` // ORIGINAL Destination Port that the application intended to reach
	Protocol uint8  `json:"protocol"` // IP Protocol (e.g., syscall.IPPROTO_TCP)
}

// --- Helper Functions ---

// NewCommand creates a new Command structure, marshalling the data payload.
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

// NewResponse creates a new Response structure, marshalling data only on success.
func NewResponse(status string, data interface{}, errMsg string) (*Response, error) {
	resp := &Response{Status: status, Error: errMsg}
	if status == StatusOK && data != nil {
		rawData, err := json.Marshal(data)
		if err != nil {
			// If data marshalling fails for an OK response, make it an error response instead.
			resp.Status = StatusError
			resp.Error = fmt.Sprintf("failed to marshal OK response data: %v", err)
			resp.Data = nil                                                        // Ensure data is nil on error
			return resp, fmt.Errorf("failed to marshal OK response data: %w", err) // Return the error too
		}
		resp.Data = rawData
	} else if status == StatusError {
		resp.Data = nil // Ensure data is nil for error responses
	}
	return resp, nil // Return nil error on success or if it's an intended error response
}

// NewOKResponse creates a success response with optional data payload.
func NewOKResponse(data interface{}) (*Response, error) {
	return NewResponse(StatusOK, data, "")
}

// NewErrorResponse creates an error response with a message.
func NewErrorResponse(errMsg string) *Response {
	// Error responses themselves don't fail creation internally.
	resp, _ := NewResponse(StatusError, nil, errMsg)
	return resp
}

// DecodeData unmarshals the raw data from a Command or Response into a target struct pointer.
func DecodeData(rawData json.RawMessage, target interface{}) error {
	// Allow empty/null data gracefully.
	if len(rawData) == 0 || string(rawData) == "null" {
		// If target is expecting data, it will remain in its zero state.
		// Caller should handle cases where data might be expected but is nil.
		return nil // Treat empty/null data as success (no data to decode)
	}
	// Ensure target is a non-nil pointer.
	if target == nil {
		return fmt.Errorf("target interface for decoding cannot be nil")
	}
	// Unmarshal the JSON data into the provided target struct.
	if err := json.Unmarshal(rawData, target); err != nil {
		return fmt.Errorf("failed to unmarshal data payload: %w", err)
	}
	return nil
}

// ClientKerberosStatusToIPC converts the map status from pkg/kerb to the IPC struct.
// This assumes the keys in the map match the field names expected here.
// Note: This function might ideally live closer to the kerb package or be handled
// by a method on the KerberosClient if direct struct access isn't feasible.
func ClientKerberosStatusToIPC(kStatus map[string]interface{}) ClientKerberosStatus {
	ipcStatus := ClientKerberosStatus{
		Initialized: false, // Default to false
	}
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
		// Optionally parse and reformat expiry time here if needed
		ipcStatus.TgtExpiry = v
	}
	if v, ok := kStatus["tgt_time_left"].(string); ok {
		ipcStatus.TgtTimeLeft = v
	}
	if v, ok := kStatus["effective_ccache_path"].(string); ok {
		ipcStatus.EffectiveCcachePath = v
	}
	// Add handling for other fields if they exist in the kStatus map

	// Example of calculating time left if expiry is a time.Time object
	// (This depends on how GetStatus in kerb package returns the expiry)
	/*
		if expiryTime, ok := kStatus["tgt_expiry_time"].(time.Time); ok && !expiryTime.IsZero() {
			ipcStatus.TgtExpiry = expiryTime.Format(time.RFC3339) // Ensure consistent format
			timeLeft := time.Until(expiryTime)
			if timeLeft > 0 {
				ipcStatus.TgtTimeLeft = timeLeft.Round(time.Second).String()
			} else {
				ipcStatus.TgtTimeLeft = "Expired"
			}
		}
	*/

	return ipcStatus
}
