package ipc

import (
	"encoding/json"
	// Config is no longer needed here as it's not sent over IPC
	// "github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

// Command represents a command sent over IPC (Client -> Service or Service -> Client)
type Command struct {
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data,omitempty"` // Use RawMessage to delay parsing
}

// Response represents a response sent over IPC (usually Service -> Client)
type Response struct {
	Status string          `json:"status"`          // "ok" or "error"
	Error  string          `json:"error,omitempty"` // Error message if status is "error"
	Data   json.RawMessage `json:"data,omitempty"`  // Response data if status is "ok"
}

// IPC Status constants
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// --- Data Structures for Specific Commands/Responses ---

// RegisterClientData (Client -> Service)
type RegisterClientData struct {
	PID int `json:"pid"` // PID reported by the client process itself
}

// Removed UpdatePortsData

// PingStatusData (Client -> Service)
type PingStatusData struct {
	ActiveConnections int64                `json:"active_connections"`
	KerberosStatus    ClientKerberosStatus `json:"kerberos_status"` // Status reported by the client
}

// Removed GetConfigData

// ClientKerberosStatus (Used within PingStatusData and GetStatusData)
// This structure defines how the client reports its Kerberos status.
type ClientKerberosStatus struct {
	Initialized         bool   `json:"initialized"`
	Principal           string `json:"principal,omitempty"`
	Realm               string `json:"realm,omitempty"`
	TgtExpiry           string `json:"tgt_expiry,omitempty"`            // Formatted time string
	TgtTimeLeft         string `json:"tgt_time_left,omitempty"`         // Formatted duration string
	EffectiveCcachePath string `json:"effective_ccache_path,omitempty"` // Path the client is actually using
}

// ClientInfo (Used within GetStatusData)
// Basic info about a connected client process.
type ClientInfo struct {
	PID uint32 `json:"pid"` // PID obtained via SO_PEERCRED
	UID uint32 `json:"uid"` // UID obtained via SO_PEERCRED
}

// GetStatusData (Service -> Client) Response for "get_status"
type GetStatusData struct {
	Status               string                          `json:"status"`           // e.g., "running", "degraded", "warning"
	ActiveInterface      string                          `json:"active_interface"` // Informational from config
	ActivePorts          []int                           `json:"active_ports"`     // Ports currently configured in BPF map
	LoadMode             string                          `json:"load_mode"`        // e.g., "sockops"
	MatchedConns         uint64                          `json:"matched_conns"`    // Total connections redirected by BPF
	UptimeSeconds        int64                           `json:"uptime_seconds"`
	ServiceVersion       string                          `json:"service_version"`
	ConnectedClients     int                             `json:"connected_clients"`
	ClientDetails        []ClientInfo                    `json:"client_details,omitempty"`         // List of connected clients
	ClientKerberosStates map[uint32]ClientKerberosStatus `json:"client_kerberos_states,omitempty"` // Map UID -> KerberosStatus reported by clients
}

// GetInterfacesData (Service -> Client) Response for "get_interfaces"
type GetInterfacesData struct {
	Interfaces       []string `json:"interfaces"`        // List of potentially usable interfaces found on the system
	CurrentInterface string   `json:"current_interface"` // Interface currently specified in the service config
}

// NotifyAcceptData (Service -> Client) Notification for BPF connection
type NotifyAcceptData struct {
	SrcIP    string `json:"src_ip"`   // Original source IP (from sock_ops)
	DstIP    string `json:"dst_ip"`   // Original destination IP (from connect4 map)
	SrcPort  uint16 `json:"src_port"` // Original source port (from sock_ops, host byte order?) -> needs check/conversion
	DstPort  uint16 `json:"dst_port"` // Original destination port (from connect4 map, network byte order?) -> needs check/conversion
	Protocol uint8  `json:"protocol"` // e.g., syscall.IPPROTO_TCP
}
