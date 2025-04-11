// FILE: pkg/ipc/types.go
package ipc

import (
	"encoding/json"
)

type Command struct {
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type Response struct {
	Status string          `json:"status"`
	Error  string          `json:"error,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

const (
	StatusOK    = "ok"
	StatusError = "error"
)

type RegisterClientData struct {
	PID int `json:"pid"`
}

type PingStatusData struct {
	ActiveConnections int64                `json:"active_connections"`
	KerberosStatus    ClientKerberosStatus `json:"kerberos_status"`
}

type ClientKerberosStatus struct {
	Initialized         bool   `json:"initialized"`
	Principal           string `json:"principal,omitempty"`
	Realm               string `json:"realm,omitempty"`
	TgtExpiry           string `json:"tgt_expiry,omitempty"`
	TgtTimeLeft         string `json:"tgt_time_left,omitempty"`
	EffectiveCcachePath string `json:"effective_ccache_path,omitempty"`
}

type ClientInfo struct {
	PID uint32 `json:"pid"`
	UID uint32 `json:"uid"`
}

type GetStatusData struct {
	Status               string                          `json:"status"`
	ActivePorts          []int                           `json:"active_ports"`
	LoadMode             string                          `json:"load_mode"`
	TotalRedirected      uint64                          `json:"total_redirected"`
	TotalGetsockoptOK    uint64                          `json:"total_getsockopt_ok"`
	TotalGetsockoptFail  uint64                          `json:"total_getsockopt_fail"`
	UptimeSeconds        int64                           `json:"uptime_seconds"`
	ServiceVersion       string                          `json:"service_version"`
	ConnectedClients     int                             `json:"connected_clients"`
	ClientDetails        []ClientInfo                    `json:"client_details,omitempty"`
	ClientKerberosStates map[uint32]ClientKerberosStatus `json:"client_kerberos_states,omitempty"`
}
