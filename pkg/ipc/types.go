package ipc

import (
	"encoding/json"

	"github.com/yolki/kernelgatekeeper/pkg/config"
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

type UpdatePortsData struct {
	Ports []int `json:"ports"`
}

type PingStatusData struct {
	ActiveConnections int64                `json:"active_connections"`
	KerberosStatus    ClientKerberosStatus `json:"kerberos_status"`
}

type GetConfigData struct {
	Config config.Config `json:"config"`
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
	ActiveInterface      string                          `json:"active_interface"`
	ActivePorts          []int                           `json:"active_ports"`
	LoadMode             string                          `json:"load_mode"`
	MatchedConns         uint64                          `json:"matched_conns"`
	UptimeSeconds        int64                           `json:"uptime_seconds"`
	ServiceVersion       string                          `json:"service_version"`
	ConnectedClients     int                             `json:"connected_clients"`
	ClientDetails        []ClientInfo                    `json:"client_details,omitempty"`
	ClientKerberosStates map[uint32]ClientKerberosStatus `json:"client_kerberos_states,omitempty"`
}

type GetInterfacesData struct {
	Interfaces       []string `json:"interfaces"`
	CurrentInterface string   `json:"current_interface"`
}

type NotifyAcceptData struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
}
