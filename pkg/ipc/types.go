package ipc

import (
	"encoding/json"
	"fmt"

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

type GetConfigData struct {
	Config config.Config `json:"config"`
}

type UpdatePortsData struct {
	Ports []int `json:"ports"`
}

type UpdateInterfaceData struct {
	Interface string `json:"interface"`
}

type GetStatusData struct {
	Status          string `json:"status"`
	ActiveInterface string `json:"active_interface"`
	ActivePorts     []int  `json:"active_ports"`
	LoadMode        string `json:"load_mode"`
	TotalPackets    uint64 `json:"total_packets"`
	TotalBytes      uint64 `json:"total_bytes"`
	MatchedConns    uint64 `json:"matched_conns"`
	MatchedBytes    uint64 `json:"matched_bytes"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	ServiceVersion  string `json:"service_version"`
}

type GetInterfacesData struct {
	Interfaces       []string `json:"interfaces"`
	CurrentInterface string   `json:"current_interface"`
}

type RegisterClientData struct {
	PID int `json:"pid"`
}

type NotifyAcceptData struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
}

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

func NewResponse(status string, data interface{}, errMsg string) (*Response, error) {
	resp := &Response{Status: status, Error: errMsg}
	if status == StatusOK && data != nil {
		rawData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response data: %w", err)
		}
		resp.Data = rawData
	}
	return resp, nil
}

func NewOKResponse(data interface{}) (*Response, error) {
	return NewResponse(StatusOK, data, "")
}

func NewErrorResponse(errMsg string) *Response {
	resp, _ := NewResponse(StatusError, nil, errMsg)
	return resp
}

func DecodeData(rawData json.RawMessage, target interface{}) error {
	if len(rawData) == 0 || string(rawData) == "null" {
		return nil
	}
	if err := json.Unmarshal(rawData, target); err != nil {
		return fmt.Errorf("failed to unmarshal data payload: %w", err)
	}
	return nil
}
