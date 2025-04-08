package ipc

import (
	"encoding/json"
	"fmt"
)

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
			resp.Status = StatusError
			resp.Error = fmt.Sprintf("failed to marshal OK response data: %v", err)
			resp.Data = nil
			return resp, fmt.Errorf("failed to marshal OK response data: %w", err)
		}
		resp.Data = rawData
	} else if status == StatusError {
		resp.Data = nil
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
	if target == nil {
		return fmt.Errorf("target interface for decoding cannot be nil")
	}
	if err := json.Unmarshal(rawData, target); err != nil {
		return fmt.Errorf("failed to unmarshal data payload: %w", err)
	}
	return nil
}

func ClientKerberosStatusToIPC(kStatus map[string]interface{}) ClientKerberosStatus {
	ipcStatus := ClientKerberosStatus{
		Initialized: false,
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
