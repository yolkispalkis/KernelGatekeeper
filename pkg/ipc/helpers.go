package ipc

import (
	"encoding/json"
	"fmt"
	"time" // Import time for ClientKerberosStatusToIPC
)

// NewCommand creates a new Command struct with marshaled data.
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

// NewResponse creates a new Response struct with marshaled data.
func NewResponse(status string, data interface{}, errMsg string) (*Response, error) {
	resp := &Response{Status: status, Error: errMsg}
	if status == StatusOK && data != nil {
		rawData, err := json.Marshal(data)
		if err != nil {
			// If marshalling OK data fails, create an error response instead
			resp.Status = StatusError
			resp.Error = fmt.Sprintf("failed to marshal OK response data: %v", err)
			resp.Data = nil // Ensure data is nil on error
			// Return the error response, but also signal the marshalling error
			return resp, fmt.Errorf("failed to marshal OK response data: %w", err)
		}
		resp.Data = rawData
	} else if status == StatusError {
		// Ensure data is nil for error responses, even if passed erroneously
		resp.Data = nil
	}
	return resp, nil // No error if marshalling succeeded or wasn't needed
}

// NewOKResponse creates a success response.
func NewOKResponse(data interface{}) (*Response, error) {
	return NewResponse(StatusOK, data, "")
}

// NewErrorResponse creates a failure response. Error during creation is unlikely.
func NewErrorResponse(errMsg string) *Response {
	resp, _ := NewResponse(StatusError, nil, errMsg) // Ignore error as data is nil
	return resp
}

// DecodeData unmarshals the RawMessage data from a Command or Response into a target struct.
func DecodeData(rawData json.RawMessage, target interface{}) error {
	// Check if data is actually present
	if len(rawData) == 0 || string(rawData) == "null" {
		// Consider if target should be nil or zeroed in this case.
		// For now, just return nil, indicating no data to decode.
		// The caller must handle the case where target remains unchanged/zeroed.
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

// ClientKerberosStatusToIPC converts the map status from the KerberosClient
// into the IPC struct format.
func ClientKerberosStatusToIPC(kStatus map[string]interface{}) ClientKerberosStatus {
	ipcStatus := ClientKerberosStatus{
		Initialized: false, // Default to false
	}

	// Safely extract and type-assert values from the map
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
		// Basic validation could be added here if needed (e.g., check format)
		ipcStatus.TgtExpiry = v
	}
	// Parse TgtTimeLeft only if expiry is valid and in the future
	if expiryStr, okExpiry := kStatus["tgt_expiry"].(string); okExpiry {
		expiryTime, err := time.Parse(time.RFC3339, expiryStr)
		if err == nil && time.Now().Before(expiryTime) {
			// Use the pre-formatted string from the status map if available
			if v, ok := kStatus["tgt_time_left"].(string); ok {
				ipcStatus.TgtTimeLeft = v
			} else {
				// Recalculate if not present (shouldn't happen ideally)
				ipcStatus.TgtTimeLeft = expiryTime.Sub(time.Now()).Round(time.Second).String()
			}
		} else {
			ipcStatus.TgtTimeLeft = "Expired"
			ipcStatus.Initialized = false // Ensure initialized is false if expired
		}
	} else {
		ipcStatus.TgtTimeLeft = "N/A" // Indicate expiry wasn't available/parseable
		ipcStatus.Initialized = false
	}

	if v, ok := kStatus["effective_ccache_path"].(string); ok {
		ipcStatus.EffectiveCcachePath = v
	}

	// Ensure consistency: if not initialized, clear potentially sensitive fields?
	// Or keep them for debugging? For now, keep them.
	// if !ipcStatus.Initialized {
	//     ipcStatus.Principal = ""
	//     ipcStatus.Realm = ""
	//     // etc.
	// }

	return ipcStatus
}
