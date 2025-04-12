// FILE: pkg/common/utils.go
package common

import "time"

// Moved from config/config.go
const (
	DefaultSocketPath         = "/var/run/kernelgatekeeper.sock"
	DefaultClientListenerPort = 3129
	LocalListenAddr           = "127.0.0.1"
)

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MinDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
