package common

import "time"

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
