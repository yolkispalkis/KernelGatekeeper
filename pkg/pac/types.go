package pac

import (
	"net/url"
	"time"
)

// ResultType indicates the outcome of PAC evaluation for a URL.
type ResultType int

const (
	ResultUnknown ResultType = iota // Error or undetermined
	ResultDirect                    // "DIRECT"
	ResultProxy                     // One or more proxies specified
)

// ProxyInfo describes a single proxy server returned by PAC.
type ProxyInfo struct {
	Scheme string // "http", "https" (SOCKS not currently supported by kernelgatekeeper client)
	Host   string // "hostname:port"
}

// PacResult represents the fully parsed outcome of FindProxyForURL.
type PacResult struct {
	Type    ResultType
	Proxies []ProxyInfo // Ordered list if Type is ResultProxy. Empty for ResultDirect.
}

// dnsCacheEntry stores a resolved IP and its expiry time.
type dnsCacheEntry struct {
	ip     string // Store as string for simplicity with PAC
	expiry time.Time
}

// Helper to convert internal ProxyInfo to net/url.URL (best effort)
func (p ProxyInfo) URL() (*url.URL, error) {
	// Ensure host contains port. If not, assign default? For now, assume valid.
	return url.Parse(p.Scheme + "://" + p.Host)
}
