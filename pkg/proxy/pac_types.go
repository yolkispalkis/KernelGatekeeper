package proxy

import (
	"net/url"
	"reflect" // Needed for deep comparison utility
)

// ResultType indicates whether the PAC result specified DIRECT or a PROXY.
type ResultType int

const (
	// ResultUnknown indicates an error or inability to determine the proxy.
	ResultUnknown ResultType = iota
	// ResultDirect means a direct connection should be used.
	ResultDirect
	// ResultProxy means one or more proxy servers should be used.
	ResultProxy
)

// ProxyInfo holds the scheme and host:port for a single proxy server.
type ProxyInfo struct {
	Scheme string // e.g., "http", "https", "socks" (though only http/https handled currently)
	Host   string // host:port
}

// PacResult represents the parsed outcome of a PAC script execution.
type PacResult struct {
	Type    ResultType
	Proxies []ProxyInfo // List of proxies to try, in order. Only the first is used currently.
}

// URL converts ProxyInfo into a standard url.URL.
// Returns nil if parsing fails.
func (p ProxyInfo) URL() *url.URL {
	// Construct a string that url.Parse can understand
	urlString := p.Scheme + "://" + p.Host
	u, err := url.Parse(urlString)
	if err != nil {
		// Log the error? For now, return nil.
		// slog.Warn("Failed to parse ProxyInfo into URL", "scheme", p.Scheme, "host", p.Host, "error", err)
		return nil
	}
	return u
}

// ReflectDeepEqualPacResult compares two PacResult structs for deep equality.
// Useful for detecting changes in effective proxy settings.
func ReflectDeepEqualPacResult(a, b PacResult) bool {
	if a.Type != b.Type {
		return false
	}
	return reflect.DeepEqual(a.Proxies, b.Proxies)
}
