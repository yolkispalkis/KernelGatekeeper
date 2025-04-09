package proxy

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

const (
	proxyDirect      = "DIRECT"
	proxyHttp        = "PROXY"  // Standard HTTP Proxy
	proxyHttps       = "HTTPS"  // HTTP Proxy over TLS (rarely used for proxy connection itself, often means target is HTTPS)
	proxySocks4      = "SOCKS"  // SOCKS v4
	proxySocks5      = "SOCKS5" // SOCKS v5
	pacResultSplit   = ";"
	defaultProxyPort = 8080 // Default port if not specified (common but not standard)
	defaultHttpsPort = 443  // Default port for HTTPS scheme if not specified
)

// Regex to capture the first PAC entry type and its host:port argument.
// Example: "PROXY proxy.example.com:8080; DIRECT" -> matches "PROXY proxy.example.com:8080"
// Example: "DIRECT" -> matches "DIRECT"
// Example: "HTTPS secure.proxy:443" -> matches "HTTPS secure.proxy:443"
var pacEntryRegex = regexp.MustCompile(`^\s*([A-Z0-9]+)(?:\s+([^;]+))?`)

// ParsePacResultString converts the raw string output from a PAC script
// into a structured PacResult. It only considers the *first* valid entry.
func ParsePacResultString(result string) PacResult {
	// Trim whitespace
	result = strings.TrimSpace(result)
	if result == "" {
		return PacResult{Type: ResultUnknown}
	}

	// Split potential multiple results (e.g., "PROXY proxy1:8080; PROXY proxy2:8080; DIRECT")
	parts := strings.Split(result, pacResultSplit)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		matches := pacEntryRegex.FindStringSubmatch(part)
		// Expected matches:
		// [0]: Full match (e.g., "PROXY proxy.example.com:8080")
		// [1]: Type (e.g., "PROXY")
		// [2]: Argument (e.g., "proxy.example.com:8080") - Optional

		if len(matches) < 2 {
			// Invalid format for this part, try next
			continue
		}

		proxyType := strings.ToUpper(matches[1])
		proxyArg := ""
		if len(matches) > 2 {
			proxyArg = strings.TrimSpace(matches[2])
		}

		switch proxyType {
		case proxyDirect:
			// Found DIRECT, return immediately (highest precedence if first)
			return PacResult{Type: ResultDirect}

		case proxyHttp: // "PROXY host:port"
			if proxyArg == "" {
				continue // Invalid PROXY entry without host:port
			}
			// url.Parse needs a scheme, add http:// temporarily for parsing host/port
			tempURL, err := url.Parse("http://" + proxyArg)
			if err != nil || tempURL.Host == "" {
				continue // Invalid host:port format
			}
			return PacResult{
				Type: ResultProxy,
				Proxies: []ProxyInfo{
					{Scheme: "http", Host: tempURL.Host}, // Use Host which includes port if present
				},
			}

		case proxyHttps: // "HTTPS host:port"
			// Note: This usually specifies a proxy that *itself* is connected to via HTTPS,
			// OR it might just be an alias for PROXY when the *target* is HTTPS.
			// We'll treat it as an HTTP proxy specified by host:port for the CONNECT tunnel.
			// Establishing the tunnel *to* the proxy over TLS is not supported here.
			if proxyArg == "" {
				continue // Invalid HTTPS entry without host:port
			}
			tempURL, err := url.Parse("https://" + proxyArg) // Use https:// to potentially get default port 443
			if err != nil || tempURL.Host == "" {
				continue // Invalid host:port format
			}
			host := tempURL.Hostname()
			port := tempURL.Port()
			if port == "" {
				port = "443" // Default port for HTTPS scheme
			}
			return PacResult{
				Type: ResultProxy,
				Proxies: []ProxyInfo{
					{Scheme: "http", Host: net.JoinHostPort(host, port)}, // Connect using HTTP CONNECT
				},
			}

		case proxySocks4, proxySocks5:
			// SOCKS proxying is not implemented in the tunnel logic.
			// Treat as unhandled for now, maybe fall through or log warning.
			// Depending on requirements, could return ResultUnknown or try next part.
			continue // Try next part of the PAC string

		default:
			// Unknown type, ignore and try next part
			continue
		}
	}

	// If loop finishes without finding a valid, recognized directive
	return PacResult{Type: ResultUnknown}
}
