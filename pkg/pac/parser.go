package pac

import (
	"log/slog"
	"net"
	"net/url"
	"strings"
)

// ParseResult parses the raw string output of FindProxyForURL.
// Example input: "PROXY proxy1:8080; HTTPS proxy2:8443; DIRECT"
func ParseResult(resultString string) PacResult {
	resultString = strings.TrimSpace(resultString)
	if resultString == "" {
		slog.Warn("PAC script returned empty result, assuming DIRECT")
		return PacResult{Type: ResultDirect}
	}

	parts := strings.Split(resultString, ";")
	var proxies []ProxyInfo
	hasDirect := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		fields := strings.Fields(part) // Split by space, e.g., ["PROXY", "host:port"]

		if len(fields) == 0 {
			continue
		}

		directive := strings.ToUpper(fields[0])

		switch directive {
		case "DIRECT":
			hasDirect = true

		case "PROXY", "HTTP": // Treat PROXY and HTTP the same
			if len(fields) < 2 {
				slog.Warn("Invalid PAC directive: missing host:port", "directive", part)
				continue
			}
			hostPort := fields[1]
			if _, _, err := net.SplitHostPort(hostPort); err != nil {
				// Maybe allow just hostname and assume port 80? Risky. Require port for now.
				slog.Warn("Invalid PROXY/HTTP format (expected host:port)", "value", hostPort, "error", err)
				continue
			}
			proxies = append(proxies, ProxyInfo{Scheme: "http", Host: hostPort})

		case "HTTPS":
			if len(fields) < 2 {
				slog.Warn("Invalid PAC directive: missing host:port", "directive", part)
				continue
			}
			hostPort := fields[1]
			if _, _, err := net.SplitHostPort(hostPort); err != nil {
				slog.Warn("Invalid HTTPS format (expected host:port)", "value", hostPort, "error", err)
				continue
			}
			proxies = append(proxies, ProxyInfo{Scheme: "https", Host: hostPort})

		case "SOCKS", "SOCKS4", "SOCKS5":
			slog.Warn("SOCKS proxy type found in PAC result, but SOCKS is not supported by KernelGatekeeper. Ignoring.", "directive", part)
			continue // Ignore SOCKS directives

		default:
			slog.Warn("Unknown PAC directive type encountered, ignoring", "directive", part)
		}
	}

	// Determine final result type based on parsed directives
	if len(proxies) > 0 {
		// If PROXY/HTTPS directives were found, return them. Order is preserved.
		// The client logic will typically try them in order.
		// Even if DIRECT was present, proxy preference usually takes precedence.
		return PacResult{Type: ResultProxy, Proxies: proxies}
	} else if hasDirect {
		// If only DIRECT was found (or only invalid/unsupported directives + DIRECT)
		return PacResult{Type: ResultDirect}
	} else {
		// If nothing valid was parsed (e.g., only unsupported SOCKS or garbage)
		slog.Warn("Failed to parse any valid directives from PAC result, treating as error/unknown", "result_string", resultString)
		return PacResult{Type: ResultUnknown} // Indicate error/unknown state
	}
}

// UrlsFromPacResult converts PacResult proxies to []*url.URL for convenience.
func UrlsFromPacResult(pr PacResult) []*url.URL {
	if pr.Type != ResultProxy {
		return nil
	}
	urls := make([]*url.URL, 0, len(pr.Proxies))
	for _, p := range pr.Proxies {
		u, err := p.URL() // Use the helper method
		if err == nil {
			urls = append(urls, u)
		} else {
			slog.Warn("Failed to convert PacResult ProxyInfo to url.URL", "proxy", p, "error", err)
		}
	}
	return urls
}
