package pac

import (
	"log/slog"
	"net"
	"net/url"
	"reflect"
	"strings"
)

const (
	proxyDirect  = "DIRECT"
	proxyHttp    = "PROXY"
	proxyHttps   = "HTTPS"
	proxySocks4  = "SOCKS"
	proxySocks5  = "SOCKS5"
	pacDelimiter = ";"
)

func ParseResult(result string) PacResult {
	if result == "" {
		slog.Debug("PAC result string is empty, returning Unknown")
		return PacResult{Type: ResultUnknown}
	}

	parts := strings.Split(result, pacDelimiter)
	parsed := PacResult{Proxies: make([]ProxyInfo, 0)}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}

		directive := strings.ToUpper(fields[0])

		switch directive {
		case proxyDirect:
			if len(parsed.Proxies) == 0 {
				parsed.Type = ResultDirect
				return parsed
			} else {
				slog.Warn("PAC result contained DIRECT after other proxies, ignoring DIRECT", "result", result)
				continue
			}

		case proxyHttp, proxyHttps:
			if len(fields) < 2 {
				slog.Warn("PAC result missing host:port for PROXY/HTTPS directive", "directive", part)
				continue
			}
			host := strings.TrimSpace(fields[1])
			scheme := "http"
			if directive == proxyHttps {
				scheme = "https"
			}
			if !strings.Contains(host, ":") {
				defaultPort := "80"
				if scheme == "https" {
					defaultPort = "443"
				}
				host = net.JoinHostPort(host, defaultPort)
			}
			parsed.Type = ResultProxy
			parsed.Proxies = append(parsed.Proxies, ProxyInfo{Scheme: scheme, Host: host})

		case proxySocks4, proxySocks5:
			slog.Warn("Ignoring unsupported SOCKS proxy directive in PAC result", "directive", part)
			if parsed.Type == ResultDirect {
				slog.Error("Internal logic error: SOCKS directive found after DIRECT")
			}

		default:
			slog.Warn("Ignoring unknown directive in PAC result", "directive", part)
		}
	}

	if len(parsed.Proxies) > 0 {
		parsed.Type = ResultProxy
	} else if parsed.Type == ResultUnknown {
		slog.Debug("No valid DIRECT or PROXY directives found in PAC result", "result", result)
		parsed.Type = ResultUnknown
	}

	return parsed
}

func UrlsToStrings(urls []*url.URL) []string {
	if urls == nil {
		return nil
	}
	strs := make([]string, len(urls))
	for i, u := range urls {
		if u != nil {
			strs[i] = u.String()
		} else {
			strs[i] = "<nil>"
		}
	}
	return strs
}

func reflectDeepEqualPacResult(a, b PacResult) bool {
	if a.Type != b.Type {
		return false
	}
	if !reflect.DeepEqual(a.Proxies, b.Proxies) {
		return false
	}
	return true
}

func UrlsFromPacResult(result PacResult) []*url.URL {
	if result.Proxies == nil {
		return nil
	}
	urls := make([]*url.URL, 0, len(result.Proxies))
	for _, pInfo := range result.Proxies {
		if u, err := pInfo.URL(); err == nil {
			urls = append(urls, u)
		}
	}
	return urls
}
