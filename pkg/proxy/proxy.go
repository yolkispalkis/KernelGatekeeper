// pkg/proxy/proxy.go
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appconfig "github.com/yolki/kernelgatekeeper/pkg/config"
)

type ProxyManager struct {
	config            *appconfig.ProxyConfig
	effectiveProxyURL *url.URL
	proxyURLMutex     sync.RWMutex
	baseTransport     *http.Transport
	wpadCache         struct {
		url       string
		proxyURL  *url.URL
		timestamp time.Time
		mu        sync.RWMutex
	}
	retryConfig struct {
		maxRetries     int
		retryDelay     time.Duration
		connectTimeout time.Duration
	}
	stopChan chan struct{}
	stopOnce sync.Once
}

func NewProxyManager(cfg *appconfig.ProxyConfig) (*ProxyManager, error) {
	slog.Info("Initializing Proxy Manager (Client Side)", "type", cfg.Type, "url", cfg.URL, "wpad_url", cfg.WpadURL)
	connectTimeout := time.Duration(cfg.ConnectionTimeout) * time.Second
	pm := &ProxyManager{
		config:   cfg,
		stopChan: make(chan struct{}),
		retryConfig: struct {
			maxRetries     int
			retryDelay     time.Duration
			connectTimeout time.Duration
		}{
			maxRetries: cfg.MaxRetries, retryDelay: time.Second * 2, connectTimeout: connectTimeout,
		},
		baseTransport: &http.Transport{
			Proxy: nil, DialContext: (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2: true, MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: 1 * time.Second,
		},
	}
	if err := pm.updateProxySettings(); err != nil {
		slog.Error("Initial proxy settings update failed", "error", err)
	}
	if strings.ToLower(pm.config.Type) == "wpad" {
		go pm.wpadRefresher()
	}
	return pm, nil
}

func (pm *ProxyManager) updateProxySettings() error {
	pm.proxyURLMutex.Lock()
	defer pm.proxyURLMutex.Unlock()
	var newProxyURL *url.URL
	var err error
	proxyType := strings.ToLower(pm.config.Type)
	changed := false
	switch proxyType {
	case "http", "https":
		if pm.config.URL == "" {
			err = errors.New("proxy URL is empty")
		} else {
			newProxyURL, err = url.Parse(pm.config.URL)
			if err != nil {
				err = fmt.Errorf("invalid proxy URL '%s': %w", pm.config.URL, err)
			}
		}
	case "wpad":
		if pm.config.WpadURL == "" {
			err = errors.New("WPAD URL is empty")
		} else {
			newProxyURL, err = pm.getProxyFromWPADWithCache(pm.config.WpadURL)
			if err != nil {
				newProxyURL = pm.effectiveProxyURL
				err = nil
			} // Keep old on WPAD error
		}
	case "none":
		newProxyURL = nil
	default:
		err = fmt.Errorf("unsupported proxy type: %s", pm.config.Type)
	}
	if err != nil {
		slog.Error("Failed determine effective proxy URL", "error", err)
		return err
	}
	if (pm.effectiveProxyURL == nil && newProxyURL != nil) || (pm.effectiveProxyURL != nil && newProxyURL == nil) || (pm.effectiveProxyURL != nil && newProxyURL != nil && pm.effectiveProxyURL.String() != newProxyURL.String()) {
		slog.Info("Effective proxy URL changed", "old", urlToString(pm.effectiveProxyURL), "new", urlToString(newProxyURL))
		pm.effectiveProxyURL = newProxyURL
		changed = true
	}
	if changed {
		slog.Debug("Proxy settings updated successfully.")
	} else {
		slog.Debug("Proxy settings remain unchanged.")
	}
	return nil
}

func (pm *ProxyManager) GetEffectiveProxyURL() *url.URL {
	pm.proxyURLMutex.RLock()
	defer pm.proxyURLMutex.RUnlock()
	return pm.effectiveProxyURL
}

func (pm *ProxyManager) wpadRefresher() {
	interval := 55 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("Starting WPAD refresh background task", "interval", interval)
	for {
		select {
		case <-ticker.C:
			slog.Debug("Performing periodic WPAD refresh...")
			if err := pm.updateProxySettings(); err != nil {
				slog.Error("Error during periodic WPAD refresh", "error", err)
			}
		case <-pm.stopChan:
			slog.Info("Stopping WPAD refresh background task.")
			return
		}
	}
}

func (pm *ProxyManager) getProxyFromWPADWithCache(wpadURL string) (*url.URL, error) {
	pm.wpadCache.mu.RLock()
	if pm.wpadCache.url == wpadURL && pm.wpadCache.proxyURL != nil && time.Since(pm.wpadCache.timestamp) < time.Hour {
		cachedURL := pm.wpadCache.proxyURL
		pm.wpadCache.mu.RUnlock()
		slog.Debug("Using cached WPAD result", "proxy", urlToString(cachedURL))
		return cachedURL, nil
	}
	pm.wpadCache.mu.RUnlock()
	slog.Info("Fetching and parsing WPAD file", "url", wpadURL)
	proxyURL, err := pm.fetchAndParsePAC(wpadURL)
	if err != nil {
		return nil, err
	}
	pm.wpadCache.mu.Lock()
	pm.wpadCache.url = wpadURL
	pm.wpadCache.proxyURL = proxyURL
	pm.wpadCache.timestamp = time.Now()
	pm.wpadCache.mu.Unlock()
	slog.Info("WPAD cache updated", "proxy", urlToString(proxyURL))
	return proxyURL, nil
}

func (pm *ProxyManager) fetchAndParsePAC(pacURL string) (*url.URL, error) {
	slog.Warn("Using simplified PAC file parser. Only 'PROXY host:port' and 'HTTPS host:port' directives recognized.")
	ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.connectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", pacURL, nil)
	if err != nil {
		return nil, fmt.Errorf("PAC req create failed: %w", err)
	}
	req.Header.Set("User-Agent", "KernelGatekeeper-Client/1.0 (WPAD Fetch)")
	resp, err := pm.baseTransport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("PAC fetch %s failed: %w", pacURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PAC fetch failed: %s", resp.Status)
	}
	maxPacSize := int64(1 * 1024 * 1024)
	pacContent, err := io.ReadAll(io.LimitReader(resp.Body, maxPacSize))
	if err != nil {
		return nil, fmt.Errorf("PAC read failed: %w", err)
	}
	pacStr := string(pacContent)
	pacStrLower := strings.ToLower(pacStr)
	patterns := []struct{ prefix, scheme string }{{"PROXY ", "http://"}, {"HTTPS ", "https://"}}
	for _, pattern := range patterns {
		idx := strings.Index(pacStrLower, strings.ToLower(pattern.prefix))
		if idx != -1 {
			start := idx + len(pattern.prefix)
			end := len(pacStr)
			terminators := []string{";", "\n", "\r", " ", "\t"}
			for _, term := range terminators {
				if termIdx := strings.Index(pacStr[start:], term); termIdx != -1 {
					if (start + termIdx) < end {
						end = start + termIdx
					}
				}
			}
			proxyHostPort := strings.TrimSpace(pacStr[start:end])
			if proxyHostPort == "" {
				continue
			}
			_, _, err := net.SplitHostPort(proxyHostPort)
			if err != nil {
				slog.Warn("PAC directive invalid host:port", "directive", proxyHostPort, "error", err)
				continue
			}
			proxyURLStr := pattern.scheme + proxyHostPort
			parsedURL, err := url.Parse(proxyURLStr)
			if err != nil {
				slog.Warn("Failed parse PAC proxy string", "string", proxyURLStr, "error", err)
				continue
			}
			if parsedURL.Host == "" {
				slog.Warn("Parsed PAC URL has empty host", "string", proxyURLStr)
				continue
			}
			slog.Info("Found proxy via simple PAC parse", "proxy", parsedURL.String())
			return parsedURL, nil
		}
	}
	if strings.Contains(pacStrLower, "direct") {
		slog.Info("PAC file specifies DIRECT connection.")
		return nil, nil
	}
	return nil, errors.New("no suitable PROXY/HTTPS directive found in PAC (simple parser)")
}

func (pm *ProxyManager) Close() error {
	slog.Info("Closing Proxy Manager (Client Side)...")
	pm.stopOnce.Do(func() { close(pm.stopChan) })
	if pm.baseTransport != nil {
		pm.baseTransport.CloseIdleConnections()
	}
	slog.Info("Proxy Manager closed.")
	return nil
}

func urlToString(u *url.URL) string {
	if u == nil {
		return "<none>"
	}
	return u.String()
}
