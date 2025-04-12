// FILE: pkg/proxy/manager.go
package proxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	// Import the actual config package
	pkgconfig "github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

// ProxyManager determines the appropriate proxy configuration based on settings.
type ProxyManager struct {
	config             *pkgconfig.ProxyConfig // Use the imported config type
	pacParser          *PacParser
	staticProxyResult  PacResult // Pre-calculated result for static config types
	proxyMutex         sync.RWMutex
	stopChan           chan struct{}
	initializationDone bool
	initializationErr  error
}

// NewProxyManager creates and initializes a new ProxyManager.
func NewProxyManager(cfg *pkgconfig.ProxyConfig) (*ProxyManager, error) { // Use imported config type
	pm := &ProxyManager{
		config:   cfg,
		stopChan: make(chan struct{}),
	}

	slog.Info("Initializing ProxyManager",
		"type", cfg.Type,
		"static_url", cfg.URL,
		"wpad_url", cfg.WpadURL,
		"pac_ttl", cfg.PacFileTTL,
	)

	err := pm.initialize()
	if err != nil {
		slog.Error("ProxyManager initialization failed, proxying may not work", "error", err)
		pm.initializationErr = err
	}
	pm.initializationDone = true

	return pm, nil // Return manager even on initial PAC error
}

// initialize sets up the manager based on the config type.
func (pm *ProxyManager) initialize() error {
	pm.proxyMutex.Lock()
	defer pm.proxyMutex.Unlock()

	proxyType := strings.ToLower(pm.config.Type)

	switch proxyType {
	case "http", "https":
		proxyURL, err := url.Parse(pm.config.URL)
		if err != nil {
			return fmt.Errorf("invalid static proxy URL %s: %w", pm.config.URL, err)
		}
		pm.staticProxyResult = PacResult{
			Type: ResultProxy,
			Proxies: []ProxyInfo{
				{Scheme: proxyURL.Scheme, Host: proxyURL.Host},
			},
		}
		slog.Info("ProxyManager configured for static proxy", "url", pm.config.URL)
		pm.pacParser = nil

	case "wpad":
		pacURL, err := url.Parse(pm.config.WpadURL)
		if err != nil {
			return fmt.Errorf("invalid wpad/pac URL %s: %w", pm.config.WpadURL, err)
		}

		fetchTimeout := time.Duration(pm.config.ConnectionTimeout) * time.Second
		ttl := time.Duration(pm.config.PacFileTTL) * time.Second
		charset := pm.config.PacCharset

		parser, err := NewPacParser(pacURL, fetchTimeout, ttl, charset)
		if err != nil {
			pm.pacParser = parser // Store parser even if initial fetch failed
			return fmt.Errorf("failed to initialize PAC parser: %w", err)
		}
		pm.pacParser = parser
		pm.staticProxyResult = PacResult{Type: ResultUnknown}
		slog.Info("ProxyManager configured for WPAD/PAC", "url", pm.config.WpadURL)

	case "none":
		pm.staticProxyResult = PacResult{Type: ResultDirect}
		pm.pacParser = nil
		slog.Info("ProxyManager configured for DIRECT connections (type=none)")

	default:
		return fmt.Errorf("unknown proxy type: %s", pm.config.Type)
	}

	return nil
}

// GetEffectiveProxyForURL determines the proxy result (DIRECT or specific proxy URL) for a target URL.
func (pm *ProxyManager) GetEffectiveProxyForURL(targetURL *url.URL) (PacResult, error) {
	if !pm.initializationDone {
		return PacResult{Type: ResultUnknown}, errors.New("proxy manager not yet initialized")
	}
	if pm.initializationErr != nil && pm.pacParser == nil && pm.staticProxyResult.Type == ResultUnknown {
		return PacResult{Type: ResultUnknown}, fmt.Errorf("proxy manager initialization failed: %w", pm.initializationErr)
	}

	pm.proxyMutex.RLock() // Use RLock for reading config type and accessing parser/static result
	proxyType := strings.ToLower(pm.config.Type)
	currentPacParser := pm.pacParser            // Read parser under RLock
	currentStaticResult := pm.staticProxyResult // Read static result under RLock
	initErr := pm.initializationErr             // Read init error under RLock
	pm.proxyMutex.RUnlock()

	switch proxyType {
	case "http", "https":
		return currentStaticResult, nil
	case "none":
		return currentStaticResult, nil
	case "wpad":
		if currentPacParser == nil {
			return PacResult{Type: ResultUnknown}, fmt.Errorf("PAC parser unavailable: %w", initErr)
		}
		pacStringResult, err := currentPacParser.FindProxy(targetURL)
		if err != nil {
			slog.Error("PAC script execution failed", "url", targetURL.String(), "error", err)
			return PacResult{Type: ResultUnknown}, fmt.Errorf("PAC execution failed: %w", err)
		}

		parsedResult := ParsePacResultString(pacStringResult)
		if parsedResult.Type == ResultUnknown {
			slog.Warn("PAC script returned unknown or unparseable result", "url", targetURL.String(), "result", pacStringResult)
			return PacResult{Type: ResultUnknown}, fmt.Errorf("unparseable PAC result: %s", pacStringResult)
		}
		slog.Debug("PAC result parsed", "url", targetURL.String(), "pac_string", pacStringResult, "parsed_type", parsedResult.Type)
		return parsedResult, nil

	default:
		return PacResult{Type: ResultUnknown}, fmt.Errorf("internal error: unhandled proxy type %s", proxyType)
	}
}

// Close cleans up resources used by the ProxyManager.
func (pm *ProxyManager) Close() error {
	pm.proxyMutex.Lock()
	defer pm.proxyMutex.Unlock()

	select {
	case <-pm.stopChan:
		// Already closed
	default:
		close(pm.stopChan)
	}

	if pm.pacParser != nil {
		// Perform any PAC parser cleanup if necessary in the future
		pm.pacParser = nil
		slog.Debug("PAC parser resources cleared.")
	}
	slog.Info("ProxyManager closed.")
	return nil
}

// GetStaticProxyURL returns the *first* configured static proxy URL.
// Returns nil if type is not 'http' or 'https'.
func (pm *ProxyManager) GetStaticProxyURL() *url.URL {
	pm.proxyMutex.RLock()
	defer pm.proxyMutex.RUnlock()

	if pm.staticProxyResult.Type == ResultProxy && len(pm.staticProxyResult.Proxies) > 0 {
		return pm.staticProxyResult.Proxies[0].URL()
	}
	return nil
}
