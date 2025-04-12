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
	// Config import removed
	// Removed pkg/pac import
)

// Define ProxyConfig locally if it's only needed here
type ProxyConfig struct {
	Type                string `mapstructure:"type"`
	URL                 string `mapstructure:"url"`
	WpadURL             string `mapstructure:"wpadUrl"`
	ConnectionTimeout   int    `mapstructure:"connectionTimeout"`
	RequestTimeout      int    `mapstructure:"requestTimeout"`
	MaxRetries          int    `mapstructure:"maxRetries"`
	PacCharset          string `mapstructure:"pacCharset"`
	PacExecutionTimeout int    `mapstructure:"pacExecutionTimeout"`
	PacFileTTL          int    `mapstructure:"pacFileTtl"`
}

// ProxyManager determines the appropriate proxy configuration based on settings.
type ProxyManager struct {
	config             *ProxyConfig // Use local struct
	pacParser          *PacParser   // Replaced pacEngine with gopac based parser
	staticProxyResult  PacResult    // Pre-calculated result for static config types
	proxyMutex         sync.RWMutex
	stopChan           chan struct{} // For potential background tasks (none currently)
	initializationDone bool
	initializationErr  error
}

// NewProxyManager creates and initializes a new ProxyManager.
func NewProxyManager(cfg *ProxyConfig) (*ProxyManager, error) { // Use local struct
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
		// Even if init fails (e.g., wpad unavailable), return the manager.
		// GetEffectiveProxyForURL will handle the error state.
		slog.Error("ProxyManager initialization failed, proxying may not work", "error", err)
		pm.initializationErr = err // Store error
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
		// Static proxy configuration
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
		pm.pacParser = nil // Ensure no PAC parser is active

	case "wpad":
		// WPAD/PAC configuration
		pacURL, err := url.Parse(pm.config.WpadURL)
		if err != nil {
			return fmt.Errorf("invalid wpad/pac URL %s: %w", pm.config.WpadURL, err)
		}

		fetchTimeout := time.Duration(pm.config.ConnectionTimeout) * time.Second // Use connection timeout for fetching
		ttl := time.Duration(pm.config.PacFileTTL) * time.Second
		charset := pm.config.PacCharset

		parser, err := NewPacParser(pacURL, fetchTimeout, ttl, charset)
		if err != nil {
			// Error during initial fetch/parse is logged by NewPacParser
			pm.pacParser = parser // Store parser even if initial fetch failed
			return fmt.Errorf("failed to initialize PAC parser: %w", err)
		}
		pm.pacParser = parser
		pm.staticProxyResult = PacResult{Type: ResultUnknown} // Not static
		slog.Info("ProxyManager configured for WPAD/PAC", "url", pm.config.WpadURL)

	case "none":
		// Explicitly no proxy
		pm.staticProxyResult = PacResult{Type: ResultDirect}
		pm.pacParser = nil
		slog.Info("ProxyManager configured for DIRECT connections (type=none)")

	default:
		// Should be caught by config validation, but handle defensively
		return fmt.Errorf("unknown proxy type: %s", pm.config.Type)
	}

	return nil
}

// GetEffectiveProxyForURL determines the proxy result (DIRECT or specific proxy URL) for a target URL.
func (pm *ProxyManager) GetEffectiveProxyForURL(targetURL *url.URL) (PacResult, error) {
	if !pm.initializationDone {
		// Should not happen in normal flow, but prevents panic if accessed too early
		return PacResult{Type: ResultUnknown}, errors.New("proxy manager not yet initialized")
	}
	if pm.initializationErr != nil && pm.pacParser == nil && pm.staticProxyResult.Type == ResultUnknown {
		// If initialization failed completely (no static, no PAC parser)
		return PacResult{Type: ResultUnknown}, fmt.Errorf("proxy manager initialization failed: %w", pm.initializationErr)
	}

	pm.proxyMutex.RLock()
	defer pm.proxyMutex.RUnlock()

	proxyType := strings.ToLower(pm.config.Type)

	switch proxyType {
	case "http", "https":
		// Return pre-calculated static result
		return pm.staticProxyResult, nil
	case "none":
		// Return pre-calculated direct result
		return pm.staticProxyResult, nil
	case "wpad":
		if pm.pacParser == nil {
			// Initialization must have failed to create parser
			return PacResult{Type: ResultUnknown}, fmt.Errorf("PAC parser unavailable: %w", pm.initializationErr)
		}
		// Execute PAC script via the parser
		pacStringResult, err := pm.pacParser.FindProxy(targetURL)
		if err != nil {
			slog.Error("PAC script execution failed", "url", targetURL.String(), "error", err)
			// Fallback: could return DIRECT, or error. Let's return error.
			return PacResult{Type: ResultUnknown}, fmt.Errorf("PAC execution failed: %w", err)
		}

		// Parse the string result (e.g., "PROXY proxy:8080; DIRECT")
		parsedResult := ParsePacResultString(pacStringResult)
		if parsedResult.Type == ResultUnknown {
			slog.Warn("PAC script returned unknown or unparseable result", "url", targetURL.String(), "result", pacStringResult)
			// Fallback decision: error or DIRECT? Let's return error.
			return PacResult{Type: ResultUnknown}, fmt.Errorf("unparseable PAC result: %s", pacStringResult)
		}
		slog.Debug("PAC result parsed", "url", targetURL.String(), "pac_string", pacStringResult, "parsed_type", parsedResult.Type)
		return parsedResult, nil

	default:
		// Should not be reached
		return PacResult{Type: ResultUnknown}, fmt.Errorf("internal error: unhandled proxy type %s", proxyType)
	}
}

// Close cleans up resources used by the ProxyManager.
func (pm *ProxyManager) Close() error {
	pm.proxyMutex.Lock()
	defer pm.proxyMutex.Unlock()

	close(pm.stopChan) // Signal any potential background tasks (none currently)

	// Clean up PAC parser resources if it exists
	if pm.pacParser != nil {
		// gopac parser itself doesn't have an explicit Close().
		// The http client might need closing if we add idle conn closing,
		// but the client used here is simple.
		// Clear references to help GC.
		pm.pacParser = nil
		slog.Debug("PAC parser resources cleared.")
	}
	slog.Info("ProxyManager closed.")
	return nil
}

// GetStaticProxyURL returns the *first* configured static proxy URL.
// Returns nil if type is not 'http' or 'https'.
// DEPRECATED: Use GetEffectiveProxyForURL instead. Kept for potential compatibility/specific use cases.
func (pm *ProxyManager) GetStaticProxyURL() *url.URL {
	pm.proxyMutex.RLock()
	defer pm.proxyMutex.RUnlock()

	if pm.staticProxyResult.Type == ResultProxy && len(pm.staticProxyResult.Proxies) > 0 {
		return pm.staticProxyResult.Proxies[0].URL()
	}
	return nil
}
