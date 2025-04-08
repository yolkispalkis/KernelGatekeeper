package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"

	appconfig "github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/pac"
)

const (
	wpadCacheDuration = 1 * time.Hour
	pacMaxSizeBytes   = 1 * 1024 * 1024
)

type ProxyManager struct {
	config           *appconfig.ProxyConfig
	effectiveProxy   pac.PacResult // Stores the default/static proxy or result of initial PAC eval
	wpadPacScript    string        // Cached PAC script content
	proxyMutex       sync.RWMutex
	pacEngine        *pac.Engine
	httpClientForPAC *http.Client
	wpadCacheExpiry  time.Time
	stopChan         chan struct{}
	stopOnce         sync.Once
	wg               sync.WaitGroup
	retryConfig      retrySettings
}

type retrySettings struct {
	// maxRetries is not directly used here anymore but kept for potential future use
	// maxRetries     int
	retryDelay     time.Duration
	connectTimeout time.Duration
	pacExecTimeout time.Duration
}

func NewProxyManager(cfg *appconfig.ProxyConfig) (*ProxyManager, error) {
	if cfg == nil {
		return nil, errors.New("proxy config cannot be nil")
	}
	slog.Info("Initializing Proxy Manager (Client Side)",
		"type", cfg.Type,
		"url", cfg.URL, // Informational only if type is wpad
		"wpad_url", cfg.WpadURL, // Informational only if type is not wpad
	)

	connectTimeout := time.Duration(cfg.ConnectionTimeout) * time.Second
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
		slog.Warn("Invalid proxy.connectionTimeout, using default", "default", connectTimeout)
	}
	pacExecTimeout := time.Duration(cfg.PacExecutionTimeout) * time.Second
	if pacExecTimeout <= 0 {
		pacExecTimeout = 5 * time.Second
		slog.Warn("Invalid proxy.pacExecutionTimeout, using default", "default", pacExecTimeout)
	}

	// HTTP client specifically for fetching PAC files (should not use any system proxy)
	pacTransport := &http.Transport{
		Proxy: nil, // Explicitly disable proxying for PAC fetches
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          5,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	engine, err := pac.NewEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PAC engine: %w", err)
	}

	pm := &ProxyManager{
		config:   cfg,
		stopChan: make(chan struct{}),
		retryConfig: retrySettings{
			// maxRetries:     cfg.MaxRetries, // Store if needed later
			retryDelay:     time.Second * 2, // Fixed retry delay for now
			connectTimeout: connectTimeout,
			pacExecTimeout: pacExecTimeout,
		},
		pacEngine: engine,
		httpClientForPAC: &http.Client{
			Transport: pacTransport,
			Timeout:   connectTimeout, // Use connect timeout for overall PAC fetch
		},
		// Initialize effectiveProxy to Unknown until updateProxySettings runs
		effectiveProxy: pac.PacResult{Type: pac.ResultUnknown},
	}

	// Perform initial setup based on config type
	if err := pm.updateProxySettings(true); err != nil {
		slog.Error("Initial proxy settings update failed, proxy functionality may be impaired", "error", err)
		// Continue running, GetEffectiveProxyForURL will return Unknown/Error
	}

	// Start refresher only if type is WPAD
	if strings.ToLower(pm.config.Type) == "wpad" {
		pm.wg.Add(1)
		go pm.wpadRefresher()
	}

	return pm, nil
}

// updateProxySettings determines the effective default proxy or fetches/updates the PAC script.
// Called during initialization and by the WPAD refresher.
func (pm *ProxyManager) updateProxySettings(initial bool) error {
	pm.proxyMutex.Lock()
	defer pm.proxyMutex.Unlock()

	var newEffectiveResult pac.PacResult
	var fetchedScriptContent string
	var currentErr error
	proxyType := strings.ToLower(pm.config.Type)

	slog.Debug("Updating proxy settings", "type", proxyType, "initial_run", initial)

	switch proxyType {
	case "http", "https":
		if pm.config.URL == "" {
			currentErr = errors.New("proxy URL is empty for http/https type")
			newEffectiveResult = pac.PacResult{Type: pac.ResultUnknown}
		} else {
			// Use ParseResult helper which handles defaults and validation
			parsedResult := pac.ParseResult(fmt.Sprintf("%s %s", strings.ToUpper(proxyType), pm.config.URL))
			if parsedResult.Type != pac.ResultProxy {
				currentErr = fmt.Errorf("failed to parse static proxy URL '%s'", pm.config.URL)
				newEffectiveResult = pac.PacResult{Type: pac.ResultUnknown}
			} else {
				newEffectiveResult = parsedResult
			}
		}

	case "wpad":
		if pm.config.WpadURL == "" {
			currentErr = errors.New("WPAD URL is empty for wpad type")
			newEffectiveResult = pac.PacResult{Type: pac.ResultUnknown} // Error state
			pm.wpadPacScript = ""                                       // Clear script on error
		} else {
			needsFetch := initial || time.Now().After(pm.wpadCacheExpiry) || pm.wpadPacScript == ""

			if needsFetch {
				slog.Info("Fetching/Refreshing WPAD PAC script", "url", pm.config.WpadURL)
				scriptContent, fetchErr := pm.fetchPACScript(pm.config.WpadURL)
				if fetchErr != nil {
					currentErr = fmt.Errorf("failed to fetch PAC script from %s: %w", pm.config.WpadURL, fetchErr)
					slog.Warn("Failed to fetch new PAC script, using previously cached script (if any)", "error", currentErr)
					fetchedScriptContent = pm.wpadPacScript // Use old script if fetch fails
					// Do not update expiry if fetch failed
				} else {
					fetchedScriptContent = scriptContent
					// Only update cache if content changed or was empty before
					if fetchedScriptContent != pm.wpadPacScript || pm.wpadPacScript == "" {
						slog.Info("Fetched new/updated PAC script content.", "size", len(fetchedScriptContent))
						pm.wpadPacScript = fetchedScriptContent
					} else {
						slog.Debug("Fetched PAC script content is unchanged.")
					}
					pm.wpadCacheExpiry = time.Now().Add(wpadCacheDuration) // Update expiry even if unchanged
					slog.Debug("WPAD PAC script cache expiry updated", "expiry", pm.wpadCacheExpiry.Format(time.RFC3339))
				}
			} else {
				slog.Debug("Using cached WPAD PAC script content.", "expiry", pm.wpadCacheExpiry.Format(time.RFC3339))
				fetchedScriptContent = pm.wpadPacScript // Use cached script
			}

			// Determine the effective "default" proxy by evaluating for a dummy URL
			// This isn't strictly necessary but helps log the default behavior.
			// GetEffectiveProxyForURL will always evaluate the script for WPAD.
			if fetchedScriptContent == "" {
				slog.Warn("WPAD PAC script content is empty, cannot determine effective proxy setting, using Unknown")
				newEffectiveResult = pac.PacResult{Type: pac.ResultUnknown} // If no script, it's an error/unknown state
				if currentErr == nil {                                      // Keep fetch error if it happened
					currentErr = errors.New("WPAD PAC script is empty after fetch/cache attempt")
				}
			} else {
				// For WPAD, the effectiveProxy just holds the last known default result,
				// it's not used directly for routing decisions.
				// We just log the evaluation for a dummy URL here.
				dummyURL := "http://wpad.dummy.local/check"
				dummyHost := "wpad.dummy.local"
				ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout)
				resultString, execErr := pm.pacEngine.FindProxyForURL(ctx, fetchedScriptContent, dummyURL, dummyHost)
				cancel()
				if execErr != nil {
					// Log error but don't change effectiveProxy type based on dummy eval failure
					slog.Warn("Failed to evaluate PAC script for dummy URL", "error", execErr)
					newEffectiveResult = pm.effectiveProxy // Keep previous default
				} else {
					newEffectiveResult = pac.ParseResult(resultString)
					slog.Debug("Dummy PAC evaluation result", "result_string", resultString, "parsed_type", newEffectiveResult.Type)
				}
			}
		}

	case "none":
		newEffectiveResult = pac.PacResult{Type: pac.ResultDirect}
		pm.wpadPacScript = "" // Ensure script cache is clear

	default:
		currentErr = fmt.Errorf("unsupported proxy type: %s", pm.config.Type)
		newEffectiveResult = pac.PacResult{Type: pac.ResultUnknown}
		pm.wpadPacScript = ""
	}

	// Log and update effectiveProxy state
	if currentErr != nil {
		slog.Error("Error determining effective proxy setting", "type", proxyType, "error", currentErr)
		// If an error occurred, force state to Unknown, unless it was already Unknown
		if pm.effectiveProxy.Type != pac.ResultUnknown {
			slog.Warn("Updating effective proxy state to Unknown due to error")
			pm.effectiveProxy = pac.PacResult{Type: pac.ResultUnknown}
		}
		// Keep returning the error that occurred
		return currentErr
	}

	// Compare and log changes to the effective *default* setting
	changed := !reflectDeepEqualPacResult(pm.effectiveProxy, newEffectiveResult)
	if changed {
		logProxies := pac.UrlsFromPacResult(newEffectiveResult)
		slog.Info("Effective default proxy setting changed",
			"old_type", pm.effectiveProxy.Type, "old_proxies", UrlsToStrings(pac.UrlsFromPacResult(pm.effectiveProxy)),
			"new_type", newEffectiveResult.Type, "new_proxies", UrlsToStrings(logProxies))
		pm.effectiveProxy = newEffectiveResult
	} else {
		slog.Debug("Effective default proxy setting remains unchanged.")
	}

	return nil // No error occurred
}

func (pm *ProxyManager) GetEffectiveProxyForURL(targetURL *url.URL) (pac.PacResult, error) {
	if targetURL == nil {
		return pac.PacResult{Type: pac.ResultUnknown}, errors.New("targetURL cannot be nil")
	}

	pm.proxyMutex.RLock()
	proxyType := strings.ToLower(pm.config.Type)
	scriptContent := pm.wpadPacScript
	staticResult := pm.effectiveProxy // Read the current default/static config
	pm.proxyMutex.RUnlock()

	switch proxyType {
	case "http", "https":
		// Static config: return the pre-calculated effectiveProxy
		if staticResult.Type == pac.ResultUnknown {
			return staticResult, errors.New("proxy statically configured but is in error state")
		}
		slog.Debug("Using static proxy setting for URL", "url", targetURL.String(), "proxy_type", staticResult.Type, "proxies", UrlsToStrings(pac.UrlsFromPacResult(staticResult)))
		return staticResult, nil

	case "none":
		// Direct connection
		slog.Debug("Using DIRECT connection for URL (type=none)", "url", targetURL.String())
		return pac.PacResult{Type: pac.ResultDirect}, nil

	case "wpad":
		// WPAD: must evaluate the script
		if scriptContent == "" {
			slog.Warn("WPAD mode active, but no PAC script content available. Cannot determine proxy.", "url", targetURL.String())
			// Return Unknown, as we can't make a decision
			return pac.PacResult{Type: pac.ResultUnknown}, errors.New("WPAD PAC script is not available")
		}

		slog.Debug("Evaluating WPAD PAC script for URL", "url", targetURL.String())
		ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout)
		defer cancel()

		resultString, err := pm.pacEngine.FindProxyForURL(ctx, scriptContent, targetURL.String(), targetURL.Hostname())
		if err != nil {
			slog.Error("PAC script execution failed for URL", "url", targetURL.String(), "error", err)
			// Return Unknown on script execution error
			return pac.PacResult{Type: pac.ResultUnknown}, fmt.Errorf("PAC script execution failed: %w", err)
		}

		parsedResult := pac.ParseResult(resultString)
		logCtx := slog.With("target_url", targetURL.String(), "result_string", resultString, "parsed_type", parsedResult.Type)
		if parsedResult.Type == pac.ResultProxy {
			logCtx = logCtx.With("parsed_proxies", UrlsToStrings(pac.UrlsFromPacResult(parsedResult)))
		}
		logCtx.Debug("PAC execution result for URL")

		// Handle cases where PAC returns nonsense like "DIRECT ; PROXY host:port"
		// The ParseResult function should handle prioritizing PROXY over DIRECT if mixed.
		if parsedResult.Type == pac.ResultUnknown {
			slog.Warn("PAC script returned invalid/empty directives for URL, treating as error", "url", targetURL.String(), "result_string", resultString)
			return parsedResult, fmt.Errorf("PAC script returned invalid result: %q", resultString)
		}

		return parsedResult, nil // Return the evaluated result

	default:
		slog.Error("Internal error: unsupported proxy type encountered in GetEffectiveProxyForURL", "type", proxyType)
		return pac.PacResult{Type: pac.ResultUnknown}, fmt.Errorf("internal error: unsupported proxy type '%s'", proxyType)
	}
}

// GetEffectiveProxyURL returns the *first* configured static or default proxy URL.
// Returns nil if type is DIRECT, WPAD, or in error state.
func (pm *ProxyManager) GetEffectiveProxyURL() *url.URL {
	pm.proxyMutex.RLock()
	defer pm.proxyMutex.RUnlock()

	// Only return a URL if it's a statically defined proxy
	if pm.effectiveProxy.Type == pac.ResultProxy && len(pm.effectiveProxy.Proxies) > 0 {
		u, err := pm.effectiveProxy.Proxies[0].URL()
		if err == nil {
			return u
		}
		slog.Warn("Failed to convert default ProxyInfo back to url.URL", "proxy", pm.effectiveProxy.Proxies[0], "error", err)
	}
	return nil // Not applicable for DIRECT, WPAD, or Error states
}

func (pm *ProxyManager) wpadRefresher() {
	defer pm.wg.Done()

	// Initial slightly randomized delay before first refresh
	initialJitter := time.Duration(rand.Int63n(int64(5 * time.Minute)))
	time.Sleep(initialJitter)

	baseInterval := wpadCacheDuration
	// Ensure some minimum refresh interval even if cache duration is short
	minInterval := 15 * time.Minute
	if baseInterval > minInterval*2 {
		minInterval = baseInterval / 2
	}

	// Refresh slightly before the cache actually expires
	refreshInterval := baseInterval - (5 * time.Minute)
	if refreshInterval < minInterval {
		refreshInterval = minInterval
	}

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	slog.Info("Starting WPAD refresh background task", "refresh_interval", refreshInterval, "cache_duration", baseInterval)

	for {
		select {
		case <-ticker.C:
			slog.Debug("Performing periodic WPAD refresh...")
			if err := pm.updateProxySettings(false); err != nil {
				// Log error, but continue ticking. updateProxySettings handles using old cache.
				slog.Error("Error during periodic WPAD refresh", "error", err)
			}
			// Reset ticker for next interval (no jitter needed here, runs near expiry)
			ticker.Reset(refreshInterval)

		case <-pm.stopChan:
			slog.Info("Stopping WPAD refresh background task.")
			return
		}
	}
}

func (pm *ProxyManager) fetchPACScript(location string) (string, error) {
	slog.Debug("Attempting to fetch PAC script", "location", location)
	var contentBytes []byte
	var err error
	var contentType string

	parsedURL, urlErr := url.Parse(location)

	// HTTP(S) fetch
	if urlErr == nil && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https") {
		ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.connectTimeout)
		defer cancel()

		req, reqErr := http.NewRequestWithContext(ctx, "GET", location, nil)
		if reqErr != nil {
			return "", fmt.Errorf("failed to create PAC request for %s: %w", location, reqErr)
		}
		req.Header.Set("User-Agent", "KernelGatekeeper-Client/PAC-Fetcher") // Identify client

		resp, doErr := pm.httpClientForPAC.Do(req)
		if doErr != nil {
			return "", fmt.Errorf("failed to fetch PAC from %s: %w", location, doErr)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyPreviewBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			bodyPreview := strings.ToValidUTF8(string(bodyPreviewBytes), "?") // Ensure preview is valid UTF8
			return "", fmt.Errorf("failed to fetch PAC from %s: status %s, body: %s", location, resp.Status, bodyPreview)
		}

		contentType = resp.Header.Get("Content-Type")
		limitedReader := io.LimitReader(resp.Body, pacMaxSizeBytes)
		contentBytes, err = io.ReadAll(limitedReader)
		if err != nil {
			return "", fmt.Errorf("failed to read PAC content from %s: %w", location, err)
		}
		// Check if limit was actually hit
		if int64(len(contentBytes)) == pacMaxSizeBytes {
			n, _ := io.ReadFull(resp.Body, make([]byte, 1)) // Try reading one more byte
			if n > 0 {
				return "", fmt.Errorf("PAC script %s exceeds maximum size limit (%d bytes)", location, pacMaxSizeBytes)
			}
		}
		slog.Debug("Fetched PAC script via HTTP(S)", "url", location, "size", len(contentBytes), "content_type", contentType)

	} else { // File fetch
		filePath := location
		// Handle file:// URLs specifically for cross-platform paths
		if urlErr == nil && parsedURL.Scheme == "file" {
			filePath = parsedURL.Path
			// Convert Windows path like /C:/path/to/file
			if os.PathSeparator == '\\' && strings.HasPrefix(filePath, "/") && len(filePath) > 2 && filePath[2] == ':' {
				filePath = filePath[1:] // Remove leading /
			}
			// Convert UNC paths like //server/share/path
			if os.PathSeparator == '\\' && strings.HasPrefix(filePath, "//") {
				// Keep the double slash for UNC
			} else {
				// Standard path cleaning
				filePath = filepath.FromSlash(filePath)
			}
		}
		filePath = filepath.Clean(filePath)

		fileInfo, statErr := os.Stat(filePath)
		if statErr != nil {
			return "", fmt.Errorf("failed to stat PAC file path '%s': %w", filePath, statErr)
		}
		if fileInfo.Size() > pacMaxSizeBytes {
			return "", fmt.Errorf("PAC file %s exceeds maximum size limit (%d bytes)", filePath, pacMaxSizeBytes)
		}
		if fileInfo.IsDir() {
			return "", fmt.Errorf("PAC file path %s is a directory, not a file", filePath)
		}

		contentBytes, err = os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read PAC file %s: %w", filePath, err)
		}
		slog.Debug("Read PAC script from local file", "path", filePath, "size", len(contentBytes))
		contentType = "" // No content type for local files unless we sniff it
	}

	// --- Content Decoding ---
	reader := bytes.NewReader(contentBytes)
	var specifiedCharset string

	// 1. Use charset from config if provided
	if pm.config.PacCharset != "" {
		specifiedCharset = pm.config.PacCharset
		slog.Debug("Using PAC charset specified in config", "charset", specifiedCharset)
	} else if contentType != "" { // 2. Try Content-Type header
		if parts := strings.Split(contentType, "charset="); len(parts) == 2 {
			specifiedCharset = strings.Trim(strings.TrimSpace(parts[1]), `"'`) // Handle quotes
			slog.Debug("Detected PAC charset from Content-Type", "charset", specifiedCharset)
		}
	}
	// 3. TODO: Could add BOM sniffing here if needed

	finalReader := io.Reader(reader) // Start with original bytes
	specifiedCharset = strings.ToLower(strings.TrimSpace(specifiedCharset))

	if specifiedCharset != "" && specifiedCharset != "utf-8" && specifiedCharset != "utf8" {
		encoding, _ := charset.Lookup(specifiedCharset)
		if encoding == nil {
			slog.Warn("Unsupported PAC charset specified or detected, falling back to UTF-8 attempt", "charset", specifiedCharset)
			// Proceed using original bytes, hoping it's UTF-8 or ASCII
		} else {
			slog.Debug("Decoding PAC script content", "charset", specifiedCharset)
			finalReader = transform.NewReader(reader, encoding.NewDecoder())
		}
	} else {
		slog.Debug("Assuming PAC script is UTF-8 (no specific non-UTF-8 charset detected/configured)")
	}

	// Read potentially transformed content
	decodedBytes, err := io.ReadAll(finalReader)
	if err != nil {
		// Provide context about the charset being used
		csMsg := specifiedCharset
		if csMsg == "" {
			csMsg = "utf-8 (default)"
		}
		return "", fmt.Errorf("failed to decode PAC content (charset: %s): %w", csMsg, err)
	}

	// Final check for UTF-8 validity
	if !utf8.Valid(decodedBytes) {
		slog.Warn("PAC content is not valid UTF-8 after decoding attempt, forcing conversion with replacement characters", "location", location)
		validUTF8String := strings.ToValidUTF8(string(decodedBytes), string(utf8.RuneError))
		return validUTF8String, nil // Return the lossy converted string
	}

	return string(decodedBytes), nil
}

func (pm *ProxyManager) Close() error {
	slog.Info("Closing Proxy Manager (Client Side)...")
	pm.stopOnce.Do(func() {
		close(pm.stopChan) // Signal background tasks (WPAD refresher) to stop
		// Wait for background tasks to finish
		pm.wg.Wait()
		// Close PAC engine after background tasks (which might use it) are done
		if pm.pacEngine != nil {
			pm.pacEngine.Close()
		}
		// Close idle connections in the HTTP client used for PAC fetching
		if pm.httpClientForPAC != nil && pm.httpClientForPAC.Transport != nil {
			if transport, ok := pm.httpClientForPAC.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}
	})
	slog.Info("Proxy Manager closed.")
	return nil
}

// UrlsToStrings helper remains the same
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

// reflectDeepEqualPacResult helper remains the same
func reflectDeepEqualPacResult(a, b pac.PacResult) bool {
	if a.Type != b.Type {
		return false
	}
	// Compare slices regardless of order? For now, order matters.
	if !reflect.DeepEqual(a.Proxies, b.Proxies) {
		return false
	}
	return true
}
