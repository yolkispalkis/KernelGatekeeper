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
	"os" // Needed for file reading
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html/charset" // Use this for Lookup
	"golang.org/x/text/transform"

	// "github.com/robertkrimen/otto" // No longer needed directly here

	appconfig "github.com/yolki/kernelgatekeeper/pkg/config"
	"github.com/yolki/kernelgatekeeper/pkg/pac" // Import the new PAC package
)

// ProxyResultType and ProxyResult are moved to pkg/pac/types.go
const (
	wpadCacheDuration = 1 * time.Hour // Example: Refresh hourly
	pacMaxSizeBytes   = 1 * 1024 * 1024
)

// ProxyManager handles obtaining and managing proxy settings, including WPAD/PAC.
type ProxyManager struct {
	config           *appconfig.ProxyConfig
	effectiveProxy   pac.PacResult // Stores the static or default WPAD result (use pac.PacResult type)
	wpadPacScript    string        // Stores the content of the fetched PAC script for WPAD
	proxyMutex       sync.RWMutex
	pacEngine        *pac.Engine  // Use the PAC engine
	httpClientForPAC *http.Client // Dedicated client for fetching PAC
	wpadCacheExpiry  time.Time    // When the fetched wpadPacScript expires
	stopChan         chan struct{}
	stopOnce         sync.Once
	wg               sync.WaitGroup // Added WaitGroup
	retryConfig      retrySettings  // Keep retry settings
}

// retrySettings struct remains the same
type retrySettings struct {
	maxRetries     int
	retryDelay     time.Duration
	connectTimeout time.Duration
	pacExecTimeout time.Duration // This might be handled within pac.Engine now
}

// Initialize random number generator used for jitter
func init() {
	rand.New(rand.NewSource(time.Now().UnixNano()))
}

// NewProxyManager creates and initializes a ProxyManager.
func NewProxyManager(cfg *appconfig.ProxyConfig) (*ProxyManager, error) {
	slog.Info("Initializing Proxy Manager (Client Side)",
		"type", cfg.Type,
		"url", cfg.URL,
		"wpad_url", cfg.WpadURL)

	connectTimeout := time.Duration(cfg.ConnectionTimeout) * time.Second
	pacExecTimeout := time.Duration(cfg.PacExecutionTimeout) * time.Second // Default timeout for engine

	// PAC Transport setup (remains the same)
	pacTransport := &http.Transport{
		Proxy: nil,
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

	// Create the PAC engine
	engine, err := pac.NewEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PAC engine: %w", err)
	}

	pm := &ProxyManager{
		config:   cfg,
		stopChan: make(chan struct{}),
		retryConfig: retrySettings{
			maxRetries:     cfg.MaxRetries,
			retryDelay:     time.Second * 2,
			connectTimeout: connectTimeout,
			pacExecTimeout: pacExecTimeout, // Store for reference if needed
		},
		pacEngine: engine, // Store the engine instance
		httpClientForPAC: &http.Client{
			Transport: pacTransport,
			Timeout:   connectTimeout, // Overall timeout for PAC GET/read request
		},
	}

	// Determine initial effective proxy settings (fetches/evaluates PAC if needed)
	if err := pm.updateProxySettings(true); err != nil {
		slog.Error("Initial proxy settings update failed, proxy functionality may be impaired", "error", err)
		// Continue, hoping a later refresh works
	}

	// Start WPAD refresher goroutine if type is wpad
	if strings.ToLower(pm.config.Type) == "wpad" {
		pm.wg.Add(1) // Add to waitgroup if refresher is started
		go pm.wpadRefresher()
	}

	return pm, nil
}

// updateProxySettings determines the effective proxy based on config type.
// For WPAD, it fetches the script and runs it for a dummy URL to get the default.
// If initial is true, forces WPAD fetch even if cache is valid.
func (pm *ProxyManager) updateProxySettings(initial bool) error {
	pm.proxyMutex.Lock()
	defer pm.proxyMutex.Unlock()

	var newDefaultResult pac.PacResult // Stores the default result
	var fetchedScriptContent string    // Store fetched script here for WPAD
	var wpadErr error
	proxyType := strings.ToLower(pm.config.Type)

	switch proxyType {
	case "http", "https":
		if pm.config.URL == "" {
			wpadErr = errors.New("proxy URL is empty for http/https type")
			newDefaultResult = pac.PacResult{Type: pac.ResultUnknown}
		} else {
			parsedURL, parseErr := url.Parse(pm.config.URL)
			if parseErr != nil {
				wpadErr = fmt.Errorf("invalid proxy URL '%s': %w", pm.config.URL, parseErr)
				newDefaultResult = pac.PacResult{Type: pac.ResultUnknown}
			} else {
				// Determine scheme and host:port from parsed URL
				scheme := parsedURL.Scheme
				if scheme == "" {
					scheme = "http" // Default scheme
				}
				host := parsedURL.Host // Should include port if specified
				if host == "" {
					wpadErr = fmt.Errorf("proxy URL missing host:port: %s", pm.config.URL)
					newDefaultResult = pac.PacResult{Type: pac.ResultUnknown}
				} else {
					// Ensure port is present if scheme implies it
					if !strings.Contains(host, ":") {
						if scheme == "https" {
							host = net.JoinHostPort(host, "443")
						} else {
							host = net.JoinHostPort(host, "80") // Default for http/PROXY
						}
					}
					newDefaultResult = pac.PacResult{
						Type:    pac.ResultProxy,
						Proxies: []pac.ProxyInfo{{Scheme: scheme, Host: host}},
					}
				}
			}
		}
	case "wpad":
		if pm.config.WpadURL == "" {
			wpadErr = errors.New("WPAD URL is empty for wpad type")
			newDefaultResult = pac.PacResult{Type: pac.ResultUnknown}
		} else {
			// --- WPAD Logic ---
			// Check cache expiry unless forced
			needsFetch := initial || time.Now().After(pm.wpadCacheExpiry) || pm.wpadPacScript == ""

			if needsFetch {
				slog.Info("Fetching/Refreshing WPAD PAC script", "url", pm.config.WpadURL, "force", initial)
				scriptContent, fetchErr := pm.fetchPACScript(pm.config.WpadURL) // Updated fetch
				if fetchErr != nil {
					wpadErr = fmt.Errorf("failed to fetch PAC script from %s: %w", pm.config.WpadURL, fetchErr)
					// Keep old script and expiry on fetch error? Yes. Log warning.
					slog.Warn("Failed to fetch new PAC script, using previously cached script (if any)", "error", wpadErr)
					// Use existing script for evaluation below if available
					fetchedScriptContent = pm.wpadPacScript
				} else {
					fetchedScriptContent = scriptContent
					pm.wpadPacScript = scriptContent // Store fetched script
					pm.wpadCacheExpiry = time.Now().Add(wpadCacheDuration)
					slog.Info("Successfully fetched and cached new PAC script.", "expiry", pm.wpadCacheExpiry.Format(time.RFC3339))
				}
			} else {
				slog.Debug("Using cached WPAD PAC script content.", "expiry", pm.wpadCacheExpiry.Format(time.RFC3339))
				fetchedScriptContent = pm.wpadPacScript // Use cached script
			}

			// Evaluate PAC for a dummy URL to get the default proxy setting
			if fetchedScriptContent == "" {
				slog.Warn("WPAD PAC script content is empty (fetch failed or empty file?), assuming DIRECT as default")
				newDefaultResult = pac.PacResult{Type: pac.ResultDirect}
			} else {
				dummyURL := "http://example.com" // Standard dummy URL
				dummyHost := "example.com"
				slog.Debug("Evaluating PAC script for default proxy", "dummy_url", dummyURL)

				// Create context for execution timeout
				ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout)

				resultString, execErr := pm.pacEngine.FindProxyForURL(ctx, fetchedScriptContent, dummyURL, dummyHost)
				cancel() // Release context resources

				if execErr != nil {
					// Error during default evaluation, keep old default if possible
					wpadErr = fmt.Errorf("initial PAC script execution failed for dummy URL: %w", execErr)
					slog.Warn("Failed to evaluate PAC for default, retaining previous default setting (if any)", "error", wpadErr)
					newDefaultResult = pm.effectiveProxy // Keep old default
				} else {
					newDefaultResult = pac.ParseResult(resultString) // Parse the result
					slog.Debug("PAC default evaluation result", "result_string", resultString, "parsed_type", newDefaultResult.Type)
				}
			}
			// --- End WPAD Logic ---
		}
	case "none":
		newDefaultResult = pac.PacResult{Type: pac.ResultDirect}
	default:
		wpadErr = fmt.Errorf("unsupported proxy type: %s", pm.config.Type)
		newDefaultResult = pac.PacResult{Type: pac.ResultUnknown}
	}

	// Log errors if they occurred
	if wpadErr != nil {
		slog.Error("Error determining effective proxy setting", "type", proxyType, "error", wpadErr)
		// If we encountered an error, ensure the effective type is Unknown/Error
		if pm.effectiveProxy.Type != pac.ResultUnknown {
			slog.Warn("Updating effective proxy state to Unknown/Error")
			pm.effectiveProxy = pac.PacResult{Type: pac.ResultUnknown} // Reset to error state
		}
		// Keep existing script/expiry if WPAD fetch/exec failed
		return wpadErr // Return the error
	}

	// Check if the effective *default* proxy setting actually changed
	changed := !reflectDeepEqualPacResult(pm.effectiveProxy, newDefaultResult) // Use updated comparison func

	if changed {
		logProxies := pac.UrlsFromPacResult(newDefaultResult) // Convert for logging
		slog.Info("Effective default proxy setting changed",
			"old_type", pm.effectiveProxy.Type, "old_proxies", UrlsToStrings(pac.UrlsFromPacResult(pm.effectiveProxy)), // Log old proxies
			"new_type", newDefaultResult.Type, "new_proxies", UrlsToStrings(logProxies))
		pm.effectiveProxy = newDefaultResult
	} else {
		slog.Debug("Effective default proxy setting remains unchanged.")
	}

	return nil // Success
}

// GetEffectiveProxyForURL determines the proxy to use for a specific target URL.
// For WPAD, this executes the PAC script using the PAC engine.
func (pm *ProxyManager) GetEffectiveProxyForURL(targetURL *url.URL) (pac.PacResult, error) {
	if targetURL == nil {
		return pac.PacResult{Type: pac.ResultUnknown}, errors.New("targetURL cannot be nil")
	}

	pm.proxyMutex.RLock() // Read lock needed for config type and script content
	proxyType := strings.ToLower(pm.config.Type)
	scriptContent := pm.wpadPacScript // Get cached script content
	staticResult := pm.effectiveProxy // Get the default result
	pm.proxyMutex.RUnlock()

	switch proxyType {
	case "http", "https":
		// Return the statically configured proxy default
		if staticResult.Type == pac.ResultUnknown {
			return staticResult, errors.New("proxy statically configured but is in error state")
		}
		slog.Debug("Using static proxy setting for URL", "url", targetURL, "proxy_type", staticResult.Type, "proxies", UrlsToStrings(pac.UrlsFromPacResult(staticResult)))
		return staticResult, nil
	case "none":
		// Always connect directly
		slog.Debug("Using DIRECT connection for URL (type=none)", "url", targetURL)
		return pac.PacResult{Type: pac.ResultDirect}, nil
	case "wpad":
		// Execute PAC script using the stored content
		if scriptContent == "" {
			// If fetch/initial eval failed, we might have no script
			slog.Warn("WPAD mode active, but no PAC script content available, falling back to default", "url", targetURL, "default_type", staticResult.Type)
			// Fallback to the cached 'default' result (which might be DIRECT or Unknown/Error)
			if staticResult.Type == pac.ResultUnknown {
				return staticResult, errors.New("WPAD mode active, but PAC script unavailable and no valid default")
			}
			return staticResult, nil
		}

		slog.Debug("Evaluating WPAD PAC script for URL", "url", targetURL.String())
		// Create context for execution timeout
		ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout) // Use configured timeout
		defer cancel()

		resultString, err := pm.pacEngine.FindProxyForURL(ctx, scriptContent, targetURL.String(), targetURL.Hostname())
		if err != nil {
			// Error during PAC execution for this specific URL
			slog.Error("PAC script execution failed for URL", "url", targetURL.String(), "error", err)
			// Fallback strategy: Use default? Or return error? Return error for now.
			return pac.PacResult{Type: pac.ResultUnknown}, fmt.Errorf("PAC script execution failed: %w", err)
		}

		// Parse the result string
		parsedResult := pac.ParseResult(resultString)
		slog.Debug("PAC execution result for URL", "target_url", targetURL.String(), "result_string", resultString, "parsed_type", parsedResult.Type, "parsed_proxies", UrlsToStrings(pac.UrlsFromPacResult(parsedResult)))

		// Handle case where PAC returns nothing valid
		if parsedResult.Type == pac.ResultUnknown {
			slog.Warn("PAC script returned invalid/empty directives for URL, treating as error", "url", targetURL.String(), "result_string", resultString)
			// Return error or fallback? Return error.
			return parsedResult, fmt.Errorf("PAC script returned invalid result: %q", resultString)
		}

		return parsedResult, nil
	default:
		slog.Error("Internal error: unsupported proxy type encountered in GetEffectiveProxyForURL", "type", proxyType)
		return pac.PacResult{Type: pac.ResultUnknown}, fmt.Errorf("internal error: unsupported proxy type '%s'", proxyType)
	}
}

// GetEffectiveProxyURL (DEPRECATED but kept for compatibility)
// Returns the *first* proxy URL from the default/static configuration.
func (pm *ProxyManager) GetEffectiveProxyURL() *url.URL {
	pm.proxyMutex.RLock()
	defer pm.proxyMutex.RUnlock()

	// Use the stored default result
	if pm.effectiveProxy.Type == pac.ResultProxy && len(pm.effectiveProxy.Proxies) > 0 {
		// Try to convert the first ProxyInfo back to url.URL
		u, err := pm.effectiveProxy.Proxies[0].URL()
		if err == nil {
			return u
		}
		slog.Warn("Failed to convert default ProxyInfo back to url.URL", "proxy", pm.effectiveProxy.Proxies[0], "error", err)
	}
	return nil // Return nil if default is DIRECT, Unknown, or parsing fails
}

// --- WPAD / PAC Handling ---

// wpadRefresher remains largely the same, calls pm.updateProxySettings(false)
func (pm *ProxyManager) wpadRefresher() {
	defer pm.wg.Done() // Signal completion when exiting

	// Calculate jittered interval (same logic as before)
	baseInterval := wpadCacheDuration
	minInterval := baseInterval - (5 * time.Minute)
	if minInterval <= 0 {
		minInterval = baseInterval / 2
	} // Ensure positive min interval
	jitterRange := (10 * time.Minute).Nanoseconds()
	interval := minInterval + time.Duration(rand.Int63n(jitterRange))
	if interval <= 0 {
		interval = 30 * time.Minute
	} // Fallback

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("Starting WPAD refresh background task", "initial_interval", interval)
	for {
		select {
		case <-ticker.C:
			slog.Debug("Performing periodic WPAD refresh...")
			// Update settings, don't force fetch (allow time-based cache in updateProxySettings)
			if err := pm.updateProxySettings(false); err != nil {
				slog.Error("Error during periodic WPAD refresh", "error", err)
				// Don't reset interval on error? Or use shorter retry? Keep interval for now.
			}
			// Reset ticker with new jittered interval
			interval = minInterval + time.Duration(rand.Int63n(jitterRange))
			if interval <= 0 {
				interval = 30 * time.Minute
			}
			ticker.Reset(interval)
			slog.Debug("WPAD refresher interval reset", "new_interval", interval)

		case <-pm.stopChan:
			slog.Info("Stopping WPAD refresh background task.")
			return
		}
	}
}

// fetchPACScript fetches the PAC script content from the given URL or local path.
// Handles potential character encoding issues.
func (pm *ProxyManager) fetchPACScript(location string) (string, error) {
	slog.Debug("Attempting to fetch PAC script", "location", location)
	var contentBytes []byte
	var err error
	var contentType string // To store Content-Type for charset detection

	parsedURL, urlErr := url.Parse(location)

	// Check if it's an HTTP/HTTPS URL
	if urlErr == nil && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https") {
		ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.connectTimeout) // Timeout for fetch
		defer cancel()

		req, reqErr := http.NewRequestWithContext(ctx, "GET", location, nil)
		if reqErr != nil {
			return "", fmt.Errorf("failed to create PAC request for %s: %w", location, reqErr)
		}
		req.Header.Set("User-Agent", "KernelGatekeeper-Client/1.0 (PAC Fetch)")

		resp, doErr := pm.httpClientForPAC.Do(req)
		if doErr != nil {
			return "", fmt.Errorf("failed to fetch PAC from %s: %w", location, doErr)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			// Read some of the body for error context
			bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return "", fmt.Errorf("failed to fetch PAC from %s: status %s, body: %s", location, resp.Status, string(bodyPreview))
		}

		contentType = resp.Header.Get("Content-Type") // Get content type for charset detection
		// Limit reader and read content
		limitedReader := io.LimitReader(resp.Body, pacMaxSizeBytes)
		contentBytes, err = io.ReadAll(limitedReader)
		if err != nil {
			return "", fmt.Errorf("failed to read PAC content from %s: %w", location, err)
		}
		// Check size limit wasn't hit (by checking if limitedReader still has data)
		// This is slightly more complex than just checking length after ReadAll
		// _, errPeek := limitedReader.(*io.LimitedReader).R.(io.ByteReader).ReadByte()
		// if errPeek != io.EOF {
		// 	return "", fmt.Errorf("PAC script %s exceeds maximum size limit (%d bytes)", location, pacMaxSizeBytes)
		// }
		if int64(len(contentBytes)) >= pacMaxSizeBytes { // Simplified check after ReadAll
			_, errPeek := resp.Body.Read(make([]byte, 1)) // Try reading one more byte from original body
			if errPeek != io.EOF {
				return "", fmt.Errorf("PAC script %s exceeds maximum size limit (%d bytes)", location, pacMaxSizeBytes)
			}
		}

		slog.Debug("Fetched PAC script via HTTP(S)", "url", location, "size", len(contentBytes))

	} else {
		// Assume it's a local file path (either file:// scheme or just a path)
		filePath := location
		if urlErr == nil && parsedURL.Scheme == "file" {
			filePath = parsedURL.Path // Use path from file URL
			// Handle potential windows path conversion if needed:
			if os.PathSeparator == '\\' && strings.HasPrefix(filePath, "/") {
				filePath = strings.TrimPrefix(filePath, "/") // Remove leading slash
				filePath = filepath.FromSlash(filePath)      // Convert slashes
			}
		}
		filePath = filepath.Clean(filePath) // Clean path

		// Check if file exists and limit reading size
		fileInfo, statErr := os.Stat(filePath)
		if statErr != nil {
			return "", fmt.Errorf("failed to stat PAC file path %s: %w", filePath, statErr)
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
		// No content type header for local files, rely on config or UTF-8 default
		contentType = ""
	}

	// --- Character Encoding Handling ---
	reader := bytes.NewReader(contentBytes)
	var specifiedCharset string
	// 1. Check config override
	if pm.config.PacCharset != "" {
		specifiedCharset = pm.config.PacCharset
		slog.Debug("Using PAC charset specified in config", "charset", specifiedCharset)
	} else if contentType != "" {
		// 2. Try Content-Type header (only for HTTP fetch)
		if parts := strings.Split(contentType, "charset="); len(parts) == 2 {
			specifiedCharset = strings.TrimSpace(parts[1])
			slog.Debug("Detected PAC charset from Content-Type", "charset", specifiedCharset)
		}
	}

	var finalReader io.Reader = reader
	specifiedCharset = strings.ToLower(strings.TrimSpace(specifiedCharset))

	if specifiedCharset != "" && specifiedCharset != "utf-8" && specifiedCharset != "utf8" {
		// Use charset.Lookup from x/net/html which uses ianaindex internally
		encoding, err := charset.Lookup(specifiedCharset)
		if err != nil {
			slog.Warn("Unsupported PAC charset specified or detected, falling back to UTF-8", "charset", specifiedCharset, "error", err)
			// Use original reader (assuming UTF-8 or binary)
		} else if encoding != nil {
			slog.Debug("Decoding PAC script content", "charset", specifiedCharset)
			finalReader = transform.NewReader(reader, encoding.NewDecoder())
		}
	} else {
		slog.Debug("Assuming PAC script is UTF-8 (no specific charset detected/configured or explicitly UTF-8)")
	}

	// Read the potentially decoded content
	decodedBytes, err := io.ReadAll(finalReader)
	if err != nil {
		// Error during decoding transformation
		return "", fmt.Errorf("failed to decode PAC content (charset: %s): %w", specifiedCharset, err)
	}

	// Final check: ensure the result is valid UTF-8 for the JS engine
	if !utf8.Valid(decodedBytes) {
		slog.Warn("PAC content is not valid UTF-8 after decoding attempt, forcing conversion", "location", location)
		// Replace invalid bytes with the Unicode replacement character
		validUTF8String := strings.ToValidUTF8(string(decodedBytes), string(utf8.RuneError))
		return validUTF8String, nil
	}

	return string(decodedBytes), nil
}

// executePacScript is removed - logic moved to pac.Engine.FindProxyForURL

// parsePacResult is removed - logic moved to pac.ParseResult

// --- PAC Helper Function Implementations are removed - moved to pac.Engine ---

// --- Utility ---

// Close shuts down the ProxyManager.
func (pm *ProxyManager) Close() error {
	slog.Info("Closing Proxy Manager (Client Side)...")
	pm.stopOnce.Do(func() {
		close(pm.stopChan)
		// Close PAC engine background tasks (like cache cleaner)
		if pm.pacEngine != nil {
			pm.pacEngine.Close()
		}
		// Close idle connections in the dedicated PAC client transport
		if pm.httpClientForPAC != nil && pm.httpClientForPAC.Transport != nil {
			if transport, ok := pm.httpClientForPAC.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}
		// Wait for goroutines managed by ProxyManager (only wpadRefresher currently)
		pm.wg.Wait()
	})
	slog.Info("Proxy Manager closed.")
	return nil
}

// UrlsToStrings converts []*url.URL to []string for logging.
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

// reflectDeepEqualPacResult compares two pac.PacResult structs.
// Necessary because url.URL contains unexported fields.
func reflectDeepEqualPacResult(a, b pac.PacResult) bool {
	if a.Type != b.Type {
		return false
	}
	// Use reflect.DeepEqual for comparing the slices of ProxyInfo structs
	// This handles potential differences in slice capacity vs. length correctly.
	if !reflect.DeepEqual(a.Proxies, b.Proxies) {
		return false
	}
	return true
}
