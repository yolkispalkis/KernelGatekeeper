package pac

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

	"golang.org/x/net/html/charset" // For character encoding detection
	// For specific encodings
	"golang.org/x/text/transform" // For applying decoders

	appconfig "github.com/yolki/kernelgatekeeper/pkg/config"
	// Removed direct import of "github.com/yolki/kernelgatekeeper/pkg/pac" as we are *in* the pac package now
)

const (
	// Cache duration for fetched WPAD PAC scripts
	wpadCacheDuration = 1 * time.Hour // Example: Refresh hourly

	// Maximum size for downloaded/read PAC files (e.g., 1MB)
	pacMaxSizeBytes = 1 * 1024 * 1024
)

// Constants defined locally
const (
	proxyDirect  = "DIRECT"
	proxyHttp    = "PROXY"
	proxyHttps   = "HTTPS" // Standard PAC uses PROXY or HTTPS, not HTTP
	proxySocks4  = "SOCKS" // SOCKS4 uses SOCKS keyword
	proxySocks5  = "SOCKS5"
	pacDelimiter = ";"
)

// ProxyManager handles obtaining and managing proxy settings, including WPAD/PAC.
// This struct remains in parser.go because it heavily uses the PAC Engine and parsing logic.
// Renaming the file to manager.go might be clearer in the future.
type ProxyManager struct {
	config           *appconfig.ProxyConfig
	effectiveProxy   PacResult // Stores the static or default WPAD result
	wpadPacScript    string    // Stores the content of the fetched PAC script for WPAD
	proxyMutex       sync.RWMutex
	pacEngine        *Engine      // Use the PAC engine
	httpClientForPAC *http.Client // Dedicated client for fetching PAC
	wpadCacheExpiry  time.Time    // When the fetched wpadPacScript expires
	stopChan         chan struct{}
	stopOnce         sync.Once
	wg               sync.WaitGroup // Added waitgroup for refresher
	retryConfig      retrySettings
}

// retrySettings struct remains the same
type retrySettings struct {
	maxRetries     int
	retryDelay     time.Duration
	connectTimeout time.Duration
	pacExecTimeout time.Duration
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
	pacExecTimeout := time.Duration(cfg.PacExecutionTimeout) * time.Second // Use configured timeout

	// PAC Transport setup
	pacTransport := &http.Transport{
		Proxy: nil, // Important: Use direct connection for fetching PAC/WPAD
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout, // Use configured timeout
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          5,                // Limit idle connections for PAC client
		IdleConnTimeout:       90 * time.Second, // Standard idle timeout
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Create the PAC engine
	engine, err := NewEngine() // Use NewEngine from this package
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PAC engine: %w", err)
	}

	pm := &ProxyManager{
		config:   cfg,
		stopChan: make(chan struct{}),
		retryConfig: retrySettings{
			maxRetries:     cfg.MaxRetries,
			retryDelay:     time.Second * 2, // Default retry delay
			connectTimeout: connectTimeout,
			pacExecTimeout: pacExecTimeout, // Store configured timeout
		},
		pacEngine: engine, // Store the engine instance
		httpClientForPAC: &http.Client{
			Transport: pacTransport,
			Timeout:   connectTimeout + (5 * time.Second), // Overall timeout slightly longer than dial
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

	var newDefaultResult PacResult  // Stores the default result
	var fetchedScriptContent string // Store fetched script here for WPAD
	var wpadErr error
	proxyType := strings.ToLower(pm.config.Type)

	switch proxyType {
	case "http", "https":
		if pm.config.URL == "" {
			wpadErr = errors.New("proxy URL is empty for http/https type")
			newDefaultResult = PacResult{Type: ResultUnknown}
		} else {
			parsedURL, parseErr := url.Parse(pm.config.URL)
			if parseErr != nil {
				wpadErr = fmt.Errorf("invalid proxy URL '%s': %w", pm.config.URL, parseErr)
				newDefaultResult = PacResult{Type: ResultUnknown}
			} else {
				// Determine scheme and host:port from parsed URL
				scheme := parsedURL.Scheme
				if scheme == "" {
					scheme = "http" // Default scheme
				}
				host := parsedURL.Host // Should include port if specified
				if host == "" {
					wpadErr = fmt.Errorf("proxy URL missing host:port: %s", pm.config.URL)
					newDefaultResult = PacResult{Type: ResultUnknown}
				} else {
					// Ensure port is present if scheme implies it
					if !strings.Contains(host, ":") {
						if scheme == "https" {
							host = net.JoinHostPort(host, "443")
						} else {
							host = net.JoinHostPort(host, "80") // Default for http/PROXY
						}
					}
					newDefaultResult = PacResult{
						Type:    ResultProxy,
						Proxies: []ProxyInfo{{Scheme: scheme, Host: host}}, // Use local ProxyInfo
					}
				}
			}
		}
	case "wpad":
		if pm.config.WpadURL == "" {
			wpadErr = errors.New("WPAD URL is empty for wpad type")
			newDefaultResult = PacResult{Type: ResultUnknown}
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
				newDefaultResult = PacResult{Type: ResultDirect}
			} else {
				dummyURL := "http://init.local" // Use a non-public TLD for initial check
				dummyHost := "init.local"
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
					// Use the parser (defined in this package)
					newDefaultResult = ParseResult(resultString)
					slog.Debug("PAC default evaluation result", "result_string", resultString, "parsed_type", newDefaultResult.Type)
					// Handle case where PAC returns nothing valid
					if newDefaultResult.Type == ResultUnknown {
						slog.Warn("PAC script returned invalid directives for default evaluation, potentially assuming DIRECT", "result_string", resultString)
						// Keep ResultUnknown
						// newDefaultResult.Type = ResultDirect
					}
				}
			}
			// --- End WPAD Logic ---
		}
	case "none":
		newDefaultResult = PacResult{Type: ResultDirect}
	default:
		wpadErr = fmt.Errorf("unsupported proxy type: %s", pm.config.Type)
		newDefaultResult = PacResult{Type: ResultUnknown}
	}

	// Log errors if they occurred
	if wpadErr != nil {
		slog.Error("Error determining effective proxy setting", "type", proxyType, "error", wpadErr)
		// If we encountered an error, ensure the effective type is Unknown/Error
		if pm.effectiveProxy.Type != ResultUnknown {
			slog.Warn("Updating effective proxy state to Unknown/Error")
			pm.effectiveProxy = PacResult{Type: ResultUnknown} // Reset to error state
		}
		// Keep existing script/expiry if WPAD fetch/exec failed
		return wpadErr // Return the error
	}

	// Check if the effective *default* proxy setting actually changed
	changed := !reflectDeepEqualPacResult(pm.effectiveProxy, newDefaultResult) // Use updated comparison func

	if changed {
		logProxiesOld := UrlsFromPacResult(pm.effectiveProxy) // Convert old for logging (call local func)
		logProxiesNew := UrlsFromPacResult(newDefaultResult)  // Convert new for logging (call local func)
		slog.Info("Effective default proxy setting changed",
			"old_type", pm.effectiveProxy.Type, "old_proxies", UrlsToStrings(logProxiesOld),
			"new_type", newDefaultResult.Type, "new_proxies", UrlsToStrings(logProxiesNew))
		pm.effectiveProxy = newDefaultResult
	} else {
		slog.Debug("Effective default proxy setting remains unchanged.")
	}

	return nil // Success
}

// GetEffectiveProxyForURL determines the proxy to use for a specific target URL.
// For WPAD, this executes the PAC script using the PAC engine.
func (pm *ProxyManager) GetEffectiveProxyForURL(targetURL *url.URL) (PacResult, error) { // Return local PacResult
	if targetURL == nil {
		return PacResult{Type: ResultUnknown}, errors.New("targetURL cannot be nil")
	}

	pm.proxyMutex.RLock() // Read lock needed for config type and script content
	proxyType := strings.ToLower(pm.config.Type)
	scriptContent := pm.wpadPacScript // Get cached script content
	staticResult := pm.effectiveProxy // Get the default result
	pm.proxyMutex.RUnlock()

	switch proxyType {
	case "http", "https":
		// Return the statically configured proxy default
		if staticResult.Type == ResultUnknown {
			return staticResult, errors.New("proxy statically configured but is in error state")
		}
		slog.Debug("Using static proxy setting for URL", "url", targetURL, "proxy_type", staticResult.Type, "proxies", UrlsToStrings(UrlsFromPacResult(staticResult)))
		return staticResult, nil
	case "none":
		// Always connect directly // Return local PacResult
		slog.Debug("Using DIRECT connection for URL (type=none)", "url", targetURL)
		return PacResult{Type: ResultDirect}, nil
	case "wpad":
		// Execute PAC script using the stored content
		if scriptContent == "" {
			// If fetch/initial eval failed, we might have no script
			slog.Warn("WPAD mode active, but no PAC script content available, falling back to default", "url", targetURL, "default_type", staticResult.Type)
			// Fallback to the cached 'default' result (which might be DIRECT or Unknown/Error)
			if staticResult.Type == ResultUnknown {
				return staticResult, errors.New("WPAD mode active, but PAC script unavailable and no valid default") // Return local PacResult
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
			return PacResult{Type: ResultUnknown}, fmt.Errorf("PAC script execution failed: %w", err)
		}

		// Parse the result string
		parsedResult := ParseResult(resultString) // Call local func
		slog.Debug("PAC execution result for URL", "target_url", targetURL.String(), "result_string", resultString, "parsed_type", parsedResult.Type, "parsed_proxies", UrlsToStrings(UrlsFromPacResult(parsedResult)))

		// Return local PacResult
		// Handle case where PAC returns nothing valid
		if parsedResult.Type == ResultUnknown {
			slog.Warn("PAC script returned invalid/empty directives for URL, treating as error", "url", targetURL.String(), "result_string", resultString)
			// Return error or fallback? Return error.
			return parsedResult, fmt.Errorf("PAC script returned invalid result: %q", resultString)
		}

		return parsedResult, nil
	default:
		slog.Error("Internal error: unsupported proxy type encountered in GetEffectiveProxyForURL", "type", proxyType)
		return PacResult{Type: ResultUnknown}, fmt.Errorf("internal error: unsupported proxy type '%s'", proxyType)
	}
}

// GetEffectiveProxyURL (DEPRECATED but kept for compatibility)
// Returns the *first* proxy URL from the default/static configuration.
func (pm *ProxyManager) GetEffectiveProxyURL() *url.URL {
	pm.proxyMutex.RLock()
	defer pm.proxyMutex.RUnlock()

	// Use the stored default result
	if pm.effectiveProxy.Type == ResultProxy && len(pm.effectiveProxy.Proxies) > 0 {
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

// wpadRefresher periodically calls updateProxySettings for WPAD mode.
func (pm *ProxyManager) wpadRefresher() {
	defer pm.wg.Done() // Signal completion when exiting

	// Calculate jittered interval (same logic as Proxydetox)
	baseInterval := wpadCacheDuration
	minInterval := baseInterval - (15 * time.Minute) // More jitter +/- 15 min
	if minInterval <= baseInterval/2 {               // Ensure minimum interval isn't too small
		minInterval = baseInterval / 2
	}
	jitterRange := (30 * time.Minute).Nanoseconds() // Total jitter window of 30 mins
	if jitterRange <= 0 {
		jitterRange = (10 * time.Minute).Nanoseconds() // Fallback jitter
	}

	calculateNextInterval := func() time.Duration {
		interval := minInterval + time.Duration(rand.Int63n(jitterRange))
		if interval <= 0 {
			interval = 30 * time.Minute // Fallback interval
		}
		return interval
	}

	nextInterval := calculateNextInterval()
	ticker := time.NewTicker(nextInterval)
	defer ticker.Stop()

	slog.Info("Starting WPAD refresh background task", "initial_interval", nextInterval)

	for {
		select {
		case <-ticker.C:
			slog.Debug("Performing periodic WPAD refresh...")
			// Update settings, don't force fetch (allow time-based cache check)
			if err := pm.updateProxySettings(false); err != nil {
				slog.Error("Error during periodic WPAD refresh", "error", err)
				// Keep the same interval after an error, maybe retry sooner?
				// For now, reset with a new jittered interval anyway.
			}
			// Reset ticker with new jittered interval
			nextInterval = calculateNextInterval()
			ticker.Reset(nextInterval)
			slog.Debug("WPAD refresher interval reset", "new_interval", nextInterval)

		case <-pm.stopChan:
			slog.Info("Stopping WPAD refresh background task.")
			return
		}
	}
}

// fetchPACScript fetches the PAC script content from the given URL or local path.
// Handles character encoding and size limits.
func (pm *ProxyManager) fetchPACScript(location string) (string, error) {
	slog.Debug("Attempting to fetch PAC script", "location", location)
	var contentBytes []byte
	var err error
	var contentType string // To store Content-Type for charset detection

	parsedURL, urlErr := url.Parse(location)

	// --- Fetching ---
	if urlErr == nil && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https") {
		// Fetch via HTTP/HTTPS
		ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.connectTimeout+(5*time.Second))
		defer cancel()

		req, reqErr := http.NewRequestWithContext(ctx, "GET", location, nil)
		if reqErr != nil {
			return "", fmt.Errorf("failed to create PAC request for %s: %w", location, reqErr)
		}
		req.Header.Set("User-Agent", "KernelGatekeeper-Client/PAC-Fetch") // Identify the client

		resp, doErr := pm.httpClientForPAC.Do(req)
		if doErr != nil {
			return "", fmt.Errorf("failed to fetch PAC from %s: %w", location, doErr)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return "", fmt.Errorf("failed to fetch PAC from %s: status %s, body: %s", location, resp.Status, string(bodyPreview))
		}

		contentType = resp.Header.Get("Content-Type")

		// Limit reader to prevent excessive memory usage and read content
		limitedReader := io.LimitReader(resp.Body, pacMaxSizeBytes+1) // Read one extra byte to detect overflow
		contentBytes, err = io.ReadAll(limitedReader)
		if err != nil {
			return "", fmt.Errorf("failed to read PAC content from %s: %w", location, err)
		}
		// Check if the limit was exceeded
		if int64(len(contentBytes)) > pacMaxSizeBytes {
			return "", fmt.Errorf("PAC script %s exceeds maximum size limit (%d bytes)", location, pacMaxSizeBytes)
		}
		slog.Debug("Fetched PAC script via HTTP(S)", "url", location, "size", len(contentBytes), "content_type", contentType)

	} else {
		// Assume it's a local file path
		filePath := location
		if urlErr == nil && parsedURL.Scheme == "file" {
			filePath = parsedURL.Path // Use path from file URL
			// TODO: Handle Windows path conversion if necessary
			// if runtime.GOOS == "windows" && strings.HasPrefix(filePath, "/") { ... }
		}
		filePath = filepath.Clean(filePath) // Clean the path

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
		contentType = "" // No content type header for local files
	}

	// --- Character Encoding Handling ---
	// Use the configured charset if provided, otherwise detect from content/type
	finalCharset := pm.config.PacCharset // Get from config
	if finalCharset == "" {
		// Detect if not configured
		enc, name, _ := charset.DetermineEncoding(contentBytes, contentType)
		if enc != nil && name != "utf-8" { // Check if detection found something non-UTF-8
			finalCharset = name
			slog.Debug("Detected non-UTF-8 PAC charset", "charset", finalCharset)
		} else {
			finalCharset = "utf-8" // Default to UTF-8 if detection uncertain or finds UTF-8
			slog.Debug("Assuming UTF-8 for PAC script (detection/default)")
		}
	} else {
		slog.Debug("Using PAC charset specified in config", "charset", finalCharset)
	}

	finalCharset = strings.ToLower(strings.TrimSpace(finalCharset))
	var reader io.Reader = bytes.NewReader(contentBytes)

	// If the final charset (from config or detection) is not UTF-8, try decoding
	if finalCharset != "utf-8" && finalCharset != "utf8" {
		enc, _ := charset.Lookup(finalCharset) // Use charset.Lookup from x/net/html
		if enc == nil {
			slog.Warn("Unsupported PAC charset specified or detected, falling back to UTF-8", "charset", finalCharset)
			// Use original reader (assuming UTF-8 or binary)
		} else {
			slog.Info("Decoding PAC script content", "charset", finalCharset)
			reader = transform.NewReader(reader, enc.NewDecoder())
		}
	}

	// Read the potentially decoded content
	decodedBytes, err := io.ReadAll(reader)
	if err != nil {
		// Error during decoding transformation
		return "", fmt.Errorf("failed to decode PAC content (charset: %s): %w", finalCharset, err)
	}

	// Return the (potentially decoded) content as a string
	return string(decodedBytes), nil
}

// ParseResult parses the semicolon-separated result string from FindProxyForURL.
func ParseResult(result string) PacResult {
	if result == "" {
		slog.Debug("PAC result string is empty, returning Unknown")
		return PacResult{Type: ResultUnknown}
	}

	parts := strings.Split(result, pacDelimiter)
	parsed := PacResult{Proxies: make([]ProxyInfo, 0)} // Initialize Proxies slice

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		fields := strings.Fields(part) // Split by space
		if len(fields) == 0 {
			continue
		}

		directive := strings.ToUpper(fields[0])

		switch directive {
		case proxyDirect:
			// DIRECT should be the only directive if present
			if len(parsed.Proxies) == 0 {
				parsed.Type = ResultDirect
				// If DIRECT is found, standard behavior is to ignore subsequent proxies.
				return parsed
			} else {
				slog.Warn("PAC result contained DIRECT after other proxies, ignoring DIRECT", "result", result)
				continue // Skip DIRECT if proxies already found
			}

		case proxyHttp, proxyHttps: // Treat PROXY and HTTPS keywords similarly (HTTP proxy)
			if len(fields) < 2 {
				slog.Warn("PAC result missing host:port for PROXY/HTTPS directive", "directive", part)
				continue
			}
			host := strings.TrimSpace(fields[1])
			scheme := "http" // Default scheme for PROXY keyword
			if directive == proxyHttps {
				scheme = "https"
			}
			// Ensure port is present
			if !strings.Contains(host, ":") {
				defaultPort := "80"
				if scheme == "https" {
					defaultPort = "443"
				}
				host = net.JoinHostPort(host, defaultPort)
			}
			parsed.Type = ResultProxy // Mark as proxy type
			parsed.Proxies = append(parsed.Proxies, ProxyInfo{Scheme: scheme, Host: host})

		case proxySocks4, proxySocks5:
			// KernelGatekeeper client doesn't currently support SOCKS.
			// Log a warning and ignore the directive.
			slog.Warn("Ignoring unsupported SOCKS proxy directive in PAC result", "directive", part)
			// If this is the *only* valid directive found so far, the overall type might remain Unknown.
			if parsed.Type == ResultUnknown && len(parsed.Proxies) == 0 {
				// Keep type as Unknown if only SOCKS found
			} else if parsed.Type == ResultDirect {
				// This shouldn't happen due to early return on DIRECT, but defensive check.
				slog.Error("Internal logic error: SOCKS directive found after DIRECT")
			} else {
				// We already found HTTP proxies, just ignore SOCKS
			}

		default:
			slog.Warn("Ignoring unknown directive in PAC result", "directive", part)
		}
	}

	// If after parsing, we have proxies, type must be ResultProxy
	if len(parsed.Proxies) > 0 {
		parsed.Type = ResultProxy
	} else if parsed.Type == ResultUnknown { // If no DIRECT and no valid proxies found
		slog.Debug("No valid DIRECT or PROXY directives found in PAC result", "result", result)
		parsed.Type = ResultUnknown // Explicitly set Unknown (might already be default)
	}

	return parsed
}

// --- Utility ---

// Close shuts down the ProxyManager, including stopping the WPAD refresher and PAC engine.
func (pm *ProxyManager) Close() error {
	slog.Info("Closing Proxy Manager (Client Side)...")
	pm.stopOnce.Do(func() {
		close(pm.stopChan) // Signal goroutines to stop

		// Close PAC engine background tasks (cache cleaner)
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

// reflectDeepEqualPacResult compares two PacResult structs.
// Necessary because url.URL contains unexported fields.
func reflectDeepEqualPacResult(a, b PacResult) bool {
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

// UrlsFromPacResult converts PacResult.Proxies ([]ProxyInfo) to []*url.URL.
func UrlsFromPacResult(result PacResult) []*url.URL {
	if result.Proxies == nil {
		return nil
	}
	urls := make([]*url.URL, 0, len(result.Proxies))
	for _, pInfo := range result.Proxies {
		if u, err := pInfo.URL(); err == nil { // Call method on local ProxyInfo
			urls = append(urls, u)
		}
	}
	return urls
}
