package proxy

import (
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
	"github.com/yolki/kernelgatekeeper/pkg/pac"
)

const (
	// Cache duration for fetched WPAD PAC scripts
	wpadCacheDuration = 1 * time.Hour // Example: Refresh hourly

	// Maximum size for downloaded/read PAC files (e.g., 1MB)
	pacMaxSizeBytes = 1 * 1024 * 1024
)

// ProxyManager handles obtaining and managing proxy settings, including WPAD/PAC.
type ProxyManager struct {
	config           *appconfig.ProxyConfig
	effectiveProxy   pac.PacResult // Stores the static or default WPAD result
	wpadPacScript    string        // Stores the content of the fetched PAC script for WPAD
	proxyMutex       sync.RWMutex
	pacEngine        *pac.Engine  // Use the PAC engine
	httpClientForPAC *http.Client // Dedicated client for fetching PAC
	wpadCacheExpiry  time.Time    // When the fetched wpadPacScript expires
	stopChan         chan struct{}
	stopOnce         sync.Once
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
	engine, err := pac.NewEngine()
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

	var newDefaultResult pac.PacResult
	var fetchedScriptContent string
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
				scheme := parsedURL.Scheme
				if scheme != "http" && scheme != "https" {
					slog.Warn("Proxy URL scheme is not http/https, defaulting to http", "url", pm.config.URL, "detected_scheme", scheme)
					scheme = "http" // Default scheme if missing or unsupported
				}
				host := parsedURL.Host // Should include port if specified
				if host == "" {
					wpadErr = fmt.Errorf("proxy URL missing host:port: %s", pm.config.URL)
					newDefaultResult = pac.PacResult{Type: pac.ResultUnknown}
				} else {
					// Ensure port is present
					_, _, splitErr := net.SplitHostPort(host)
					if splitErr != nil {
						defaultPort := "80"
						if scheme == "https" {
							defaultPort = "443"
						}
						host = net.JoinHostPort(host, defaultPort)
						slog.Debug("Added default port to static proxy URL", "scheme", scheme, "port", defaultPort, "final_host", host)
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
			needsFetch := initial || time.Now().After(pm.wpadCacheExpiry) || pm.wpadPacScript == ""

			if needsFetch {
				slog.Info("Fetching/Refreshing WPAD PAC script", "url", pm.config.WpadURL, "force", initial)
				// Use fetchPACScript which now handles encoding and size limits
				scriptContent, fetchErr := pm.fetchPACScript(pm.config.WpadURL)
				if fetchErr != nil {
					wpadErr = fmt.Errorf("failed to fetch PAC script from %s: %w", pm.config.WpadURL, fetchErr)
					slog.Warn("Failed to fetch new PAC script, using previously cached script (if any)", "error", wpadErr)
					fetchedScriptContent = pm.wpadPacScript // Use old script if fetch fails
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
				dummyURL := "http://init.local" // Use a non-public TLD for initial check
				dummyHost := "init.local"
				slog.Debug("Evaluating PAC script for default proxy", "dummy_url", dummyURL)

				// Create context for execution timeout
				ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout)

				// Use the PAC engine to execute
				resultString, execErr := pm.pacEngine.FindProxyForURL(ctx, fetchedScriptContent, dummyURL, dummyHost)
				cancel() // Release context resources

				if execErr != nil {
					wpadErr = fmt.Errorf("initial PAC script execution failed for dummy URL: %w", execErr)
					slog.Warn("Failed to evaluate PAC for default, retaining previous default setting (if any)", "error", wpadErr)
					newDefaultResult = pm.effectiveProxy // Keep old default on exec error
				} else {
					// Use the improved parser
					newDefaultResult = pac.ParseResult(resultString)
					slog.Debug("PAC default evaluation result", "result_string", resultString, "parsed_type", newDefaultResult.Type)
					if newDefaultResult.Type == pac.ResultUnknown {
						slog.Warn("PAC script returned invalid directives for default evaluation, potentially assuming DIRECT", "result_string", resultString)
						// Decide fallback: Treat Unknown as DIRECT or error? Let's treat as Unknown/Error for now.
						// newDefaultResult.Type = pac.ResultDirect
					}
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
		if pm.effectiveProxy.Type != pac.ResultUnknown {
			slog.Warn("Updating effective proxy state to Unknown/Error due to processing error")
			pm.effectiveProxy = pac.PacResult{Type: pac.ResultUnknown} // Ensure error state
		}
		// Keep existing script/expiry if WPAD fetch/exec failed? Yes, already handled above.
		return wpadErr // Return the error
	}

	// Compare new default result with the old one
	// Use the improved comparison function
	changed := !reflectDeepEqualPacResult(pm.effectiveProxy, newDefaultResult)

	if changed {
		logProxiesOld := pac.UrlsFromPacResult(pm.effectiveProxy) // Convert old for logging
		logProxiesNew := pac.UrlsFromPacResult(newDefaultResult)  // Convert new for logging
		slog.Info("Effective default proxy setting changed",
			"old_type", pm.effectiveProxy.Type, "old_proxies", UrlsToStrings(logProxiesOld),
			"new_type", newDefaultResult.Type, "new_proxies", UrlsToStrings(logProxiesNew))
		pm.effectiveProxy = newDefaultResult // Update the stored default
	} else {
		slog.Debug("Effective default proxy setting remains unchanged.")
	}

	return nil // Success
}

// GetEffectiveProxyForURL determines the proxy to use for a specific target URL.
// Uses the PAC engine for WPAD mode.
func (pm *ProxyManager) GetEffectiveProxyForURL(targetURL *url.URL) (pac.PacResult, error) {
	if targetURL == nil {
		return pac.PacResult{Type: pac.ResultUnknown}, errors.New("targetURL cannot be nil")
	}

	pm.proxyMutex.RLock() // Read lock for config type and script content
	proxyType := strings.ToLower(pm.config.Type)
	scriptContent := pm.wpadPacScript
	staticResult := pm.effectiveProxy // Get the current default/static result
	pm.proxyMutex.RUnlock()

	switch proxyType {
	case "http", "https":
		// Return the statically configured proxy (or error state if setup failed)
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
			slog.Warn("WPAD mode active, but no PAC script content available, falling back to default", "url", targetURL, "default_type", staticResult.Type)
			if staticResult.Type == pac.ResultUnknown {
				return staticResult, errors.New("WPAD mode active, but PAC script unavailable and no valid default")
			}
			return staticResult, nil // Fallback to the cached 'default' result
		}

		slog.Debug("Evaluating WPAD PAC script for URL", "url", targetURL.String())
		// Create context for execution timeout
		ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout)
		defer cancel()

		// Execute using the PAC engine
		resultString, err := pm.pacEngine.FindProxyForURL(ctx, scriptContent, targetURL.String(), targetURL.Hostname())
		if err != nil {
			slog.Error("PAC script execution failed for URL", "url", targetURL.String(), "error", err)
			// Fallback strategy: Use default? Or return error? Return error.
			return pac.PacResult{Type: pac.ResultUnknown}, fmt.Errorf("PAC script execution failed: %w", err)
		}

		// Parse the result string using the improved parser
		parsedResult := pac.ParseResult(resultString)
		slog.Debug("PAC execution result for URL", "target_url", targetURL.String(), "result_string", resultString, "parsed_type", parsedResult.Type, "parsed_proxies", UrlsToStrings(pac.UrlsFromPacResult(parsedResult)))

		// Handle case where PAC returns nothing valid (ResultUnknown)
		if parsedResult.Type == pac.ResultUnknown {
			slog.Warn("PAC script returned invalid/empty directives for URL, treating as error", "url", targetURL.String(), "result_string", resultString)
			return parsedResult, fmt.Errorf("PAC script returned invalid result: %q", resultString)
		}

		return parsedResult, nil

	default:
		slog.Error("Internal error: unsupported proxy type encountered in GetEffectiveProxyForURL", "type", proxyType)
		return pac.PacResult{Type: pac.ResultUnknown}, fmt.Errorf("internal error: unsupported proxy type '%s'", proxyType)
	}
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
	detectedEncoding, encodingName, certain := charset.DetermineEncoding(contentBytes, contentType)
	slog.Debug("Determined PAC script encoding", "name", encodingName, "certain", certain, "config_override", pm.config.PacCharset)

	// Prefer config override if provided
	if pm.config.PacCharset != "" {
		enc, err := charset.Lookup(pm.config.PacCharset)
		if err == nil {
			slog.Info("Using PAC charset specified in config", "charset", pm.config.PacCharset)
			detectedEncoding = enc // Override detected encoding
		} else {
			slog.Warn("Invalid PAC charset specified in config, ignoring override", "configured_charset", pm.config.PacCharset, "error", err)
			// Fall back to automatically detected encoding
		}
	}

	// If encoding is not UTF-8, decode it
	if detectedEncoding != nil && !strings.EqualFold(encodingName, "utf-8") {
		slog.Info("Decoding PAC script content", "detected_charset", encodingName)
		transformer := detectedEncoding.NewDecoder()
		decodedBytes, _, err := transform.Bytes(transformer, contentBytes)
		if err != nil {
			// If decoding fails, maybe fall back to raw bytes assuming UTF-8? Or return error?
			// Let's return an error for now.
			return "", fmt.Errorf("failed to decode PAC content from charset '%s': %w", encodingName, err)
		}
		// Use the decoded bytes
		contentBytes = decodedBytes
	} else {
		slog.Debug("Assuming PAC script is UTF-8 or config overridden to UTF-8")
	}

	// Return the (potentially decoded) content as a string
	// Note: The JS engine expects a valid Go string (which is UTF-8).
	// If the source wasn't UTF-8 and decoding failed/wasn't possible,
	// creating a string might lead to issues in the JS engine.
	// However, Go strings handle invalid UTF-8 sequences gracefully in many contexts.
	return string(contentBytes), nil
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
