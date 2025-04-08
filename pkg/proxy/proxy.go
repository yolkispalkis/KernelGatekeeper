// pkg/proxy/proxy.go
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
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/robertkrimen/otto"         // JavaScript engine for PAC
	"golang.org/x/text/encoding/ianaindex" // For PAC charset decoding
	"golang.org/x/text/transform"

	appconfig "github.com/yolki/kernelgatekeeper/pkg/config"
)

// ProxyResult represents the outcome of executing FindProxyForURL.
type ProxyResult struct {
	Type    ProxyResultType
	Proxies []*url.URL // List of proxies if Type is ProxyResultProxy
}

// ProxyResultType indicates whether to use a proxy or connect directly.
type ProxyResultType int

const (
	ProxyResultUnknown ProxyResultType = iota
	ProxyResultDirect                  // "DIRECT"
	ProxyResultProxy                   // "PROXY host:port; ..."
	ProxyResultError                   // Error during PAC execution or parsing
)

const (
	wpadCacheDuration = 1 * time.Hour   // How long to cache WPAD results
	pacMaxSizeBytes   = 1 * 1024 * 1024 // 1MB limit for PAC file size
)

// ProxyManager handles obtaining and managing proxy settings, including WPAD/PAC.
type ProxyManager struct {
	config           *appconfig.ProxyConfig
	effectiveProxy   ProxyResult // Stores the result for non-WPAD or the cached WPAD result
	proxyMutex       sync.RWMutex
	baseTransport    *http.Transport // Used for fetching PAC files
	ottoVM           *otto.Otto      // Reusable JS VM instance
	ottoVMMutex      sync.Mutex      // Protects ottoVM access (otto is not thread-safe)
	wpadCache        wpadCacheEntry
	retryConfig      retrySettings
	stopChan         chan struct{}
	stopOnce         sync.Once
	httpClientForPAC *http.Client // Dedicated client for fetching PAC
}

type wpadCacheEntry struct {
	url       string
	result    ProxyResult
	timestamp time.Time
	mu        sync.RWMutex
}

type retrySettings struct {
	maxRetries     int
	retryDelay     time.Duration
	connectTimeout time.Duration // Timeout for connecting to the proxy itself or fetching PAC
	pacExecTimeout time.Duration // Timeout for executing PAC script
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
	pacExecTimeout := time.Duration(cfg.PacExecutionTimeout) * time.Second // Use correct field

	// Basic transport for fetching PAC file (no proxy, specific timeouts)
	pacTransport := &http.Transport{
		Proxy: nil, // Never use proxy for fetching PAC
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout, // Use connection timeout for fetching PAC
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          5, // Fewer needed for PAC fetching
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	pm := &ProxyManager{
		config:   cfg,
		stopChan: make(chan struct{}),
		retryConfig: retrySettings{
			maxRetries:     cfg.MaxRetries,
			retryDelay:     time.Second * 2,
			connectTimeout: connectTimeout,
			pacExecTimeout: pacExecTimeout,
		},
		baseTransport: pacTransport, // Use this dedicated transport for PAC fetches
		httpClientForPAC: &http.Client{ // Client using the PAC transport
			Transport: pacTransport,
			Timeout:   connectTimeout, // Overall timeout for PAC GET request
		},
		ottoVM: otto.New(), // Initialize the JS VM
	}

	// Pre-register basic PAC helper functions (implementations below)
	if err := pm.registerPacHelpers(); err != nil {
		return nil, fmt.Errorf("failed to register PAC helper functions: %w", err)
	}

	// Determine initial effective proxy settings
	if err := pm.updateProxySettings(true); err != nil {
		// Log error but allow manager to start, maybe it recovers later
		slog.Error("Initial proxy settings update failed", "error", err)
	}

	// Start WPAD refresher goroutine if type is wpad
	if strings.ToLower(pm.config.Type) == "wpad" {
		go pm.wpadRefresher()
	}

	return pm, nil
}

// updateProxySettings determines the effective proxy based on config type.
// If initial is true, forces WPAD fetch even if cache is valid.
func (pm *ProxyManager) updateProxySettings(initial bool) error {
	pm.proxyMutex.Lock()
	defer pm.proxyMutex.Unlock()

	var newResult ProxyResult
	var err error
	proxyType := strings.ToLower(pm.config.Type)

	switch proxyType {
	case "http", "https":
		if pm.config.URL == "" {
			err = errors.New("proxy URL is empty for http/https type")
			newResult = ProxyResult{Type: ProxyResultError}
		} else {
			parsedURL, parseErr := url.Parse(pm.config.URL)
			if parseErr != nil {
				err = fmt.Errorf("invalid proxy URL '%s': %w", pm.config.URL, parseErr)
				newResult = ProxyResult{Type: ProxyResultError}
			} else {
				newResult = ProxyResult{Type: ProxyResultProxy, Proxies: []*url.URL{parsedURL}}
			}
		}
	case "wpad":
		if pm.config.WpadURL == "" {
			err = errors.New("WPAD URL is empty for wpad type")
			newResult = ProxyResult{Type: ProxyResultError}
		} else {
			// Fetch from WPAD (using cache logic internally)
			// Force fetch if it's the initial setup.
			newResult, err = pm.getProxyFromWPAD(pm.config.WpadURL, initial)
			if err != nil {
				// On WPAD error, *keep* the previously known effective proxy setting
				slog.Warn("Failed to get proxy from WPAD, retaining previous setting", "wpad_url", pm.config.WpadURL, "error", err)
				err = nil                     // Clear error so we don't return it if keeping old setting
				newResult = pm.effectiveProxy // Keep old setting
			}
		}
	case "none":
		newResult = ProxyResult{Type: ProxyResultDirect} // "none" means DIRECT connection
	default:
		err = fmt.Errorf("unsupported proxy type: %s", pm.config.Type)
		newResult = ProxyResult{Type: ProxyResultError}
	}

	if err != nil {
		slog.Error("Failed to determine effective proxy setting", "type", proxyType, "error", err)
		// Persist the error state if we couldn't determine a proxy or keep the old one
		if pm.effectiveProxy.Type != ProxyResultError {
			slog.Warn("Updating effective proxy state to ERROR")
			pm.effectiveProxy = ProxyResult{Type: ProxyResultError}
		}
		return err // Return the error that occurred
	}

	// Check if the effective proxy setting actually changed
	changed := !reflectDeepEqualProxyResult(pm.effectiveProxy, newResult)

	if changed {
		slog.Info("Effective proxy setting changed",
			"old_type", pm.effectiveProxy.Type, "old_proxies", UrlsToStrings(pm.effectiveProxy.Proxies),
			"new_type", newResult.Type, "new_proxies", UrlsToStrings(newResult.Proxies))
		pm.effectiveProxy = newResult
	} else {
		slog.Debug("Effective proxy setting remains unchanged.")
	}

	return nil // Success
}

// GetEffectiveProxyForURL determines the proxy to use for a specific target URL.
// For WPAD, this executes the PAC script. For other types, it returns the static setting.
func (pm *ProxyManager) GetEffectiveProxyForURL(targetURL *url.URL) (ProxyResult, error) {
	pm.proxyMutex.RLock()
	proxyType := strings.ToLower(pm.config.Type)
	wpadURL := pm.config.WpadURL
	staticResult := pm.effectiveProxy // Get the currently configured static/cached result
	pm.proxyMutex.RUnlock()

	if targetURL == nil {
		return ProxyResult{Type: ProxyResultError}, errors.New("targetURL cannot be nil")
	}

	switch proxyType {
	case "http", "https":
		// Return the statically configured proxy
		if staticResult.Type == ProxyResultError {
			return staticResult, errors.New("proxy statically configured but is in error state")
		}
		return staticResult, nil
	case "none":
		// Always connect directly
		return ProxyResult{Type: ProxyResultDirect}, nil
	case "wpad":
		// Need to execute PAC script for the specific URL
		if wpadURL == "" {
			return ProxyResult{Type: ProxyResultError}, errors.New("WPAD type configured but WPAD URL is missing")
		}
		pacScript, err := pm.fetchPACScript(wpadURL) // Fetch script (uses cache internally)
		if err != nil {
			return ProxyResult{Type: ProxyResultError}, fmt.Errorf("failed to fetch PAC script from %s: %w", wpadURL, err)
		}
		if pacScript == "" {
			// Treat empty script as DIRECT? Or error? Let's assume error for now.
			return ProxyResult{Type: ProxyResultError}, fmt.Errorf("fetched PAC script is empty from %s", wpadURL)
		}

		// Execute the PAC script
		resultString, err := pm.executePacScript(pacScript, targetURL.String(), targetURL.Hostname())
		if err != nil {
			return ProxyResult{Type: ProxyResultError}, fmt.Errorf("PAC script execution failed: %w", err)
		}

		// Parse the result string (e.g., "PROXY proxy:port; DIRECT")
		parsedResult := pm.parsePacResult(resultString)
		slog.Debug("PAC execution result for URL", "target_url", targetURL.String(), "result_string", resultString, "parsed_type", parsedResult.Type, "parsed_proxies", UrlsToStrings(parsedResult.Proxies))
		return parsedResult, nil
	default:
		// Should not happen if validation is correct
		return ProxyResult{Type: ProxyResultError}, fmt.Errorf("internal error: unsupported proxy type '%s' encountered", proxyType)
	}
}

// GetEffectiveProxyURL is a simplified getter for the static/cached proxy URL.
// DEPRECATED: Use GetEffectiveProxyForURL for WPAD correctness.
// This remains for compatibility with the client's initial connection logic
// where it needs *a* proxy URL before knowing the target. It will return the
// first proxy from the cached/static list if available.
func (pm *ProxyManager) GetEffectiveProxyURL() *url.URL {
	pm.proxyMutex.RLock()
	defer pm.proxyMutex.RUnlock()
	if pm.effectiveProxy.Type == ProxyResultProxy && len(pm.effectiveProxy.Proxies) > 0 {
		return pm.effectiveProxy.Proxies[0]
	}
	return nil
}

// --- WPAD / PAC Handling ---

// wpadRefresher periodically calls updateProxySettings for WPAD type.
func (pm *ProxyManager) wpadRefresher() {
	// Use a slightly jittered interval based on cache duration
	baseInterval := wpadCacheDuration
	minInterval := baseInterval - (5 * time.Minute)
	jitterRange := (10 * time.Minute).Nanoseconds() // 10 min jitter range
	jitter := time.Duration(rand.Int63n(jitterRange))
	interval := minInterval + jitter

	if interval <= 0 { // Ensure positive interval
		interval = 30 * time.Minute // Fallback to 30 mins if calculation is bad
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("Starting WPAD refresh background task", "interval", interval)
	for {
		select {
		case <-ticker.C:
			slog.Debug("Performing periodic WPAD refresh...")
			// Update settings, but don't force fetch (allow cache)
			if err := pm.updateProxySettings(false); err != nil {
				slog.Error("Error during periodic WPAD refresh", "error", err)
			}
			// Reset ticker with new jittered interval
			jitter = time.Duration(rand.Int63n(jitterRange))
			interval = minInterval + jitter
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

// getProxyFromWPAD fetches PAC, executes FindProxyForURL for a dummy URL ("http://example.com")
// to get the general proxy setting, using caching.
// If force is true, bypasses the cache time check.
func (pm *ProxyManager) getProxyFromWPAD(wpadURL string, force bool) (ProxyResult, error) {
	pm.wpadCache.mu.RLock()
	// Check cache first (unless forced)
	if !force && pm.wpadCache.url == wpadURL && time.Since(pm.wpadCache.timestamp) < wpadCacheDuration {
		cachedResult := pm.wpadCache.result
		pm.wpadCache.mu.RUnlock()
		slog.Debug("Using cached WPAD result", "type", cachedResult.Type, "proxies", UrlsToStrings(cachedResult.Proxies))
		return cachedResult, nil
	}
	pm.wpadCache.mu.RUnlock()

	slog.Info("Fetching and parsing WPAD file", "url", wpadURL, "force_fetch", force)

	// 1. Fetch the PAC script content
	pacScript, err := pm.fetchPACScript(wpadURL)
	if err != nil {
		return ProxyResult{Type: ProxyResultError}, err // Return error result
	}
	if pacScript == "" {
		slog.Warn("Fetched PAC script is empty, treating as DIRECT", "url", wpadURL)
		// Update cache with DIRECT result
		result := ProxyResult{Type: ProxyResultDirect}
		pm.updateWpadCache(wpadURL, result)
		return result, nil
	}

	// 2. Execute FindProxyForURL for a generic target to determine the default proxy
	//    Using "http://example.com" as a common practice.
	dummyURL := "http://example.com"
	dummyHost := "example.com"
	resultString, err := pm.executePacScript(pacScript, dummyURL, dummyHost)
	if err != nil {
		return ProxyResult{Type: ProxyResultError}, fmt.Errorf("initial PAC script execution failed: %w", err)
	}

	// 3. Parse the result string
	parsedResult := pm.parsePacResult(resultString)

	// 4. Update cache
	pm.updateWpadCache(wpadURL, parsedResult)

	slog.Info("WPAD initial execution complete", "result_type", parsedResult.Type, "proxies", UrlsToStrings(parsedResult.Proxies))
	return parsedResult, nil
}

// updateWpadCache safely updates the WPAD cache.
func (pm *ProxyManager) updateWpadCache(wpadURL string, result ProxyResult) {
	pm.wpadCache.mu.Lock()
	pm.wpadCache.url = wpadURL
	pm.wpadCache.result = result
	pm.wpadCache.timestamp = time.Now()
	pm.wpadCache.mu.Unlock()
	slog.Debug("WPAD cache updated", "url", wpadURL, "type", result.Type)
}

// fetchPACScript fetches the PAC script content from the given URL.
// It handles potential character encoding issues.
// NOTE: This function does *not* use caching itself; caching is handled by the caller.
func (pm *ProxyManager) fetchPACScript(pacURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.connectTimeout) // Timeout for the fetch operation
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", pacURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create PAC request for %s: %w", pacURL, err)
	}
	req.Header.Set("User-Agent", "KernelGatekeeper-Client/1.0 (WPAD Fetch)")

	resp, err := pm.httpClientForPAC.Do(req) // Use the dedicated client
	if err != nil {
		return "", fmt.Errorf("failed to fetch PAC from %s: %w", pacURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch PAC from %s: status %s", pacURL, resp.Status)
	}

	// Limit reader to prevent excessive memory usage
	limitedReader := io.LimitReader(resp.Body, pacMaxSizeBytes)

	// Handle potential character encoding based on config or Content-Type
	reader := io.Reader(limitedReader)
	specifiedCharset := pm.config.PacCharset // Config takes precedence
	if specifiedCharset == "" {
		// Try to get charset from Content-Type header
		contentType := resp.Header.Get("Content-Type")
		if parts := strings.Split(contentType, "charset="); len(parts) == 2 {
			specifiedCharset = strings.TrimSpace(parts[1])
		}
	}

	specifiedCharset = strings.ToLower(strings.TrimSpace(specifiedCharset))

	if specifiedCharset != "" && specifiedCharset != "utf-8" && specifiedCharset != "utf8" {
		slog.Debug("Attempting to decode PAC script", "charset", specifiedCharset)
		encoding, err := ianaindex.IANA.Encoding(specifiedCharset)
		if err != nil {
			slog.Warn("Unsupported PAC charset specified, falling back to UTF-8", "charset", specifiedCharset, "error", err)
		} else if encoding != nil {
			reader = transform.NewReader(reader, encoding.NewDecoder())
		}
	}

	// Read the potentially decoded content
	pacContent, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read PAC content from %s: %w", pacURL, err)
	}

	// Ensure the result is valid UTF-8, converting if necessary (best effort)
	if !utf8.Valid(pacContent) {
		slog.Warn("PAC content is not valid UTF-8 after decoding attempt, forcing conversion", "url", pacURL)
		pacContent = []byte(strings.ToValidUTF8(string(pacContent), "")) // Replace invalid bytes
	}

	return string(pacContent), nil
}

// executePacScript runs the PAC JavaScript code within the Otto VM.
func (pm *ProxyManager) executePacScript(script, targetURL, targetHost string) (string, error) {
	// Otto VM is not thread-safe, protect access
	pm.ottoVMMutex.Lock()
	defer pm.ottoVMMutex.Unlock()

	// Set a timeout for the script execution
	vm := pm.ottoVM             // Use the pre-initialized VM
	halt := make(chan struct{}) // Channel to signal completion or timeout
	defer close(halt)           // Ensure halt channel is closed eventually

	vm.Interrupt = make(chan func()) // Interrupt channel for this execution

	// Timeout goroutine
	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout)
	defer cancelTimeout()

	go func() {
		select {
		case <-timeoutCtx.Done():
			if timeoutCtx.Err() == context.DeadlineExceeded {
				slog.Warn("PAC script execution timed out", "timeout", pm.retryConfig.pacExecTimeout)
				// Send interrupt signal to Otto
				vm.Interrupt <- func() {
					panic(errors.New("pac script execution timeout"))
				}
			}
		case <-halt: // Exit if main function completes or panics first
			return
		}
	}()

	var resultString string
	var err error

	// Use a separate goroutine for the actual Otto execution
	// to allow the timeout mechanism to interrupt it.
	execDone := make(chan struct{})
	go func() {
		defer func() {
			// Catch potential panic from timeout or script error
			if r := recover(); r != nil {
				if errStr, ok := r.(string); ok && strings.Contains(errStr, "pac script execution timeout") {
					err = fmt.Errorf("pac script execution timed out after %s", pm.retryConfig.pacExecTimeout)
				} else {
					err = fmt.Errorf("panic during PAC script execution: %v", r)
				}
			}
			close(execDone) // Signal completion or panic
		}()

		// Load the script (it might have changed since last execution)
		// This replaces any previously loaded script in the shared VM.
		_, loadErr := vm.Run(script)
		if loadErr != nil {
			panic(fmt.Errorf("failed to load PAC script into JS VM: %w", loadErr)) // Panic to be caught
		}

		// Prepare the function call string
		call := fmt.Sprintf(`FindProxyForURL("%s", "%s")`, targetURL, targetHost) // Basic quoting

		// Execute FindProxyForURL
		value, runErr := vm.Run(call)
		if runErr != nil {
			// Check if FindProxyForURL is undefined
			if strings.Contains(runErr.Error(), "ReferenceError:") && strings.Contains(runErr.Error(), "FindProxyForURL") {
				panic(errors.New("function 'FindProxyForURL' not found in PAC script"))
			}
			panic(fmt.Errorf("failed to execute FindProxyForURL in PAC script: %w", runErr))
		}

		// Convert result to string
		resStr, convErr := value.ToString()
		if convErr != nil {
			panic(fmt.Errorf("failed to convert PAC result to string: %w", convErr))
		}
		resultString = resStr
	}()

	// Wait for execution to finish or timeout context to cancel
	select {
	case <-execDone:
		// Execution finished (or panicked), err will be set if panic occurred
	case <-timeoutCtx.Done():
		// This case might be hit if the timeout occurs just as execDone is closing,
		// but the primary timeout mechanism is the interrupt.
		if err == nil { // Ensure we report timeout if no panic captured
			err = fmt.Errorf("pac script execution timed out after %s (context signal)", pm.retryConfig.pacExecTimeout)
		}
	}

	vm.Interrupt = nil // Clean up interrupt channel

	return resultString, err
}

// parsePacResult converts the string output of FindProxyForURL into a ProxyResult.
func (pm *ProxyManager) parsePacResult(result string) ProxyResult {
	result = strings.TrimSpace(result)
	if result == "" {
		slog.Warn("PAC script returned empty result, assuming DIRECT")
		return ProxyResult{Type: ProxyResultDirect}
	}

	parts := strings.Split(result, ";")
	var proxies []*url.URL
	hasDirect := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		fields := strings.Fields(part) // Split by space

		if len(fields) == 0 {
			continue
		}

		proxyType := strings.ToUpper(fields[0])

		switch proxyType {
		case "DIRECT":
			hasDirect = true // Note direct is an option
		case "PROXY", "HTTPS", "HTTP": // Treat HTTP/HTTPS keywords same as PROXY
			if len(fields) < 2 {
				slog.Warn("Invalid PAC directive: missing host:port", "directive", part)
				continue
			}
			hostPort := fields[1]
			// Basic validation: check for colon, but allow just hostname (assume default port later?)
			// net.SplitHostPort requires a port.
			host, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				// Maybe it's just a hostname? Assume port 80 for PROXY/HTTP, 443 for HTTPS? Risky.
				// For now, require host:port format.
				slog.Warn("Invalid PAC proxy format (expected host:port)", "value", hostPort, "error", err)
				continue
			}
			if host == "" || port == "" {
				slog.Warn("Invalid PAC proxy format (empty host or port)", "value", hostPort)
				continue
			}

			// Determine scheme
			scheme := "http" // Default for PROXY
			if proxyType == "HTTPS" {
				scheme = "https"
			}

			proxyURLStr := fmt.Sprintf("%s://%s", scheme, hostPort)
			parsedURL, err := url.Parse(proxyURLStr)
			if err != nil {
				slog.Warn("Failed to parse proxy URL from PAC directive", "directive", part, "parsed_url", proxyURLStr, "error", err)
				continue
			}
			proxies = append(proxies, parsedURL)

		case "SOCKS", "SOCKS4", "SOCKS5":
			slog.Warn("SOCKS proxy type found in PAC result, but SOCKS is not supported. Ignoring.", "directive", part)
			continue // Ignore SOCKS directives

		default:
			slog.Warn("Unknown PAC directive type encountered", "directive", part)
		}
	}

	// Determine final result type
	if len(proxies) > 0 {
		// If PROXY directives were found, return them, even if DIRECT was also present.
		// The client logic will try proxies first.
		return ProxyResult{Type: ProxyResultProxy, Proxies: proxies}
	} else if hasDirect {
		// If only DIRECT was found
		return ProxyResult{Type: ProxyResultDirect}
	} else {
		// If nothing valid was parsed
		slog.Warn("Failed to parse any valid directives from PAC result", "result_string", result)
		return ProxyResult{Type: ProxyResultError} // Indicate error if nothing useful found
	}
}

// --- PAC Helper Functions for Otto ---

func (pm *ProxyManager) registerPacHelpers() error {
	vm := pm.ottoVM
	helpers := map[string]interface{}{
		// Basic network helpers
		"isPlainHostName":     pm.pacIsPlainHostName,
		"dnsDomainIs":         pm.pacDnsDomainIs,
		"localHostOrDomainIs": pm.pacLocalHostOrDomainIs,
		"isResolvable":        pm.pacIsResolvable,
		"dnsResolve":          pm.pacDnsResolve,
		"myIpAddress":         pm.pacMyIpAddress,
		"dnsDomainLevels":     pm.pacDnsDomainLevels,

		// Time helpers
		"weekdayRange": pm.pacWeekdayRange,
		"dateRange":    pm.pacDateRange,
		"timeRange":    pm.pacTimeRange,

		// Utility
		"shExpMatch": pm.pacShExpMatch,
		"alert":      pm.pacAlert, // Log alerts instead of showing popups

		// IPv6 helpers (implement later if adding IPv6 support)
		// "myIpAddressEx": pm.pacMyIpAddressEx,
		// "dnsResolveEx": pm.pacDnsResolveEx,
		// "isResolvableEx": pm.pacIsResolvableEx,
		// "isInNetEx": pm.pacIsInNetEx,
		// "sortIpAddressList": pm.pacSortIpAddressList,
	}

	for name, fn := range helpers {
		if err := vm.Set(name, fn); err != nil {
			return fmt.Errorf("failed to set PAC helper '%s': %w", name, err)
		}
	}
	slog.Debug("Registered PAC helper functions in JS VM.")
	return nil
}

// Implementations of PAC helper functions (simplified versions)
// These need careful implementation to match browser behavior accurately.

func (pm *ProxyManager) pacAlert(call otto.FunctionCall) otto.Value {
	message, _ := call.Argument(0).ToString()
	slog.Warn("[PAC Alert]", "message", message)
	return otto.UndefinedValue()
}

func (pm *ProxyManager) pacIsPlainHostName(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	result := !strings.Contains(host, ".")
	v, _ := pm.ottoVM.ToValue(result)
	return v
}

func (pm *ProxyManager) pacDnsDomainIs(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	domain, _ := call.Argument(1).ToString()
	// Ensure domain starts with a dot for proper suffix matching unless it's an exact match
	hostLower := strings.ToLower(host)
	domainLower := strings.ToLower(domain)
	var result bool
	if strings.HasPrefix(domainLower, ".") {
		result = strings.HasSuffix(hostLower, domainLower)
	} else {
		result = hostLower == domainLower || strings.HasSuffix(hostLower, "."+domainLower)
	}
	v, _ := pm.ottoVM.ToValue(result)
	return v
}

func (pm *ProxyManager) pacLocalHostOrDomainIs(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	hostdom, _ := call.Argument(1).ToString()
	// Simplified: check if hostname matches exactly or if it's a suffix match
	hostLower := strings.ToLower(host)
	hostdomLower := strings.ToLower(hostdom)
	result := hostLower == hostdomLower || strings.HasSuffix(hostLower, "."+hostdomLower)
	v, _ := pm.ottoVM.ToValue(result)
	return v
}

func (pm *ProxyManager) pacIsResolvable(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	// Simple check: try to resolve
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // Short timeout for resolvability check
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(ctx, host)
	result := err == nil
	v, _ := pm.ottoVM.ToValue(result)
	return v
}

func (pm *ProxyManager) pacDnsResolve(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // Short timeout for DNS resolve check
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return otto.NullValue() // Return null on failure as per spec
	}
	// Return the first resolved IP (common practice, though spec is ambiguous)
	v, _ := pm.ottoVM.ToValue(addrs[0])
	return v
}

func (pm *ProxyManager) pacMyIpAddress(call otto.FunctionCall) otto.Value {
	// Finding the "primary" non-loopback IP is complex. Return first non-loopback IPv4.
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ipStr := ipnet.IP.String()
					v, _ := pm.ottoVM.ToValue(ipStr)
					return v
				}
			}
		}
	}
	// Fallback or if only IPv6 found
	v, _ := pm.ottoVM.ToValue("127.0.0.1") // Default fallback
	return v
}

func (pm *ProxyManager) pacDnsDomainLevels(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	levels := strings.Count(host, ".")
	v, _ := pm.ottoVM.ToValue(levels)
	return v
}

func (pm *ProxyManager) pacShExpMatch(call otto.FunctionCall) otto.Value {
	str, _ := call.Argument(0).ToString()
	pattern, _ := call.Argument(1).ToString()
	// Basic glob matching (convert shExp to regex? or use path.Match)
	// path.Match is simpler
	matched, err := filepath.Match(pattern, str) // Note: filepath.Match might not be 100% shExp compatible
	if err != nil {
		slog.Warn("Error in shExpMatch", "pattern", pattern, "string", str, "error", err)
		matched = false
	}
	v, _ := pm.ottoVM.ToValue(matched)
	return v
}

// TODO: Implement date/time helpers (weekdayRange, dateRange, timeRange)
// These require careful handling of timezones and formats specified in the PAC standard.
// Returning false for now to avoid incorrect behavior.

func (pm *ProxyManager) pacWeekdayRange(call otto.FunctionCall) otto.Value {
	slog.Warn("PAC function 'weekdayRange' not fully implemented, returning false")
	v, _ := pm.ottoVM.ToValue(false)
	return v
}
func (pm *ProxyManager) pacDateRange(call otto.FunctionCall) otto.Value {
	slog.Warn("PAC function 'dateRange' not fully implemented, returning false")
	v, _ := pm.ottoVM.ToValue(false)
	return v
}
func (pm *ProxyManager) pacTimeRange(call otto.FunctionCall) otto.Value {
	slog.Warn("PAC function 'timeRange' not fully implemented, returning false")
	v, _ := pm.ottoVM.ToValue(false)
	return v
}

// --- Utility ---

// Close shuts down the ProxyManager, stopping background tasks.
func (pm *ProxyManager) Close() error {
	slog.Info("Closing Proxy Manager (Client Side)...")
	pm.stopOnce.Do(func() {
		close(pm.stopChan)
		// Close idle connections in the dedicated PAC client transport
		if pm.baseTransport != nil {
			pm.baseTransport.CloseIdleConnections()
		}
	})
	slog.Info("Proxy Manager closed.")
	return nil
}

// UrlsToStrings converts URL slice to string slice for logging (Exported).
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

// reflectDeepEqualProxyResult compares two ProxyResult structs. Necessary because url.URL contains unexported fields.
func reflectDeepEqualProxyResult(a, b ProxyResult) bool {
	if a.Type != b.Type {
		return false
	}
	if len(a.Proxies) != len(b.Proxies) {
		return false
	}
	// Compare proxies by string representation as url.URL deep equal is tricky
	aStrs := UrlsToStrings(a.Proxies) // Use exported version
	bStrs := UrlsToStrings(b.Proxies) // Use exported version
	if len(aStrs) != len(bStrs) {     // Should be caught by len check above, but double-check
		return false
	}
	// Order matters here - PAC results are ordered preference
	for i := range aStrs {
		if aStrs[i] != bStrs[i] {
			return false
		}
	}
	return true
}

// Helper function for comparing url.URL slices (order matters)
func reflectDeepEqualURLSlice(a, b []*url.URL) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		// Compare string representations for simplicity, as reflect.DeepEqual doesn't work well
		// with unexported fields in url.URL.
		aStr := ""
		bStr := ""
		if a[i] != nil {
			aStr = a[i].String()
		}
		if b[i] != nil {
			bStr = b[i].String()
		}
		if aStr != bStr {
			return false
		}
	}
	return true
}
