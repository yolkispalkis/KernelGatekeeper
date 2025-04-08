package pac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/robertkrimen/otto"
	// _ "github.com/robertkrimen/otto/underscore" // Optional: underscore.js support
)

const (
	dnsCacheTTL           = 5 * time.Minute
	myIPCacheTTL          = 10 * time.Minute // IP address changes less often
	defaultPacExecTimeout = 5 * time.Second  // Fallback if context has no deadline
	dnsLookupTimeout      = 2 * time.Second
	cacheCleanupInterval  = 15 * time.Minute
)

// dnsCacheEntry is defined in types.go now

// ipCacheEntry stores the determined IP address and its expiry.
type ipCacheEntry struct {
	ip     string
	expiry time.Time
}

// Engine encapsulates the JS VM and PAC helper logic.
type Engine struct {
	vm          *otto.Otto
	vmMutex     sync.Mutex // Protects vm access
	dnsCache    map[string]dnsCacheEntry
	dnsCacheMu  sync.RWMutex
	myIPCache   ipCacheEntry // Use struct for IP cache
	myIPCacheMu sync.RWMutex
	stopChan    chan struct{}  // For cleanup goroutine
	wg          sync.WaitGroup // Ensure cleanup goroutine finishes
}

// NewEngine creates a new PAC evaluation engine.
func NewEngine() (*Engine, error) {
	e := &Engine{
		vm:       otto.New(),
		dnsCache: make(map[string]dnsCacheEntry),
		stopChan: make(chan struct{}),
	}
	if err := e.registerPacHelpers(); err != nil {
		return nil, fmt.Errorf("failed to register PAC helpers: %w", err)
	}

	// Start background cleanup task
	e.wg.Add(1)
	go e.periodicCacheCleanup(cacheCleanupInterval)

	slog.Info("PAC Engine initialized with DNS and IP caching.")
	return e, nil
}

// Close stops background cleanup tasks and waits for them to finish.
func (e *Engine) Close() {
	// Use a non-blocking send to close channel if not already closed
	select {
	case <-e.stopChan:
		// Already closed or closing
	default:
		close(e.stopChan)
	}
	// Wait for the cleanup goroutine to exit
	e.wg.Wait()
	slog.Info("PAC Engine closed.")
}

// --- Cache Management ---

func (e *Engine) getCachedDns(host string) (string, bool) {
	e.dnsCacheMu.RLock()
	entry, found := e.dnsCache[host]
	e.dnsCacheMu.RUnlock()

	if found && time.Now().Before(entry.expiry) {
		slog.Debug("PAC dnsResolve cache hit", "host", host, "ip", entry.ip)
		return entry.ip, true
	}
	// Log why cache missed if entry was found but expired
	if found {
		slog.Debug("PAC dnsResolve cache expired", "host", host)
	} else {
		slog.Debug("PAC dnsResolve cache miss", "host", host)
	}
	return "", false
}

func (e *Engine) setCachedDns(host, ip string) {
	e.dnsCacheMu.Lock()
	defer e.dnsCacheMu.Unlock()
	// Don't cache empty results, but allow caching lookup failures (e.g., NXDOMAIN)?
	// For now, only cache successful lookups (non-empty IP).
	if host == "" || ip == "" {
		slog.Warn("Attempted to cache empty host or IP in DNS cache", "host", host, "ip", ip)
		return
	}
	e.dnsCache[host] = dnsCacheEntry{
		ip:     ip,
		expiry: time.Now().Add(dnsCacheTTL),
	}
	slog.Debug("PAC dnsResolve cache set", "host", host, "ip", ip, "ttl", dnsCacheTTL)
}

// setNegativeDnsCache marks a host as unresolvable for a shorter TTL.
func (e *Engine) setNegativeDnsCache(host string) {
	e.dnsCacheMu.Lock()
	defer e.dnsCacheMu.Unlock()
	if host == "" {
		return
	}
	// Store empty string for IP to indicate negative cache entry.
	e.dnsCache[host] = dnsCacheEntry{
		ip:     "",                              // Empty IP signifies negative cache
		expiry: time.Now().Add(dnsCacheTTL / 5), // Shorter TTL for negative cache
	}
	slog.Debug("PAC dnsResolve negative cache set", "host", host, "ttl", dnsCacheTTL/5)
}

func (e *Engine) getMyIP() (string, bool) {
	e.myIPCacheMu.RLock()
	ip := e.myIPCache.ip
	expiry := e.myIPCache.expiry
	e.myIPCacheMu.RUnlock()

	isValid := !expiry.IsZero() && time.Now().Before(expiry)

	if isValid && ip != "" {
		slog.Debug("PAC myIpAddress cache hit", "ip", ip)
		return ip, true
	}
	if ip != "" { // Log reason for cache miss
		slog.Debug("PAC myIpAddress cache expired or invalid")
	} else {
		slog.Debug("PAC myIpAddress cache miss")
	}
	return "", false
}

func (e *Engine) setMyIP(ip string) {
	e.myIPCacheMu.Lock()
	defer e.myIPCacheMu.Unlock()
	if ip == "" { // Don't cache empty IP
		slog.Warn("Attempted to cache empty IP for myIpAddress")
		// Set expiry to now to ensure immediate refresh next time
		e.myIPCache = ipCacheEntry{ip: "", expiry: time.Now()}
		return
	}
	e.myIPCache = ipCacheEntry{
		ip:     ip,
		expiry: time.Now().Add(myIPCacheTTL),
	}
	slog.Debug("PAC myIpAddress cache set", "ip", ip, "ttl", myIPCacheTTL)
}

func (e *Engine) cleanupDnsCache() {
	e.dnsCacheMu.Lock()
	defer e.dnsCacheMu.Unlock()

	now := time.Now()
	cleaned := 0
	total := len(e.dnsCache)
	for host, entry := range e.dnsCache {
		if now.After(entry.expiry) {
			delete(e.dnsCache, host)
			cleaned++
		}
	}
	if cleaned > 0 {
		slog.Debug("Cleaned up expired DNS cache entries", "count", cleaned, "remaining", total-cleaned)
	}
}

func (e *Engine) periodicCacheCleanup(interval time.Duration) {
	defer e.wg.Done() // Signal completion when exiting

	if interval <= 0 {
		slog.Warn("Periodic PAC cache cleanup disabled due to non-positive interval")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("Starting PAC cache cleanup goroutine", "interval", interval)

	for {
		select {
		case <-ticker.C:
			e.cleanupDnsCache()
			// Potentially cleanup other caches here if added
		case <-e.stopChan:
			slog.Info("Stopping PAC cache cleanup goroutine.")
			return
		}
	}
}

// --- PAC Execution ---

// FindProxyForURL executes the PAC script within the engine's VM.
// The caller must provide the script content.
func (e *Engine) FindProxyForURL(ctx context.Context, script, targetURL, targetHost string) (string, error) {
	e.vmMutex.Lock() // Lock the VM for this execution
	defer e.vmMutex.Unlock()

	// --- Timeout Handling ---
	pacExecTimeout := defaultPacExecTimeout
	parentDeadline, hasParentDeadline := ctx.Deadline()
	if hasParentDeadline {
		timeout := time.Until(parentDeadline)
		if timeout > 100*time.Millisecond { // Use context timeout if it's reasonable
			pacExecTimeout = timeout
		} else if timeout <= 0 { // Deadline already passed
			return "", fmt.Errorf("parent context deadline already passed: %w", ctx.Err())
		} // else: deadline too short, use defaultPacExecTimeout
	}
	// Create a new context with the calculated timeout, derived from the parent
	execCtx, cancel := context.WithTimeout(ctx, pacExecTimeout)
	defer cancel() // Ensure derived context is cancelled

	// --- Otto Interruption Setup ---
	vm := e.vm
	halt := make(chan struct{}) // Signals otto execution goroutine finished or panicked
	interrupted := false        // Flag to track if interrupt was sent

	vm.Interrupt = make(chan func(), 1) // Buffered channel
	defer func() {
		// Drain interrupt channel if not used
		select {
		case <-vm.Interrupt:
		default:
		}
		vm.Interrupt = nil // Clean up
		close(halt)        // Ensure halt channel is closed
	}()

	// Goroutine to monitor context cancellation and interrupt Otto
	go func() {
		select {
		case <-execCtx.Done():
			// Check if the reason was the timeout we set, or the parent context cancellation
			errReason := execCtx.Err()
			errMsg := fmt.Sprintf("pac script execution %v", errReason)
			if errors.Is(errReason, context.DeadlineExceeded) && hasParentDeadline && parentDeadline.Sub(time.Now()) <= 0 {
				errMsg = fmt.Sprintf("pac script execution cancelled by parent context: %v", ctx.Err())
			} else if errors.Is(errReason, context.DeadlineExceeded) {
				errMsg = fmt.Sprintf("pac script execution timed out after %s", pacExecTimeout)
			} // else: cancelled by parent context explicitly

			// Attempt to interrupt Otto
			select {
			case vm.Interrupt <- func() {
				// This function executes in Otto's goroutine when interrupted
				interrupted = true
				panic(errors.New(errMsg)) // Use standard error type
			}:
				slog.Warn("PAC script execution interrupted", "reason", errReason, "timeout", pacExecTimeout)
			case <-halt:
				// Otto goroutine finished before interrupt could be sent
				return
			}
		case <-halt:
			// Otto goroutine finished normally or panicked first
			return
		}
	}()

	// --- Otto Execution ---
	var resultString string
	var execErr error

	// Run Otto in its own goroutine to allow the main flow to select on context done
	execDone := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Check if panic was due to our interrupt or something else
				if err, ok := r.(error); ok && interrupted && strings.Contains(err.Error(), "pac script execution") {
					execErr = err // Capture the specific timeout/cancellation error
				} else {
					execErr = fmt.Errorf("panic during PAC script execution: %v", r)
				}
			}
			close(execDone) // Signal completion (normal or panic)
		}()

		// Load the script (Consider optimization: only load if script content changed)
		_, loadErr := vm.Run(script)
		if loadErr != nil {
			panic(fmt.Errorf("failed to load PAC script into JS VM: %w", loadErr))
		}

		// Call FindProxyForURL
		call := fmt.Sprintf(`FindProxyForURL(%q, %q)`, targetURL, targetHost)
		slog.Debug("Executing PAC function call", "call", call)

		value, runErr := vm.Run(call)
		if runErr != nil {
			// Check for common ReferenceError indicating function not found
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

	// Wait for Otto execution or context cancellation
	select {
	case <-execDone:
		// Execution finished. Check execErr from panic recovery.
		if execErr != nil {
			return "", execErr // Return error from panic (timeout, cancellation, or script error)
		}
		// Normal completion
		return resultString, nil
	case <-execCtx.Done():
		// Context finished before Otto goroutine signalled done.
		// This implies timeout or cancellation was the primary reason.
		// The interrupt goroutine should have caused a panic captured in execErr.
		// If execErr is somehow still nil, construct error from context.
		if execErr == nil {
			errReason := execCtx.Err()
			if errors.Is(errReason, context.DeadlineExceeded) && hasParentDeadline && parentDeadline.Sub(time.Now()) <= 0 {
				execErr = fmt.Errorf("pac execution cancelled by parent context: %w", ctx.Err())
			} else if errors.Is(errReason, context.DeadlineExceeded) {
				execErr = fmt.Errorf("pac script execution timed out after %s (context signal)", pacExecTimeout)
			} else { // cancelled by parent context explicitly
				execErr = fmt.Errorf("pac execution cancelled by parent context: %w", errReason)
			}
		}
		return "", execErr
	}
}

// --- PAC Helper Implementations ---

func (e *Engine) registerPacHelpers() error {
	helpers := map[string]interface{}{
		// Implemented / Enhanced Helpers
		"isPlainHostName":     pacIsPlainHostName,
		"dnsDomainIs":         pacDnsDomainIs,
		"localHostOrDomainIs": pacLocalHostOrDomainIs, // Uses dnsDomainIs logic for now
		"isResolvable":        e.pacIsResolvable,      // Uses cached dnsResolve
		"dnsResolve":          e.pacDnsResolve,        // Caching added
		"myIpAddress":         e.pacMyIpAddress,       // Caching added
		"dnsDomainLevels":     pacDnsDomainLevels,
		"isInNet":             e.pacIsInNet, // New implementation
		"shExpMatch":          pacShExpMatch,
		"alert":               pacAlert, // Logs alerts via slog

		// Stubs for unimplemented helpers (can be expanded later)
		"weekdayRange": pacWeekdayRange, // Basic implementation
		"dateRange":    pacDateRange,    // Basic implementation
		"timeRange":    pacTimeRange,    // Basic implementation

		// Less common / Deprecated - return false/null
		"myIpAddressEx": func(otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'myIpAddressEx' not implemented, returning null")
			return otto.NullValue()
		},
		"dnsResolveEx": func(otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'dnsResolveEx' not implemented, returning null")
			return otto.NullValue()
		},
		"isInNetEx": func(otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'isInNetEx' not implemented, returning false")
			return otto.FalseValue()
		},
		"sortIpAddressList": func(call otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'sortIpAddressList' not implemented, returning original list string or null")
			arg0 := call.Argument(0)
			if arg0.IsString() {
				return arg0 // Return original string representation if possible
			}
			return otto.NullValue()
		},
		"proxyProfile": func(otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'proxyProfile' (deprecated) called, returning null")
			return otto.NullValue()
		},
	}

	for name, fn := range helpers {
		if err := e.vm.Set(name, fn); err != nil {
			return fmt.Errorf("failed to set PAC helper '%s': %w", name, err)
		}
	}
	slog.Debug("Registered PAC helper functions in JS VM.")
	return nil
}

// --- Individual Helper Implementations ---

func pacAlert(call otto.FunctionCall) otto.Value {
	message, _ := call.Argument(0).ToString()
	// Log using slog, consistent with application logging
	slog.Warn("[PAC Alert]", "message", message)
	return otto.UndefinedValue()
}

func pacIsPlainHostName(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	// A plain hostname has no dots. Also check it's not purely an IP address.
	// Consider IPv6 addresses might contain colons but no dots.
	result := !strings.Contains(host, ".") && net.ParseIP(host) == nil
	v, _ := call.Otto.ToValue(result)
	return v
}

func pacDnsDomainIs(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	domain, _ := call.Argument(1).ToString()

	// Normalize: lowercase, remove trailing dots
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(domain, "."), ".")) // Allow ".example.com"

	if host == "" || domain == "" {
		v, _ := call.Otto.ToValue(false)
		return v
	}

	// Exact match or suffix match (host ends with .domain)
	result := host == domain || strings.HasSuffix(host, "."+domain)
	v, _ := call.Otto.ToValue(result)
	return v
}

// pacLocalHostOrDomainIs is often treated like dnsDomainIs.
// A more complete version would check if 'host' resolves to 127.0.0.1 or ::1.
// For now, maintain equivalence with dnsDomainIs for simplicity.
func pacLocalHostOrDomainIs(call otto.FunctionCall) otto.Value {
	// Alternative implementation (closer to spec):
	/*
		host, _ := call.Argument(0).ToString()
		hostdom, _ := call.Argument(1).ToString()

		// Check if host is literally "localhost" or resolves to loopback
		if strings.ToLower(host) == "localhost" {
			v, _ := call.Otto.ToValue(true)
			return v
		}
		// Use dnsResolve logic (with caching) to check loopback
		resolvedIPStr := ""
		// Need access to the engine 'e' here, which isn't trivial with Otto's func signature.
		// This highlights a limitation. For now, sticking to dnsDomainIs equivalence.
		// resolvedVal := e.pacDnsResolve(call) // Cannot call engine method directly
		// if !resolvedVal.IsNull() && !resolvedVal.IsUndefined() {
		// 	resolvedIPStr, _ = resolvedVal.ToString()
		// 	resolvedIP := net.ParseIP(resolvedIPStr)
		// 	if resolvedIP != nil && resolvedIP.IsLoopback() {
		//		v, _ := call.Otto.ToValue(true)
		//		return v
		//	}
		// }

		// Fallback to domain matching if not loopback
		return pacDnsDomainIs(call)
	*/
	// Simplified: Treat as dnsDomainIs
	return pacDnsDomainIs(call)
}

func pacDnsDomainLevels(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	host = strings.TrimSuffix(host, ".") // Ignore trailing dot for level count

	levels := 0
	// Count dots only if it's not an IP address and not empty
	if host != "" && net.ParseIP(host) == nil {
		levels = strings.Count(host, ".")
	}
	v, _ := call.Otto.ToValue(levels)
	return v
}

// pacShExpMatch implements shell pattern matching using filepath.Match
func pacShExpMatch(call otto.FunctionCall) otto.Value {
	str, _ := call.Argument(0).ToString()
	pattern, _ := call.Argument(1).ToString()

	// filepath.Match implements standard globbing rules (*, ?, []).
	matched, err := filepath.Match(pattern, str)
	if err != nil {
		slog.Warn("Error in PAC shExpMatch evaluation", "pattern", pattern, "string", str, "error", err)
		matched = false // Treat matching error as non-match, return false
	}
	v, _ := call.Otto.ToValue(matched)
	return v
}

// --- Helpers using Engine state (DNS/IP Caches) ---

// pacDnsResolve resolves a hostname to an IP address string, using caching.
func (e *Engine) pacDnsResolve(call otto.FunctionCall) otto.Value {
	host, err := call.Argument(0).ToString()
	if err != nil {
		slog.Warn("PAC dnsResolve: failed to get host argument", "error", err)
		return otto.NullValue()
	}
	host = strings.TrimSpace(host)
	if host == "" {
		slog.Warn("PAC dnsResolve: called with empty host")
		return otto.NullValue()
	}

	// Check if host is already an IP address
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		slog.Debug("PAC dnsResolve: input is already an IP", "ip", host)
		val, _ := e.vm.ToValue(host) // Return the input string if it's an IP
		return val
	}

	// 1. Check cache (positive and negative)
	if ip, found := e.getCachedDns(host); found {
		if ip == "" { // Negative cache hit
			slog.Debug("PAC dnsResolve negative cache hit", "host", host)
			return otto.NullValue()
		}
		// Positive cache hit handled by getCachedDns logging
		val, _ := e.vm.ToValue(ip)
		return val
	}

	// 2. Perform lookup
	slog.Debug("PAC dnsResolve: performing DNS lookup", "host", host)
	// Use a separate context for the lookup to enforce timeout
	lookupCtx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()

	ips, lookupErr := net.DefaultResolver.LookupHost(lookupCtx, host)

	if lookupErr != nil || len(ips) == 0 {
		// Log specific errors (timeout, nxdomain, etc.)
		var dnsErr *net.DNSError
		if errors.As(lookupErr, &dnsErr) {
			if dnsErr.IsTimeout {
				slog.Warn("PAC dnsResolve: DNS lookup timed out", "host", host, "timeout", dnsLookupTimeout)
			} else if dnsErr.IsNotFound {
				slog.Warn("PAC dnsResolve: DNS lookup failed (NXDOMAIN)", "host", host)
			} else {
				slog.Warn("PAC dnsResolve: DNS lookup failed", "host", host, "error", dnsErr)
			}
		} else if errors.Is(lookupErr, context.DeadlineExceeded) {
			slog.Warn("PAC dnsResolve: DNS lookup timed out (context)", "host", host, "timeout", dnsLookupTimeout)
		} else {
			slog.Warn("PAC dnsResolve: DNS lookup failed", "host", host, "error", lookupErr)
		}

		// Cache the negative result
		e.setNegativeDnsCache(host)
		return otto.NullValue() // Return null in JS
	}

	// 3. Cache and return the first IP address found
	resolvedIP := ips[0]
	// Basic check: ensure it's not an empty string just in case
	if resolvedIP == "" {
		slog.Error("PAC dnsResolve: DNS lookup returned empty string", "host", host)
		e.setNegativeDnsCache(host) // Cache as negative if result is unusable
		return otto.NullValue()
	}
	e.setCachedDns(host, resolvedIP)
	val, _ := e.vm.ToValue(resolvedIP)
	return val
}

// pacIsResolvable checks if a hostname can be resolved, using cached dnsResolve.
func (e *Engine) pacIsResolvable(call otto.FunctionCall) otto.Value {
	// Call dnsResolve internally, check if result is non-null and non-undefined
	resolvedVal := e.pacDnsResolve(call) // This uses the cache
	result := !resolvedVal.IsNull() && !resolvedVal.IsUndefined()
	v, _ := e.vm.ToValue(result)
	return v
}

// pacMyIpAddress returns the machine's primary non-loopback IP address, using caching.
func (e *Engine) pacMyIpAddress(call otto.FunctionCall) otto.Value {
	// 1. Check cache
	if ip, found := e.getMyIP(); found {
		val, _ := e.vm.ToValue(ip)
		return val
	}

	// 2. Cache miss, find IP
	slog.Debug("PAC myIpAddress: performing lookup")
	ip := e.findMyIP() // Use helper function to determine IP
	e.setMyIP(ip)      // Cache the result (even if it's the fallback)

	// Return the found IP
	val, _ := e.vm.ToValue(ip)
	return val
}

// findMyIP attempts to find a non-loopback, global unicast IP address.
// Prefers IPv4, falls back to IPv6, then to "127.0.0.1".
func (e *Engine) findMyIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		slog.Warn("PAC myIpAddress: failed to get interface addresses", "error", err)
		return "127.0.0.1" // Fallback
	}

	var firstIPv4Global string
	var firstIPv6Global string

	for _, address := range addrs {
		// Check if the address is an IPNet structure.
		if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP != nil {
			ip := ipnet.IP
			// Skip loopback, link-local, unspecified, multicast
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}

			// Check for IPv4
			if ip4 := ip.To4(); ip4 != nil {
				// Is it globally routable? (Not private or loopback - already checked loopback)
				if !ip4.IsPrivate() {
					if firstIPv4Global == "" {
						slog.Debug("PAC myIpAddress: found potential IPv4 global", "ip", ip4.String())
						firstIPv4Global = ip4.String()
						// Prefer IPv4 global, so we can return early
						return firstIPv4Global
					}
				}
				// Consider private IPv4 if no global found yet? Usually not desired for myIpAddress.
			} else if ip.To16() != nil { // Check for IPv6
				// Is it globally routable? (Not loopback, link-local, ULA, private - most covered by previous checks)
				// Global unicast is a good indicator.
				if ip.IsGlobalUnicast() {
					if firstIPv6Global == "" {
						slog.Debug("PAC myIpAddress: found potential IPv6 global", "ip", ip.String())
						firstIPv6Global = ip.String()
					}
				}
			}
		}
	}

	// If no suitable IPv4 found, return the first global IPv6 if one was found
	if firstIPv6Global != "" {
		slog.Debug("PAC myIpAddress: no suitable IPv4 global found, using first global IPv6", "ip", firstIPv6Global)
		return firstIPv6Global
	}

	// Add more fallback logic here if needed (e.g., return first private IP?)
	// For now, fall back to loopback if absolutely nothing else is found.
	slog.Warn("PAC myIpAddress: could not find suitable non-loopback global IP, falling back to 127.0.0.1")
	return "127.0.0.1" // Ultimate fallback
}

// pacIsInNet checks if a hostname or IP address belongs to a given subnet.
func (e *Engine) pacIsInNet(call otto.FunctionCall) otto.Value {
	argHost := call.Argument(0)
	argPattern := call.Argument(1)
	argMask := call.Argument(2)

	patternStr, errP := argPattern.ToString()
	maskStr, errM := argMask.ToString()

	if errP != nil || errM != nil {
		slog.Warn("PAC isInNet: failed to get pattern or mask string arguments")
		return otto.FalseValue()
	}

	// Resolve hostname if needed
	hostIPStr := ""
	if argHost.IsString() {
		hostStr, _ := argHost.ToString()
		hostStr = strings.TrimSpace(hostStr)
		if parsedIP := net.ParseIP(hostStr); parsedIP != nil {
			hostIPStr = hostStr // Already an IP
		} else {
			// Resolve using cached dnsResolve
			// Use a temporary dummy FunctionCall to pass the argument
			resolvedVal := e.pacDnsResolve(otto.FunctionCall{
				Otto:         call.Otto,
				This:         call.This,
				ArgumentList: []otto.Value{argHost},
			})
			if resolvedVal.IsNull() || resolvedVal.IsUndefined() {
				slog.Warn("PAC isInNet: failed to resolve host for comparison", "host", hostStr)
				return otto.FalseValue() // Cannot compare if resolution fails
			}
			hostIPStr, _ = resolvedVal.ToString()
		}
	} else {
		slog.Warn("PAC isInNet: first argument (host) is not a string", "arg_type", argHost.Class())
		return otto.FalseValue()
	}

	// Perform the network check
	result := ipIsInNet(hostIPStr, patternStr, maskStr)
	v, _ := e.vm.ToValue(result)
	return v
}

// --- Date/Time Helpers (Basic Implementation) ---

// Note: These date/time functions are complex to implement fully according to spec,
// especially handling GMT variations and different argument counts/types robustly.
// These are simplified versions.

func pacWeekdayRange(call otto.FunctionCall) otto.Value {
	argc := len(call.ArgumentList)
	if argc < 1 || argc > 3 {
		slog.Warn("PAC weekdayRange: incorrect number of arguments")
		return otto.FalseValue() // Or throw JS error
	}

	wd1Str, _ := call.Argument(0).ToString()
	wd2Str := wd1Str // Default if only one weekday arg
	if argc >= 2 && !call.Argument(1).IsUndefined() {
		wd2Str, _ = call.Argument(1).ToString()
	}
	gmtStr, _ := call.Argument(2).ToString() // Check for "GMT"

	now := time.Now()
	if strings.ToUpper(gmtStr) == "GMT" {
		now = now.UTC()
	}

	currentWd := now.Weekday() // Sunday = 0, ..., Saturday = 6

	wd1 := parseWeekday(wd1Str)
	wd2 := parseWeekday(wd2Str)

	if wd1 == -1 || wd2 == -1 {
		slog.Warn("PAC weekdayRange: invalid weekday string")
		return otto.FalseValue()
	}

	result := false
	if wd1 <= wd2 {
		// Simple range, e.g., MON to FRI
		result = currentWd >= wd1 && currentWd <= wd2
	} else {
		// Range wraps around the weekend, e.g., FRI to MON
		result = currentWd >= wd1 || currentWd <= wd2
	}

	v, _ := call.Otto.ToValue(result)
	return v
}

func parseWeekday(wdStr string) time.Weekday {
	switch strings.ToUpper(wdStr) {
	case "SUN":
		return time.Sunday
	case "MON":
		return time.Monday
	case "TUE":
		return time.Tuesday
	case "WED":
		return time.Wednesday
	case "THU":
		return time.Thursday
	case "FRI":
		return time.Friday
	case "SAT":
		return time.Saturday
	default:
		return -1 // Invalid weekday indicator
	}
}

// pacDateRange - Simplified: Only checks if current date matches the single date provided.
// Full implementation requires parsing various formats and ranges.
func pacDateRange(call otto.FunctionCall) otto.Value {
	argc := len(call.ArgumentList)
	if argc < 1 {
		slog.Warn("PAC dateRange: requires at least one argument")
		return otto.FalseValue()
	}

	// Very basic: check if first arg is numeric day-of-month
	dayVal, err := call.Argument(0).ToInteger()
	if err != nil {
		// Could try parsing month names, etc. here for fuller implementation
		slog.Warn("PAC dateRange: currently only supports numeric day-of-month", "error", err)
		return otto.FalseValue()
	}

	// Check for GMT - assumes last argument if present
	gmtStr, _ := call.Argument(argc - 1).ToString()
	now := time.Now()
	if strings.ToUpper(gmtStr) == "GMT" {
		now = now.UTC()
	}

	currentDay := int64(now.Day())
	result := currentDay == dayVal

	v, _ := call.Otto.ToValue(result)
	return v
}

// pacTimeRange - Simplified: Only checks if current hour matches the single hour provided.
// Full implementation requires parsing hh:mm:ss formats and ranges.
func pacTimeRange(call otto.FunctionCall) otto.Value {
	argc := len(call.ArgumentList)
	if argc < 1 {
		slog.Warn("PAC timeRange: requires at least one argument")
		return otto.FalseValue()
	}

	// Very basic: check if first arg is numeric hour
	hourVal, err := call.Argument(0).ToInteger()
	if err != nil {
		// Could try parsing hh:mm:ss here for fuller implementation
		slog.Warn("PAC timeRange: currently only supports numeric hour", "error", err)
		return otto.FalseValue()
	}

	// Check for GMT - assumes last argument if present
	gmtStr := ""
	if argc > 1 {
		// Infer GMT if last arg looks like it, heuristic
		lastArgStr, _ := call.Argument(argc - 1).ToString()
		if strings.ToUpper(lastArgStr) == "GMT" {
			gmtStr = "GMT"
		}
	}
	now := time.Now()
	if gmtStr == "GMT" {
		now = now.UTC()
	}

	currentHour := int64(now.Hour())
	result := currentHour == hourVal

	v, _ := call.Otto.ToValue(result)
	return v
}

// --- Standalone Helper Funcs (used by engine methods) ---

// ipIsInNet performs the network mask comparison. Handles IPv4 and IPv6.
func ipIsInNet(ipStr, patternStr, maskStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		slog.Warn("PAC isInNet: failed to parse IP address", "ip", ipStr)
		return false
	}

	// Handle CIDR notation (e.g., "192.168.1.0/24") directly if mask is omitted or invalid
	_, ipNetFromCIDR, errCIDR := net.ParseCIDR(patternStr)
	if errCIDR == nil && (maskStr == "" || net.ParseIP(maskStr) == nil) {
		return ipNetFromCIDR.Contains(ip)
	}

	// Handle explicit pattern IP and mask IP
	patternIP := net.ParseIP(patternStr)
	maskIP := net.ParseIP(maskStr)

	if patternIP == nil {
		slog.Warn("PAC isInNet: failed to parse pattern IP address", "pattern", patternStr)
		return false
	}
	if maskIP == nil {
		slog.Warn("PAC isInNet: failed to parse mask IP address", "mask", maskStr)
		return false
	}

	// Determine IP version consistency (important!)
	isIPv4 := ip.To4() != nil && patternIP.To4() != nil && maskIP.To4() != nil
	isIPv6 := !isIPv4 && ip.To16() != nil && patternIP.To16() != nil && maskIP.To16() != nil

	var mask net.IPMask
	if isIPv4 {
		mask = net.IPMask(maskIP.To4())
		if len(mask) != net.IPv4len {
			slog.Warn("PAC isInNet: invalid IPv4 mask length", "mask", maskStr)
			return false
		}
		network := patternIP.To4().Mask(mask)
		ipInNet := ip.To4().Mask(mask)
		return ipInNet.Equal(network)

	} else if isIPv6 {
		mask = net.IPMask(maskIP.To16())
		if len(mask) != net.IPv6len {
			slog.Warn("PAC isInNet: invalid IPv6 mask length", "mask", maskStr)
			return false
		}
		network := patternIP.To16().Mask(mask)
		ipInNet := ip.To16().Mask(mask)
		return ipInNet.Equal(network)

	} else {
		// Mismatched IP versions or invalid mask format
		slog.Warn("PAC isInNet: IP address versions mismatch or invalid mask format", "ip", ipStr, "pattern", patternStr, "mask", maskStr)
		return false
	}
}
