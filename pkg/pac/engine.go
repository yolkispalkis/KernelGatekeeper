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
	// Use standard net masks, specific IP versions not strictly needed here
)

const (
	dnsCacheTTL           = 5 * time.Minute
	myIPCacheTTL          = 10 * time.Minute // IP address changes less often
	defaultPacExecTimeout = 5 * time.Second
	dnsLookupTimeout      = 2 * time.Second
	cacheCleanupInterval  = 15 * time.Minute
)

// dnsCacheEntry stores a resolved IP and its expiry time.
type dnsCacheEntry struct {
	ip     string // Store as string for simplicity with PAC
	expiry time.Time
}

// Engine encapsulates the JS VM and PAC helper logic.
type Engine struct {
	vm          *otto.Otto
	vmMutex     sync.Mutex // Protects vm access
	dnsCache    map[string]dnsCacheEntry
	dnsCacheMu  sync.RWMutex
	myIPCache   string
	myIPExpiry  time.Time
	myIPCacheMu sync.RWMutex
	stopChan    chan struct{} // For cleanup goroutine
}

// NewEngine creates a new PAC evaluation engine.
func NewEngine() (*Engine, error) {
	e := &Engine{
		vm:        otto.New(),
		dnsCache:  make(map[string]dnsCacheEntry),
		stopChan:  make(chan struct{}),
		myIPCache: "", // Initialize cache as empty
	}
	if err := e.registerPacHelpers(); err != nil {
		return nil, fmt.Errorf("failed to register PAC helpers: %w", err)
	}
	go e.periodicCacheCleanup(cacheCleanupInterval)
	slog.Info("PAC Engine initialized with DNS and IP caching.")
	return e, nil
}

// Close stops background cleanup tasks.
func (e *Engine) Close() {
	// Use a non-blocking send to close channel if not already closed
	select {
	case <-e.stopChan:
		// Already closed
	default:
		close(e.stopChan)
	}
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

func (e *Engine) getMyIP() (string, bool) {
	e.myIPCacheMu.RLock()
	ip := e.myIPCache
	isValid := time.Now().Before(e.myIPExpiry)
	e.myIPCacheMu.RUnlock()
	if isValid && ip != "" {
		slog.Debug("PAC myIpAddress cache hit", "ip", ip)
		return ip, true
	}
	if ip != "" { // Log reason for cache miss
		slog.Debug("PAC myIpAddress cache expired")
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
		return
	}
	e.myIPCache = ip
	e.myIPExpiry = time.Now().Add(myIPCacheTTL)
	slog.Debug("PAC myIpAddress cache set", "ip", ip, "ttl", myIPCacheTTL)
}

func (e *Engine) cleanupDnsCache() {
	e.dnsCacheMu.Lock()
	now := time.Now()
	cleaned := 0
	for host, entry := range e.dnsCache {
		if now.After(entry.expiry) {
			delete(e.dnsCache, host)
			cleaned++
		}
	}
	e.dnsCacheMu.Unlock()
	if cleaned > 0 {
		slog.Debug("Cleaned up expired DNS cache entries", "count", cleaned)
	}
}

func (e *Engine) periodicCacheCleanup(interval time.Duration) {
	if interval <= 0 {
		slog.Warn("Periodic cache cleanup disabled due to non-positive interval")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("Starting PAC cache cleanup goroutine", "interval", interval)
	for {
		select {
		case <-ticker.C:
			e.cleanupDnsCache()
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

	pacExecTimeout := defaultPacExecTimeout
	// Use context deadline if available and reasonable
	if deadline, ok := ctx.Deadline(); ok {
		timeout := time.Until(deadline)
		if timeout > 100*time.Millisecond { // Use context timeout if it's longer than a minimum threshold
			pacExecTimeout = timeout
		} else if timeout > 0 { // Deadline already passed or too close
			return "", fmt.Errorf("context deadline is too short or already passed for PAC execution: %v", timeout)
		} // If timeout <= 0, deadline already passed.
	}

	vm := e.vm
	halt := make(chan struct{})
	defer close(halt) // Signal completion/panic to timeout goroutine

	vm.Interrupt = make(chan func(), 1) // Buffered channel
	defer func() {
		// Drain interrupt channel if not used
		select {
		case <-vm.Interrupt:
		default:
		}
		vm.Interrupt = nil // Clean up
	}()

	// Timeout goroutine using context derived from the input context
	timeoutCtx, cancelTimeout := context.WithTimeout(ctx, pacExecTimeout)
	defer cancelTimeout() // Important to release resources

	go func() {
		select {
		case <-timeoutCtx.Done():
			// Check if the reason was the timeout we set, or the parent context cancellation
			if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
				// Timer fired, try to interrupt Otto
				select {
				case vm.Interrupt <- func() {
					panic(fmt.Errorf("pac script execution timed out after %s", pacExecTimeout))
				}:
					slog.Warn("PAC script execution timed out, interrupt sent", "timeout", pacExecTimeout)
				case <-halt: // Already completed or panicked
					return
				}
			} else if errors.Is(timeoutCtx.Err(), context.Canceled) {
				// Parent context was cancelled
				select {
				case vm.Interrupt <- func() {
					panic(fmt.Errorf("pac script execution cancelled by parent context: %w", ctx.Err()))
				}:
					slog.Warn("PAC script execution cancelled by parent context, interrupt sent", "error", ctx.Err())
				case <-halt: // Already completed or panicked
					return
				}
			}
		case <-halt: // Completed normally or panicked first
			return
		}
	}()

	var resultString string
	var execErr error

	// Goroutine for Otto execution to allow interruption by panic
	execDone := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				execErr = fmt.Errorf("panic during PAC script execution: %v", r)
			}
			close(execDone) // Signal completion (normal or panic)
		}()

		// Consider optimizing script loading if script doesn't change often.
		_, loadErr := vm.Run(script)
		if loadErr != nil {
			panic(fmt.Errorf("failed to load PAC script into JS VM: %w", loadErr))
		}

		call := fmt.Sprintf(`FindProxyForURL(%q, %q)`, targetURL, targetHost)
		slog.Debug("Executing PAC function call", "call", call)

		value, runErr := vm.Run(call)
		if runErr != nil {
			if strings.Contains(runErr.Error(), "ReferenceError:") && strings.Contains(runErr.Error(), "FindProxyForURL") {
				panic(errors.New("function 'FindProxyForURL' not found in PAC script"))
			}
			panic(fmt.Errorf("failed to execute FindProxyForURL in PAC script: %w", runErr))
		}

		resStr, convErr := value.ToString()
		if convErr != nil {
			panic(fmt.Errorf("failed to convert PAC result to string: %w", convErr))
		}
		resultString = resStr
	}()

	// Wait for execution to finish OR the timeout context to be done
	select {
	case <-execDone:
		// Execution finished (execErr might be set if panic occurred)
	case <-timeoutCtx.Done():
		// Timeout occurred or parent context was cancelled
		// The interrupt goroutine should have set execErr via panic recovery
		// If execErr is still nil, it means the interrupt didn't panic the Otto routine in time,
		// or the cancellation happened just as it finished. Set error based on context.
		if execErr == nil {
			if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
				execErr = fmt.Errorf("pac script execution timed out after %s (context signal)", pacExecTimeout)
			} else {
				execErr = fmt.Errorf("pac execution cancelled by parent context: %w", timeoutCtx.Err())
			}
		}
	}

	return resultString, execErr
}

// --- PAC Helper Implementations ---

func (e *Engine) registerPacHelpers() error {
	helpers := map[string]interface{}{
		"isPlainHostName":     pacIsPlainHostName,
		"dnsDomainIs":         pacDnsDomainIs,
		"localHostOrDomainIs": pacLocalHostOrDomainIs,
		"isResolvable":        e.pacIsResolvable, // Uses engine
		"dnsResolve":          e.pacDnsResolve,   // Uses engine
		"myIpAddress":         e.pacMyIpAddress,  // Uses engine
		"dnsDomainLevels":     pacDnsDomainLevels,
		"isInNet":             e.pacIsInNet, // Uses engine
		"shExpMatch":          pacShExpMatch,
		"alert":               pacAlert, // Logs alerts

		// Stubs for unimplemented helpers
		"weekdayRange": func(otto.FunctionCall) otto.Value { return otto.FalseValue() },
		"dateRange":    func(otto.FunctionCall) otto.Value { return otto.FalseValue() },
		"timeRange":    func(otto.FunctionCall) otto.Value { return otto.FalseValue() },
		"myIpAddressEx": func(otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'myIpAddressEx' not implemented")
			return otto.NullValue()
		},
		"dnsResolveEx": func(otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'dnsResolveEx' not implemented")
			return otto.NullValue()
		},
		"isInNetEx": func(otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'isInNetEx' not implemented")
			return otto.FalseValue()
		},
		"sortIpAddressList": func(call otto.FunctionCall) otto.Value {
			slog.Warn("PAC function 'sortIpAddressList' not implemented, returning original list string or null")
			arg0 := call.Argument(0)
			if arg0.IsString() {
				return arg0
			} // Return original string representation if possible
			return otto.NullValue()
		},
		// Deprecated helpers might return null/false
		"proxyProfile": func(otto.FunctionCall) otto.Value { return otto.NullValue() },
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
	slog.Warn("[PAC Alert]", "message", message) // Log instead of showing popup
	return otto.UndefinedValue()
}

func pacIsPlainHostName(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	// A plain hostname has no dots. Also check it's not purely an IP address.
	result := !strings.Contains(host, ".") && !isIPAddress(host)
	v, _ := call.Otto.ToValue(result)
	return v
}

func pacDnsDomainIs(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	domain, _ := call.Argument(1).ToString()
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain = strings.ToLower(strings.TrimPrefix(domain, ".")) // Allow ".example.com"
	domain = strings.TrimSuffix(domain, ".")

	// Exact match or suffix match (host ends with .domain)
	result := host == domain || strings.HasSuffix(host, "."+domain)
	v, _ := call.Otto.ToValue(result)
	return v
}

func pacLocalHostOrDomainIs(call otto.FunctionCall) otto.Value {
	// In many simplified PAC contexts, this behaves like dnsDomainIs.
	// A full implementation would check if 'host' resolves to localhost (127.0.0.1/::1)
	// or if it matches the 'hostdom' argument using dnsDomainIs logic.
	// Let's use the simplified equivalence for now.
	return pacDnsDomainIs(call)
}

func pacDnsDomainLevels(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	host = strings.TrimSuffix(host, ".") // Ignore trailing dot for level count
	levels := 0
	if host != "" && !isIPAddress(host) { // Count dots only if it's not an IP
		levels = strings.Count(host, ".")
	}
	v, _ := call.Otto.ToValue(levels)
	return v
}

func pacShExpMatch(call otto.FunctionCall) otto.Value {
	str, _ := call.Argument(0).ToString()
	pattern, _ := call.Argument(1).ToString()
	// Use filepath.Match which implements shell pattern matching (glob).
	matched, err := filepath.Match(pattern, str)
	if err != nil {
		slog.Warn("Error in PAC shExpMatch evaluation", "pattern", pattern, "string", str, "error", err)
		matched = false // Treat matching error as non-match
	}
	v, _ := call.Otto.ToValue(matched)
	return v
}

// --- Helpers using Engine state (DNS/IP Caches) ---

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

	// 1. Check cache
	if ip, found := e.getCachedDns(host); found {
		val, _ := e.vm.ToValue(ip)
		return val
	}

	// 2. Perform lookup
	slog.Debug("PAC dnsResolve: performing DNS lookup", "host", host)
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		slog.Warn("PAC dnsResolve: DNS lookup failed", "host", host, "error", err)
		// Don't cache negative results to allow retries if DNS becomes available
		return otto.NullValue() // Return null in JS
	}

	// 3. Cache and return the first IP address found
	resolvedIP := ips[0]
	// Basic check: ensure it's not an empty string just in case
	if resolvedIP == "" {
		slog.Error("PAC dnsResolve: DNS lookup returned empty string", "host", host)
		return otto.NullValue()
	}
	e.setCachedDns(host, resolvedIP)
	val, _ := e.vm.ToValue(resolvedIP)
	return val
}

func (e *Engine) pacIsResolvable(call otto.FunctionCall) otto.Value {
	// Call dnsResolve internally, check if result is non-null and non-undefined
	resolved := e.pacDnsResolve(call)
	result := !resolved.IsNull() && !resolved.IsUndefined()
	v, _ := e.vm.ToValue(result)
	return v
}

func (e *Engine) pacMyIpAddress(call otto.FunctionCall) otto.Value {
	// 1. Check cache
	if ip, found := e.getMyIP(); found {
		val, _ := e.vm.ToValue(ip)
		return val
	}

	// 2. Cache miss, find IP
	slog.Debug("PAC myIpAddress: performing lookup")
	ip := e.findMyIP() // Use helper function to determine IP
	if ip != "" {      // Only cache if we found a non-empty IP
		e.setMyIP(ip)
	}

	// Return the found IP or the fallback "127.0.0.1"
	val, _ := e.vm.ToValue(ip)
	return val
}

// findMyIP tries to find the first non-loopback, non-linklocal, global unicast IPv4 address.
// Falls back to "127.0.0.1".
func (e *Engine) findMyIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		slog.Warn("PAC myIpAddress: failed to get interface addresses", "error", err)
		return "127.0.0.1" // Fallback
	}

	var firstIPv6Global string // Store first global IPv6 as fallback if no IPv4 found
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok {
			ip := ipnet.IP
			// Check common exclusion criteria
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			// Prefer IPv4 global unicast
			if ip4 := ip.To4(); ip4 != nil {
				slog.Debug("PAC myIpAddress: found IPv4", "ip", ip4.String())
				return ip4.String()
			}
			// Store the first global IPv6 found as a potential fallback
			if ip.To16() != nil && firstIPv6Global == "" && !ip.IsPrivate() { // Check IsPrivate for IPv6? Global usually implies not private.
				firstIPv6Global = ip.String()
			}
		}
	}

	// If no suitable IPv4 found, return the first global IPv6 if one was found
	if firstIPv6Global != "" {
		slog.Debug("PAC myIpAddress: no suitable IPv4 found, using first global IPv6", "ip", firstIPv6Global)
		return firstIPv6Global
	}

	slog.Warn("PAC myIpAddress: could not find suitable non-loopback global IP, falling back to 127.0.0.1")
	return "127.0.0.1" // Ultimate fallback
}

// pacIsInNet checks if a hostname or IP address belongs to a given subnet.
func (e *Engine) pacIsInNet(call otto.FunctionCall) otto.Value {
	// Argument 1: host (string hostname or IP)
	hostOrIPVal := call.Argument(0)
	// Argument 2: pattern (string IP address)
	patternVal, errPattern := call.Argument(1).ToString()
	// Argument 3: mask (string subnet mask)
	maskVal, errMask := call.Argument(2).ToString()

	if errPattern != nil || errMask != nil {
		slog.Warn("PAC isInNet: failed to get pattern or mask string arguments")
		return otto.FalseValue()
	}

	var hostIPStr string
	// Resolve hostname if needed
	if hostOrIPVal.IsString() {
		hostStr, _ := hostOrIPVal.ToString()
		hostStr = strings.TrimSpace(hostStr)
		// Check if it's already an IP
		if net.ParseIP(hostStr) != nil {
			hostIPStr = hostStr
		} else {
			// It's a hostname, resolve it using cached dnsResolve
			// Create a dummy call structure just to pass the host argument
			resolvedVal := e.pacDnsResolve(otto.FunctionCall{
				Otto:         call.Otto,
				This:         call.This,
				ArgumentList: []otto.Value{hostOrIPVal}, // Pass only the host argument
			})
			if resolvedVal.IsNull() || resolvedVal.IsUndefined() {
				slog.Warn("PAC isInNet: failed to resolve host", "host", hostStr)
				return otto.FalseValue() // Cannot compare if resolution fails
			}
			hostIPStr, _ = resolvedVal.ToString()
		}
	} else {
		slog.Warn("PAC isInNet: first argument is not a string", "arg", hostOrIPVal)
		return otto.FalseValue()
	}

	// Perform the network check
	result := ipIsInNet(hostIPStr, patternVal, maskVal)
	v, _ := e.vm.ToValue(result)
	return v
}

// --- Standalone Helper Funcs (used by engine methods) ---

// isIPAddress checks if a string is likely an IPv4 or IPv6 address.
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// ipIsInNet performs the network mask comparison. Handles IPv4 and IPv6.
func ipIsInNet(ipStr, patternStr, maskStr string) bool {
	ip := net.ParseIP(ipStr)
	pattern := net.ParseIP(patternStr)
	maskIP := net.ParseIP(maskStr) // Parse mask string as IP first

	if ip == nil || pattern == nil || maskIP == nil {
		slog.Warn("PAC isInNet: failed to parse one or more IP/mask strings", "ip", ipStr, "pattern", patternStr, "mask", maskStr)
		return false // Cannot compare if parsing fails
	}

	// Determine if we are working with IPv4 or IPv6 based on the mask
	// (assuming pattern and mask are consistent)
	var mask net.IPMask
	isIPv4 := maskIP.To4() != nil && ip.To4() != nil && pattern.To4() != nil               // Check if all look like IPv4
	isIPv6 := !isIPv4 && maskIP.To16() != nil && ip.To16() != nil && pattern.To16() != nil // Check if all look like IPv6

	if isIPv4 {
		mask = net.IPMask(maskIP.To4())
		// Apply mask
		network := pattern.To4().Mask(mask)
		ipInNet := ip.To4().Mask(mask)
		return ipInNet.Equal(network)
	} else if isIPv6 {
		mask = net.IPMask(maskIP.To16())
		// Apply mask
		network := pattern.To16().Mask(mask)
		ipInNet := ip.To16().Mask(mask)
		return ipInNet.Equal(network)
	} else {
		// Mismatched IP versions (e.g., comparing IPv4 host to IPv6 network) or invalid mask format
		slog.Warn("PAC isInNet: IP address versions mismatch or invalid mask format", "ip", ipStr, "pattern", patternStr, "mask", maskStr)
		return false
	}
}
