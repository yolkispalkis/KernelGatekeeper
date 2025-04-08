package pac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/robertkrimen/otto"
)

const (
	dnsCacheTTL           = 5 * time.Minute
	myIPCacheTTL          = 10 * time.Minute
	defaultPacExecTimeout = 5 * time.Second
	dnsLookupTimeout      = 2 * time.Second
	cacheCleanupInterval  = 15 * time.Minute
)

type ipCacheEntry struct {
	ip     string
	expiry time.Time
}

type Engine struct {
	vm          *otto.Otto
	vmMutex     sync.Mutex
	dnsCache    map[string]dnsCacheEntry
	dnsCacheMu  sync.RWMutex
	myIPCache   ipCacheEntry
	myIPCacheMu sync.RWMutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

func NewEngine() (*Engine, error) {
	e := &Engine{
		vm:       otto.New(),
		dnsCache: make(map[string]dnsCacheEntry),
		stopChan: make(chan struct{}),
	}
	if err := e.registerPacHelpers(); err != nil {
		return nil, fmt.Errorf("failed to register PAC helpers: %w", err)
	}

	e.wg.Add(1)
	go e.periodicCacheCleanup(cacheCleanupInterval)

	slog.Info("PAC Engine initialized with DNS and IP caching.")
	return e, nil
}

func (e *Engine) Close() {
	select {
	case <-e.stopChan:
	default:
		close(e.stopChan)
	}
	e.wg.Wait()
	slog.Info("PAC Engine closed.")
}

func (e *Engine) getCachedDns(host string) (string, bool) {
	e.dnsCacheMu.RLock()
	entry, found := e.dnsCache[host]
	e.dnsCacheMu.RUnlock()

	if found && time.Now().Before(entry.expiry) {
		slog.Debug("PAC dnsResolve cache hit", "host", host, "ip", entry.ip)
		return entry.ip, true
	}
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

func (e *Engine) setNegativeDnsCache(host string) {
	e.dnsCacheMu.Lock()
	defer e.dnsCacheMu.Unlock()
	if host == "" {
		return
	}
	e.dnsCache[host] = dnsCacheEntry{
		ip:     "",
		expiry: time.Now().Add(dnsCacheTTL / 5),
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
	if ip != "" {
		slog.Debug("PAC myIpAddress cache expired or invalid")
	} else {
		slog.Debug("PAC myIpAddress cache miss")
	}
	return "", false
}

func (e *Engine) setMyIP(ip string) {
	e.myIPCacheMu.Lock()
	defer e.myIPCacheMu.Unlock()
	if ip == "" {
		slog.Warn("Attempted to cache empty IP for myIpAddress")
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
	defer e.wg.Done()

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
		case <-e.stopChan:
			slog.Info("Stopping PAC cache cleanup goroutine.")
			return
		}
	}
}

func (e *Engine) FindProxyForURL(ctx context.Context, script, targetURL, targetHost string) (string, error) {
	e.vmMutex.Lock()
	defer e.vmMutex.Unlock()

	pacExecTimeout := defaultPacExecTimeout
	parentDeadline, hasParentDeadline := ctx.Deadline()
	if hasParentDeadline {
		timeout := time.Until(parentDeadline)
		if timeout > 100*time.Millisecond {
			pacExecTimeout = timeout
		} else if timeout <= 0 {
			return "", fmt.Errorf("parent context deadline already passed: %w", ctx.Err())
		}
	}
	execCtx, cancel := context.WithTimeout(ctx, pacExecTimeout)
	defer cancel()

	vm := e.vm
	halt := make(chan struct{})
	interrupted := false

	vm.Interrupt = make(chan func(), 1)
	defer func() {
		select {
		case <-vm.Interrupt:
		default:
		}
		vm.Interrupt = nil
		close(halt)
	}()

	go func() {
		select {
		case <-execCtx.Done():
			errReason := execCtx.Err()
			errMsg := fmt.Sprintf("pac script execution %v", errReason)
			if errors.Is(errReason, context.DeadlineExceeded) && hasParentDeadline && parentDeadline.Sub(time.Now()) <= 0 {
				errMsg = fmt.Sprintf("pac script execution cancelled by parent context: %v", ctx.Err())
			} else if errors.Is(errReason, context.DeadlineExceeded) {
				errMsg = fmt.Sprintf("pac script execution timed out after %s", pacExecTimeout)
			}

			select {
			case vm.Interrupt <- func() {
				interrupted = true
				panic(errors.New(errMsg))
			}:
				slog.Warn("PAC script execution interrupted", "reason", errReason, "timeout", pacExecTimeout)
			case <-halt:
				return
			}
		case <-halt:
			return
		}
	}()

	var resultString string
	var execErr error

	execDone := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(error); ok && interrupted && strings.Contains(err.Error(), "pac script execution") {
					execErr = err
				} else {
					execErr = fmt.Errorf("panic during PAC script execution: %v", r)
				}
			}
			close(execDone)
		}()

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

	select {
	case <-execDone:
		if execErr != nil {
			return "", execErr
		}
		return resultString, nil
	case <-execCtx.Done():
		if execErr == nil {
			errReason := execCtx.Err()
			if errors.Is(errReason, context.DeadlineExceeded) && hasParentDeadline && parentDeadline.Sub(time.Now()) <= 0 {
				execErr = fmt.Errorf("pac execution cancelled by parent context: %w", ctx.Err())
			} else if errors.Is(errReason, context.DeadlineExceeded) {
				execErr = fmt.Errorf("pac script execution timed out after %s (context signal)", pacExecTimeout)
			} else {
				execErr = fmt.Errorf("pac execution cancelled by parent context: %w", errReason)
			}
		}
		return "", execErr
	}
}

func (e *Engine) registerPacHelpers() error {
	helpers := map[string]interface{}{
		"isPlainHostName":     pacIsPlainHostName,
		"dnsDomainIs":         pacDnsDomainIs,
		"localHostOrDomainIs": pacLocalHostOrDomainIs,
		"isResolvable":        e.pacIsResolvable,
		"dnsResolve":          e.pacDnsResolve,
		"myIpAddress":         e.pacMyIpAddress,
		"dnsDomainLevels":     pacDnsDomainLevels,
		"isInNet":             e.pacIsInNet,
		"shExpMatch":          pacShExpMatch,
		"alert":               pacAlert,
		"weekdayRange":        pacWeekdayRange,
		"dateRange":           pacDateRange,
		"timeRange":           pacTimeRange,

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
				return arg0
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
