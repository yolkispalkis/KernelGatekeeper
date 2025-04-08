package pac

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/robertkrimen/otto"
)

func pacAlert(call otto.FunctionCall) otto.Value {
	message, _ := call.Argument(0).ToString()
	slog.Warn("[PAC Alert]", "message", message)
	return otto.UndefinedValue()
}

func pacIsPlainHostName(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	result := !strings.Contains(host, ".") && net.ParseIP(host) == nil
	v, _ := call.Otto.ToValue(result)
	return v
}

func pacDnsDomainIs(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	domain, _ := call.Argument(1).ToString()

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(domain, "."), "."))

	if host == "" || domain == "" {
		v, _ := call.Otto.ToValue(false)
		return v
	}

	result := host == domain || strings.HasSuffix(host, "."+domain)
	v, _ := call.Otto.ToValue(result)
	return v
}

func pacLocalHostOrDomainIs(call otto.FunctionCall) otto.Value {
	return pacDnsDomainIs(call)
}

func pacDnsDomainLevels(call otto.FunctionCall) otto.Value {
	host, _ := call.Argument(0).ToString()
	host = strings.TrimSuffix(host, ".")

	levels := 0
	if host != "" && net.ParseIP(host) == nil {
		levels = strings.Count(host, ".")
	}
	v, _ := call.Otto.ToValue(levels)
	return v
}

func pacShExpMatch(call otto.FunctionCall) otto.Value {
	str, _ := call.Argument(0).ToString()
	pattern, _ := call.Argument(1).ToString()

	matched, err := filepath.Match(pattern, str)
	if err != nil {
		slog.Warn("Error in PAC shExpMatch evaluation", "pattern", pattern, "string", str, "error", err)
		matched = false
	}
	v, _ := call.Otto.ToValue(matched)
	return v
}

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

	if parsedIP := net.ParseIP(host); parsedIP != nil {
		slog.Debug("PAC dnsResolve: input is already an IP", "ip", host)
		val, _ := e.vm.ToValue(host)
		return val
	}

	if ip, found := e.getCachedDns(host); found {
		if ip == "" {
			slog.Debug("PAC dnsResolve negative cache hit", "host", host)
			return otto.NullValue()
		}
		val, _ := e.vm.ToValue(ip)
		return val
	}

	slog.Debug("PAC dnsResolve: performing DNS lookup", "host", host)
	lookupCtx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()

	ips, lookupErr := net.DefaultResolver.LookupHost(lookupCtx, host)

	if lookupErr != nil || len(ips) == 0 {
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

		e.setNegativeDnsCache(host)
		return otto.NullValue()
	}

	resolvedIP := ips[0]
	if resolvedIP == "" {
		slog.Error("PAC dnsResolve: DNS lookup returned empty string", "host", host)
		e.setNegativeDnsCache(host)
		return otto.NullValue()
	}
	e.setCachedDns(host, resolvedIP)
	val, _ := e.vm.ToValue(resolvedIP)
	return val
}

func (e *Engine) pacIsResolvable(call otto.FunctionCall) otto.Value {
	resolvedVal := e.pacDnsResolve(call)
	result := !resolvedVal.IsNull() && !resolvedVal.IsUndefined()
	v, _ := e.vm.ToValue(result)
	return v
}

func (e *Engine) pacMyIpAddress(call otto.FunctionCall) otto.Value {
	if ip, found := e.getMyIP(); found {
		val, _ := e.vm.ToValue(ip)
		return val
	}

	slog.Debug("PAC myIpAddress: performing lookup")
	ip := e.findMyIP()
	e.setMyIP(ip)

	val, _ := e.vm.ToValue(ip)
	return val
}

func (e *Engine) findMyIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		slog.Warn("PAC myIpAddress: failed to get interface addresses", "error", err)
		return "127.0.0.1"
	}

	var firstIPv4Global string
	var firstIPv6Global string

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP != nil {
			ip := ipnet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				if !ip4.IsPrivate() {
					if firstIPv4Global == "" {
						slog.Debug("PAC myIpAddress: found potential IPv4 global", "ip", ip4.String())
						firstIPv4Global = ip4.String()
						return firstIPv4Global
					}
				}
			} else if ip.To16() != nil {
				if ip.IsGlobalUnicast() {
					if firstIPv6Global == "" {
						slog.Debug("PAC myIpAddress: found potential IPv6 global", "ip", ip.String())
						firstIPv6Global = ip.String()
					}
				}
			}
		}
	}

	if firstIPv6Global != "" {
		slog.Debug("PAC myIpAddress: no suitable IPv4 global found, using first global IPv6", "ip", firstIPv6Global)
		return firstIPv6Global
	}

	slog.Warn("PAC myIpAddress: could not find suitable non-loopback global IP, falling back to 127.0.0.1")
	return "127.0.0.1"
}

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

	hostIPStr := ""
	if argHost.IsString() {
		hostStr, _ := argHost.ToString()
		hostStr = strings.TrimSpace(hostStr)
		if parsedIP := net.ParseIP(hostStr); parsedIP != nil {
			hostIPStr = hostStr
		} else {
			resolvedVal := e.pacDnsResolve(otto.FunctionCall{
				Otto:         call.Otto,
				This:         call.This,
				ArgumentList: []otto.Value{argHost},
			})
			if resolvedVal.IsNull() || resolvedVal.IsUndefined() {
				slog.Warn("PAC isInNet: failed to resolve host for comparison", "host", hostStr)
				return otto.FalseValue()
			}
			hostIPStr, _ = resolvedVal.ToString()
		}
	} else {
		slog.Warn("PAC isInNet: first argument (host) is not a string", "arg_type", argHost.Class())
		return otto.FalseValue()
	}

	result := ipIsInNet(hostIPStr, patternStr, maskStr)
	v, _ := e.vm.ToValue(result)
	return v
}

func pacWeekdayRange(call otto.FunctionCall) otto.Value {
	argc := len(call.ArgumentList)
	if argc < 1 || argc > 3 {
		slog.Warn("PAC weekdayRange: incorrect number of arguments")
		return otto.FalseValue()
	}

	wd1Str, _ := call.Argument(0).ToString()
	wd2Str := wd1Str
	if argc >= 2 && !call.Argument(1).IsUndefined() {
		wd2Str, _ = call.Argument(1).ToString()
	}
	gmtStr, _ := call.Argument(2).ToString()

	now := time.Now()
	if strings.ToUpper(gmtStr) == "GMT" {
		now = now.UTC()
	}

	currentWd := now.Weekday()

	wd1 := parseWeekday(wd1Str)
	wd2 := parseWeekday(wd2Str)

	if wd1 == -1 || wd2 == -1 {
		slog.Warn("PAC weekdayRange: invalid weekday string")
		return otto.FalseValue()
	}

	result := false
	if wd1 <= wd2 {
		result = currentWd >= wd1 && currentWd <= wd2
	} else {
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
		return -1
	}
}

func pacDateRange(call otto.FunctionCall) otto.Value {
	argc := len(call.ArgumentList)
	if argc < 1 {
		slog.Warn("PAC dateRange: requires at least one argument")
		return otto.FalseValue()
	}

	dayVal, err := call.Argument(0).ToInteger()
	if err != nil {
		slog.Warn("PAC dateRange: currently only supports numeric day-of-month", "error", err)
		return otto.FalseValue()
	}

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

func pacTimeRange(call otto.FunctionCall) otto.Value {
	argc := len(call.ArgumentList)
	if argc < 1 {
		slog.Warn("PAC timeRange: requires at least one argument")
		return otto.FalseValue()
	}

	hourVal, err := call.Argument(0).ToInteger()
	if err != nil {
		slog.Warn("PAC timeRange: currently only supports numeric hour", "error", err)
		return otto.FalseValue()
	}

	gmtStr := ""
	if argc > 1 {
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

func ipIsInNet(ipStr, patternStr, maskStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		slog.Warn("PAC isInNet: failed to parse IP address", "ip", ipStr)
		return false
	}

	_, ipNetFromCIDR, errCIDR := net.ParseCIDR(patternStr)
	if errCIDR == nil && (maskStr == "" || net.ParseIP(maskStr) == nil) {
		return ipNetFromCIDR.Contains(ip)
	}

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
		slog.Warn("PAC isInNet: IP address versions mismatch or invalid mask format", "ip", ipStr, "pattern", patternStr, "mask", maskStr)
		return false
	}
}
