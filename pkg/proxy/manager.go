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
	effectiveProxy   pac.PacResult
	wpadPacScript    string
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
	maxRetries     int
	retryDelay     time.Duration
	connectTimeout time.Duration
	pacExecTimeout time.Duration
}

func NewProxyManager(cfg *appconfig.ProxyConfig) (*ProxyManager, error) {
	slog.Info("Initializing Proxy Manager (Client Side)",
		"type", cfg.Type,
		"url", cfg.URL,
		"wpad_url", cfg.WpadURL)

	connectTimeout := time.Duration(cfg.ConnectionTimeout) * time.Second
	pacExecTimeout := time.Duration(cfg.PacExecutionTimeout) * time.Second

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
			pacExecTimeout: pacExecTimeout,
		},
		pacEngine: engine,
		httpClientForPAC: &http.Client{
			Transport: pacTransport,
			Timeout:   connectTimeout,
		},
	}

	if err := pm.updateProxySettings(true); err != nil {
		slog.Error("Initial proxy settings update failed, proxy functionality may be impaired", "error", err)
	}

	if strings.ToLower(pm.config.Type) == "wpad" {
		pm.wg.Add(1)
		go pm.wpadRefresher()
	}

	return pm, nil
}

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
				if scheme == "" {
					scheme = "http"
				}
				host := parsedURL.Host
				if host == "" {
					wpadErr = fmt.Errorf("proxy URL missing host:port: %s", pm.config.URL)
					newDefaultResult = pac.PacResult{Type: pac.ResultUnknown}
				} else {
					if !strings.Contains(host, ":") {
						if scheme == "https" {
							host = net.JoinHostPort(host, "443")
						} else {
							host = net.JoinHostPort(host, "80")
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
			needsFetch := initial || time.Now().After(pm.wpadCacheExpiry) || pm.wpadPacScript == ""

			if needsFetch {
				slog.Info("Fetching/Refreshing WPAD PAC script", "url", pm.config.WpadURL, "force", initial)
				scriptContent, fetchErr := pm.fetchPACScript(pm.config.WpadURL)
				if fetchErr != nil {
					wpadErr = fmt.Errorf("failed to fetch PAC script from %s: %w", pm.config.WpadURL, fetchErr)
					slog.Warn("Failed to fetch new PAC script, using previously cached script (if any)", "error", wpadErr)
					fetchedScriptContent = pm.wpadPacScript
				} else {
					fetchedScriptContent = scriptContent
					pm.wpadPacScript = scriptContent
					pm.wpadCacheExpiry = time.Now().Add(wpadCacheDuration)
					slog.Info("Successfully fetched and cached new PAC script.", "expiry", pm.wpadCacheExpiry.Format(time.RFC3339))
				}
			} else {
				slog.Debug("Using cached WPAD PAC script content.", "expiry", pm.wpadCacheExpiry.Format(time.RFC3339))
				fetchedScriptContent = pm.wpadPacScript
			}

			if fetchedScriptContent == "" {
				slog.Warn("WPAD PAC script content is empty (fetch failed or empty file?), assuming DIRECT as default")
				newDefaultResult = pac.PacResult{Type: pac.ResultDirect}
			} else {
				dummyURL := "http://example.com"
				dummyHost := "example.com"
				slog.Debug("Evaluating PAC script for default proxy", "dummy_url", dummyURL)

				ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout)

				resultString, execErr := pm.pacEngine.FindProxyForURL(ctx, fetchedScriptContent, dummyURL, dummyHost)
				cancel()

				if execErr != nil {
					wpadErr = fmt.Errorf("initial PAC script execution failed for dummy URL: %w", execErr)
					slog.Warn("Failed to evaluate PAC for default, retaining previous default setting (if any)", "error", wpadErr)
					newDefaultResult = pm.effectiveProxy
				} else {
					newDefaultResult = pac.ParseResult(resultString)
					slog.Debug("PAC default evaluation result", "result_string", resultString, "parsed_type", newDefaultResult.Type)
				}
			}
		}
	case "none":
		newDefaultResult = pac.PacResult{Type: pac.ResultDirect}
	default:
		wpadErr = fmt.Errorf("unsupported proxy type: %s", pm.config.Type)
		newDefaultResult = pac.PacResult{Type: pac.ResultUnknown}
	}

	if wpadErr != nil {
		slog.Error("Error determining effective proxy setting", "type", proxyType, "error", wpadErr)
		if pm.effectiveProxy.Type != pac.ResultUnknown {
			slog.Warn("Updating effective proxy state to Unknown/Error")
			pm.effectiveProxy = pac.PacResult{Type: pac.ResultUnknown}
		}
		return wpadErr
	}

	changed := !reflectDeepEqualPacResult(pm.effectiveProxy, newDefaultResult)

	if changed {
		logProxies := pac.UrlsFromPacResult(newDefaultResult)
		slog.Info("Effective default proxy setting changed",
			"old_type", pm.effectiveProxy.Type, "old_proxies", UrlsToStrings(pac.UrlsFromPacResult(pm.effectiveProxy)),
			"new_type", newDefaultResult.Type, "new_proxies", UrlsToStrings(logProxies))
		pm.effectiveProxy = newDefaultResult
	} else {
		slog.Debug("Effective default proxy setting remains unchanged.")
	}

	return nil
}

func (pm *ProxyManager) GetEffectiveProxyForURL(targetURL *url.URL) (pac.PacResult, error) {
	if targetURL == nil {
		return pac.PacResult{Type: pac.ResultUnknown}, errors.New("targetURL cannot be nil")
	}

	pm.proxyMutex.RLock()
	proxyType := strings.ToLower(pm.config.Type)
	scriptContent := pm.wpadPacScript
	staticResult := pm.effectiveProxy
	pm.proxyMutex.RUnlock()

	switch proxyType {
	case "http", "https":
		if staticResult.Type == pac.ResultUnknown {
			return staticResult, errors.New("proxy statically configured but is in error state")
		}
		slog.Debug("Using static proxy setting for URL", "url", targetURL, "proxy_type", staticResult.Type, "proxies", UrlsToStrings(pac.UrlsFromPacResult(staticResult)))
		return staticResult, nil
	case "none":
		slog.Debug("Using DIRECT connection for URL (type=none)", "url", targetURL)
		return pac.PacResult{Type: pac.ResultDirect}, nil
	case "wpad":
		if scriptContent == "" {
			slog.Warn("WPAD mode active, but no PAC script content available, falling back to default", "url", targetURL, "default_type", staticResult.Type)
			if staticResult.Type == pac.ResultUnknown {
				return staticResult, errors.New("WPAD mode active, but PAC script unavailable and no valid default")
			}
			return staticResult, nil
		}

		slog.Debug("Evaluating WPAD PAC script for URL", "url", targetURL.String())
		ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.pacExecTimeout)
		defer cancel()

		resultString, err := pm.pacEngine.FindProxyForURL(ctx, scriptContent, targetURL.String(), targetURL.Hostname())
		if err != nil {
			slog.Error("PAC script execution failed for URL", "url", targetURL.String(), "error", err)
			return pac.PacResult{Type: pac.ResultUnknown}, fmt.Errorf("PAC script execution failed: %w", err)
		}

		parsedResult := pac.ParseResult(resultString)
		slog.Debug("PAC execution result for URL", "target_url", targetURL.String(), "result_string", resultString, "parsed_type", parsedResult.Type, "parsed_proxies", UrlsToStrings(pac.UrlsFromPacResult(parsedResult)))

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

func (pm *ProxyManager) GetEffectiveProxyURL() *url.URL {
	pm.proxyMutex.RLock()
	defer pm.proxyMutex.RUnlock()

	if pm.effectiveProxy.Type == pac.ResultProxy && len(pm.effectiveProxy.Proxies) > 0 {
		u, err := pm.effectiveProxy.Proxies[0].URL()
		if err == nil {
			return u
		}
		slog.Warn("Failed to convert default ProxyInfo back to url.URL", "proxy", pm.effectiveProxy.Proxies[0], "error", err)
	}
	return nil
}

func (pm *ProxyManager) wpadRefresher() {
	defer pm.wg.Done()

	baseInterval := wpadCacheDuration
	minInterval := baseInterval - (5 * time.Minute)
	if minInterval <= 0 {
		minInterval = baseInterval / 2
	}
	jitterRange := (10 * time.Minute).Nanoseconds()
	interval := minInterval + time.Duration(rand.Int63n(jitterRange))
	if interval <= 0 {
		interval = 30 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("Starting WPAD refresh background task", "initial_interval", interval)
	for {
		select {
		case <-ticker.C:
			slog.Debug("Performing periodic WPAD refresh...")
			if err := pm.updateProxySettings(false); err != nil {
				slog.Error("Error during periodic WPAD refresh", "error", err)
			}
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

func (pm *ProxyManager) fetchPACScript(location string) (string, error) {
	slog.Debug("Attempting to fetch PAC script", "location", location)
	var contentBytes []byte
	var err error
	var contentType string

	parsedURL, urlErr := url.Parse(location)

	if urlErr == nil && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https") {
		ctx, cancel := context.WithTimeout(context.Background(), pm.retryConfig.connectTimeout)
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
			bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return "", fmt.Errorf("failed to fetch PAC from %s: status %s, body: %s", location, resp.Status, string(bodyPreview))
		}

		contentType = resp.Header.Get("Content-Type")
		limitedReader := io.LimitReader(resp.Body, pacMaxSizeBytes)
		contentBytes, err = io.ReadAll(limitedReader)
		if err != nil {
			return "", fmt.Errorf("failed to read PAC content from %s: %w", location, err)
		}
		if int64(len(contentBytes)) >= pacMaxSizeBytes {
			_, errPeek := resp.Body.Read(make([]byte, 1))
			if errPeek != io.EOF {
				return "", fmt.Errorf("PAC script %s exceeds maximum size limit (%d bytes)", location, pacMaxSizeBytes)
			}
		}

		slog.Debug("Fetched PAC script via HTTP(S)", "url", location, "size", len(contentBytes))

	} else {
		filePath := location
		if urlErr == nil && parsedURL.Scheme == "file" {
			filePath = parsedURL.Path
			if os.PathSeparator == '\\' && strings.HasPrefix(filePath, "/") {
				filePath = strings.TrimPrefix(filePath, "/")
				filePath = filepath.FromSlash(filePath)
			}
		}
		filePath = filepath.Clean(filePath)

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
		contentType = ""
	}

	reader := bytes.NewReader(contentBytes)
	var specifiedCharset string
	if pm.config.PacCharset != "" {
		specifiedCharset = pm.config.PacCharset
		slog.Debug("Using PAC charset specified in config", "charset", specifiedCharset)
	} else if contentType != "" {
		if parts := strings.Split(contentType, "charset="); len(parts) == 2 {
			specifiedCharset = strings.TrimSpace(parts[1])
			slog.Debug("Detected PAC charset from Content-Type", "charset", specifiedCharset)
		}
	}

	var finalReader io.Reader = reader
	specifiedCharset = strings.ToLower(strings.TrimSpace(specifiedCharset))

	if specifiedCharset != "" && specifiedCharset != "utf-8" && specifiedCharset != "utf8" {
		encoding, _ := charset.Lookup(specifiedCharset)
		if encoding == nil {
			slog.Warn("Unsupported PAC charset specified or detected, falling back to UTF-8", "charset", specifiedCharset)
		} else {
			slog.Debug("Decoding PAC script content", "charset", specifiedCharset)
			finalReader = transform.NewReader(reader, encoding.NewDecoder())
		}
	} else {
		slog.Debug("Assuming PAC script is UTF-8 (no specific charset detected/configured or explicitly UTF-8)")
	}

	decodedBytes, err := io.ReadAll(finalReader)
	if err != nil {
		return "", fmt.Errorf("failed to decode PAC content (charset: %s): %w", specifiedCharset, err)
	}

	if !utf8.Valid(decodedBytes) {
		slog.Warn("PAC content is not valid UTF-8 after decoding attempt, forcing conversion", "location", location)
		validUTF8String := strings.ToValidUTF8(string(decodedBytes), string(utf8.RuneError))
		return validUTF8String, nil
	}

	return string(decodedBytes), nil
}

func (pm *ProxyManager) Close() error {
	slog.Info("Closing Proxy Manager (Client Side)...")
	pm.stopOnce.Do(func() {
		close(pm.stopChan)
		if pm.pacEngine != nil {
			pm.pacEngine.Close()
		}
		if pm.httpClientForPAC != nil && pm.httpClientForPAC.Transport != nil {
			if transport, ok := pm.httpClientForPAC.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}
		pm.wg.Wait()
	})
	slog.Info("Proxy Manager closed.")
	return nil
}

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

func reflectDeepEqualPacResult(a, b pac.PacResult) bool {
	if a.Type != b.Type {
		return false
	}
	if !reflect.DeepEqual(a.Proxies, b.Proxies) {
		return false
	}
	return true
}
