package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackwakefield/gopac"
	"golang.org/x/net/html/charset"
	"golang.org/x/sync/singleflight"
	"golang.org/x/text/transform"
)

const (
	defaultPacFileTTL = 60 * time.Second

	defaultPacFileTimeout = 5 * time.Second

	pacMaxSizeBytes = 1 * 1024 * 1024
)

type PacParser struct {
	parserPool          *sync.Pool
	singleflightGroup   singleflight.Group
	pacFileURI          *url.URL
	pacFileTTL          time.Duration
	pacFileFetchTimeout time.Duration
	pacCharset          string
	lastUpdate          time.Time
	lastPacContent      []byte
	lastModifiedHeader  string
	httpClient          *http.Client
	mu                  sync.RWMutex
	lastError           error
}

func NewPacParser(uri *url.URL, fetchTimeout, ttl time.Duration, pacCharset string) (*PacParser, error) {
	if uri == nil {
		return nil, errors.New("PAC file URI cannot be nil")
	}

	if ttl <= 0 {
		ttl = defaultPacFileTTL
	}
	if fetchTimeout <= 0 {
		fetchTimeout = defaultPacFileTimeout
	}

	httpClient := &http.Client{
		Timeout: fetchTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   fetchTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          5,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	p := &PacParser{
		pacFileURI:          uri,
		pacFileTTL:          ttl,
		pacFileFetchTimeout: fetchTimeout,
		pacCharset:          pacCharset,
		httpClient:          httpClient,
		parserPool:          &sync.Pool{},
	}

	_, err, _ := p.singleflightGroup.Do("initial-fetch", p.refreshPacFile)
	if err != nil {

		slog.Error("Initial PAC file fetch/parse failed", "uri", p.pacFileURI.String(), "error", err)
		p.lastError = err

	} else {
		slog.Info("Initial PAC file fetched and parsed successfully", "uri", p.pacFileURI.String())
	}

	return p, nil
}

func (p *PacParser) createPacParserInstance(pacFileContent []byte) (*gopac.Parser, error) {
	if len(pacFileContent) == 0 {
		return nil, errors.New("PAC file content is empty")
	}

	pacString := string(pacFileContent)

	// Use NewParser instead of New
	parser, err := gopac.NewParser(pacString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PAC script: %w", err)
	}
	return parser, nil
}

func (p *PacParser) mustRefresh() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.lastUpdate.IsZero() || time.Since(p.lastUpdate) > p.pacFileTTL
}

func (p *PacParser) refreshPacFile() (interface{}, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.lastUpdate.IsZero() && time.Since(p.lastUpdate) <= p.pacFileTTL {
		slog.Debug("PAC refresh skipped, TTL still valid within lock", "uri", p.pacFileURI)

		slog.Warn("Unexpected state: refreshPacFile called but TTL check inside lock passed.")
	}

	slog.Debug("Attempting to refresh PAC file", "uri", p.pacFileURI.String())
	newContent, newLastModified, err := p.fetchPACScriptContent(p.lastModifiedHeader)
	if err != nil {

		p.lastUpdate = time.Now()
		p.lastError = err
		slog.Error("Failed to fetch PAC file, keeping previous version (if any)", "uri", p.pacFileURI.String(), "error", err)

		return nil, err
	}

	if newContent == nil {
		slog.Debug("PAC file content unchanged based on 304/mtime, reusing existing parser pool", "uri", p.pacFileURI.String())
		p.lastUpdate = time.Now()

		p.lastError = nil

		parser, parseErr := p.createPacParserInstance(p.lastPacContent)
		if parseErr != nil {
			p.lastError = parseErr
			slog.Error("Failed to parse existing PAC file content after 304/mtime check (should not happen!)", "uri", p.pacFileURI.String(), "error", parseErr)
			return nil, parseErr
		}
		return parser, nil
	}

	if bytes.Equal(p.lastPacContent, newContent) && len(p.lastPacContent) > 0 {
		slog.Debug("PAC file content fetched but unchanged from previous version, reusing existing parser pool", "uri", p.pacFileURI.String())
		p.lastUpdate = time.Now()
		p.lastModifiedHeader = newLastModified
		p.lastError = nil

		newParser, parseErr := p.createPacParserInstance(newContent)
		if parseErr != nil {
			p.lastError = parseErr
			slog.Error("Failed to parse unchanged PAC file (should not happen)", "uri", p.pacFileURI.String(), "error", parseErr)
			return nil, parseErr
		}
		return newParser, nil
	}

	slog.Info("PAC file content changed (or first fetch), creating new parser instance", "uri", p.pacFileURI.String(), "size", len(newContent))

	newParser, parseErr := p.createPacParserInstance(newContent)
	if parseErr != nil {

		p.lastUpdate = time.Now()
		p.lastError = parseErr
		slog.Error("Failed to parse new PAC file content, previous version (if any) might be used", "uri", p.pacFileURI.String(), "error", parseErr)

		return nil, parseErr
	}

	p.lastPacContent = newContent
	p.lastModifiedHeader = newLastModified
	p.lastUpdate = time.Now()
	p.lastError = nil

	p.parserPool = &sync.Pool{
		New: func() interface{} {

			p.mu.RLock()
			content := p.lastPacContent
			p.mu.RUnlock()
			parser, err := p.createPacParserInstance(content)
			if err != nil {

				slog.Error("Failed to create new PAC parser instance for pool", "uri", p.pacFileURI.String(), "error", err)
				return nil
			}
			return parser
		},
	}

	p.parserPool.Put(newParser)

	slog.Debug("New PAC parser created and pool reset", "uri", p.pacFileURI.String())
	return newParser, nil
}

func (p *PacParser) FindProxy(targetURL *url.URL) (string, error) {
	if p.pacFileURI == nil {
		slog.Debug("No PAC file configured, returning DIRECT")
		return proxyDirect, nil
	}

	host := targetURL.Hostname()
	urlString := targetURL.String()

	if p.mustRefresh() {

		_, err, shared := p.singleflightGroup.Do(p.pacFileURI.String(), p.refreshPacFile)
		if err != nil {
			slog.Warn("Failed to refresh PAC file, attempting fallback", "uri", p.pacFileURI.String(), "error", err, "shared_call", shared)

			parserInstance := p.parserPool.Get()
			if parserInstance == nil {
				slog.Error("PAC refresh failed and no previous parser available in pool", "uri", p.pacFileURI.String())

				p.mu.RLock()
				lastErr := p.lastError
				p.mu.RUnlock()
				if lastErr != nil {
					return "", fmt.Errorf("PAC unavailable: %w", lastErr)
				}
				return "", errors.New("PAC unavailable and no previous parser found")
			}

			parser := parserInstance.(*gopac.Parser)
			result, evalErr := parser.FindProxy(urlString, host)
			p.parserPool.Put(parserInstance)
			if evalErr != nil {
				slog.Error("Error executing fallback PAC script", "url", urlString, "host", host, "error", evalErr)

				return "", fmt.Errorf("PAC fallback execution failed: %w", evalErr)
			}
			slog.Debug("Using fallback PAC result", "url", urlString, "host", host, "result", result)
			return result, nil
		}
		slog.Debug("PAC file refreshed successfully or refresh was handled by another call", "uri", p.pacFileURI.String(), "shared_call", shared)

	}

	parserInstance := p.parserPool.Get()
	if parserInstance == nil {

		slog.Error("Failed to get PAC parser instance from pool", "uri", p.pacFileURI.String())
		p.mu.RLock()
		lastErr := p.lastError
		p.mu.RUnlock()
		if lastErr != nil {
			return "", fmt.Errorf("PAC unavailable: %w", lastErr)
		}
		return "", errors.New("PAC parser instance unavailable from pool")
	}

	parser := parserInstance.(*gopac.Parser)
	result, err := parser.FindProxy(urlString, host)
	p.parserPool.Put(parserInstance)

	if err != nil {
		slog.Error("Error executing PAC script", "url", urlString, "host", host, "error", err)

		return "", fmt.Errorf("PAC execution failed: %w", err)
	}

	slog.Debug("PAC evaluation result", "url", urlString, "host", host, "result", result)
	return result, nil
}

func (p *PacParser) fetchPACScriptContent(lastModified string) ([]byte, string, error) {
	var contentBytes []byte
	var err error
	var newLastModified string
	var contentType string

	uriString := p.pacFileURI.String()
	slog.Debug("Fetching PAC script", "uri", uriString, "if-modified-since", lastModified)

	switch p.pacFileURI.Scheme {
	case "http", "https":
		req, err := http.NewRequest("GET", uriString, nil)
		if err != nil {
			return nil, lastModified, fmt.Errorf("failed to create PAC request: %w", err)
		}
		req.Header.Set("User-Agent", "KernelGatekeeper-Client/PAC-Fetcher")
		if lastModified != "" {
			req.Header.Set("If-Modified-Since", lastModified)
		}

		resp, err := p.httpClient.Do(req)
		if err != nil {
			return nil, lastModified, fmt.Errorf("failed to fetch PAC file from %s: %w", uriString, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotModified {
			slog.Debug("PAC file not modified (304)", "uri", uriString)
			return nil, lastModified, nil
		}

		if resp.StatusCode != http.StatusOK {
			return nil, lastModified, fmt.Errorf("failed to fetch PAC file: %s returned status %s", uriString, resp.Status)
		}

		limitedReader := &io.LimitedReader{R: resp.Body, N: pacMaxSizeBytes}
		contentBytes, err = ioutil.ReadAll(limitedReader)
		if err != nil {
			return nil, lastModified, fmt.Errorf("failed to read PAC response body: %w", err)
		}

		if limitedReader.N == 0 {

			n, _ := io.ReadFull(resp.Body, make([]byte, 1))
			if n > 0 {
				return nil, lastModified, fmt.Errorf("PAC file size exceeds limit (%d bytes)", pacMaxSizeBytes)
			}
		}

		newLastModified = resp.Header.Get("Last-Modified")
		contentType = resp.Header.Get("Content-Type")

	case "file":
		filePath := p.pacFileURI.Path

		if strings.HasPrefix(filePath, "/") && len(filePath) > 2 && filePath[2] == ':' {
			filePath = filePath[1:]
		}
		filePath = filepath.Clean(filePath)

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, lastModified, fmt.Errorf("failed to stat PAC file %s: %w", filePath, err)
		}
		modTimeStr := fileInfo.ModTime().UTC().Format(http.TimeFormat)
		if modTimeStr == lastModified && lastModified != "" {
			slog.Debug("PAC file not modified (mtime)", "path", filePath)
			return nil, lastModified, nil
		}

		contentBytes, err = ioutil.ReadFile(filePath)
		if err != nil {
			return nil, modTimeStr, fmt.Errorf("failed to read PAC file %s: %w", filePath, err)
		}
		newLastModified = modTimeStr
		contentType = ""

	default:
		return nil, lastModified, fmt.Errorf("unsupported PAC file scheme: %s", p.pacFileURI.Scheme)
	}

	finalBytes, err := decodeBytesWithCharset(contentBytes, contentType, p.pacCharset)
	if err != nil {

		slog.Warn("Failed to decode PAC content with specified/detected charset, using raw bytes", "uri", uriString, "error", err)
		return contentBytes, newLastModified, nil
	}

	if !utf8.Valid(finalBytes) {
		slog.Warn("PAC content is not valid UTF-8 after decoding, potential issues parsing", "uri", uriString)

	}

	return finalBytes, newLastModified, nil
}

func decodeBytesWithCharset(rawBytes []byte, contentTypeHeader string, charsetOverride string) ([]byte, error) {
	if len(rawBytes) == 0 {
		return rawBytes, nil
	}

	var encodingName string = "utf-8"

	if charsetOverride != "" {
		encodingName = charsetOverride
		slog.Debug("Using charset from config override", "charset", encodingName)
	} else if contentTypeHeader != "" {

		_, params, err := mime.ParseMediaType(contentTypeHeader)

		if err == nil {
			if name, ok := params["charset"]; ok {
				encodingName = name
				slog.Debug("Using charset from Content-Type header", "charset", encodingName, "header", contentTypeHeader)
			} else {
				slog.Debug("No charset parameter found in Content-Type header, assuming UTF-8.", "header", contentTypeHeader)
			}
		} else {
			slog.Warn("Failed to parse Content-Type header, assuming UTF-8.", "header", contentTypeHeader, "error", err)
		}
	}

	if charsetOverride == "" && (contentTypeHeader == "" || !strings.Contains(strings.ToLower(contentTypeHeader), "charset=")) {

		// Correctly capture encoding, name, and certainty. charset.DetermineEncoding does not return an error.
		_, detectedName, certain := charset.DetermineEncoding(rawBytes, "")

		if certain { // Check the boolean directly
			encodingName = detectedName // Assign the detected name (string)
			slog.Debug("Detected charset from BOM with certainty", "charset", encodingName)

		} else {
			slog.Debug("No charset override, Content-Type, or certain BOM found. Assuming UTF-8.")
		}
	}

	encodingDef, _ := charset.Lookup(encodingName)
	if encodingDef == nil {

		slog.Warn("Unsupported or unknown charset specified/detected, falling back to UTF-8", "charset", encodingName)
		encodingDef, _ = charset.Lookup("utf-8")
		if encodingDef == nil {
			return nil, errors.New("critical: UTF-8 encoding not found")
		}
		encodingName = "utf-8"
	}

	if strings.ToLower(encodingName) == "utf-8" || strings.ToLower(encodingName) == "utf8" {
		slog.Debug("Charset is UTF-8, no transformation needed.")
		return rawBytes, nil
	}

	decoder := encodingDef.NewDecoder()

	decodedBytes, _, err := transform.Bytes(decoder, rawBytes)

	if err != nil {
		return nil, fmt.Errorf("failed to transform bytes from %s to UTF-8: %w", encodingName, err)
	}

	slog.Debug("Successfully decoded bytes to UTF-8", "original_charset", encodingName)
	return decodedBytes, nil
}
