package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
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
	// Default TTL for PAC file cache if not specified in config
	defaultPacFileTTL = 60 * time.Second
	// Default connection timeout for fetching PAC file
	defaultPacFileTimeout = 5 * time.Second
	// Max PAC file size to prevent loading huge files
	pacMaxSizeBytes = 1 * 1024 * 1024 // 1 MiB
)

// PacParser manages fetching, parsing, and executing PAC scripts using gopac.
type PacParser struct {
	parserPool          *sync.Pool // Pool of *gopac.Parser instances
	singleflightGroup   singleflight.Group
	pacFileURI          *url.URL // Location of the PAC file (http, https, file)
	pacFileTTL          time.Duration
	pacFileFetchTimeout time.Duration
	pacCharset          string // Optional charset override for PAC file content
	lastUpdate          time.Time
	lastPacContent      []byte       // Store raw bytes to detect actual content change
	lastModifiedHeader  string       // Store Last-Modified header for conditional fetching
	httpClient          *http.Client // Client for fetching PAC over HTTP/S
	mu                  sync.RWMutex // Protects lastUpdate, lastPacContent, lastModifiedHeader
	lastError           error        // Store last critical error (e.g., initial parse failure)
}

// NewPacParser creates and initializes a new PacParser.
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

	// HTTP client specifically for fetching PAC files (should not use system proxy)
	httpClient := &http.Client{
		Timeout: fetchTimeout, // Use fetch timeout for the whole request
		Transport: &http.Transport{
			Proxy: nil, // Explicitly disable proxying for PAC fetches
			DialContext: (&net.Dialer{
				Timeout:   fetchTimeout, // Also apply timeout to dialing phase
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
		pacFileFetchTimeout: fetchTimeout, // Store for potential future use maybe?
		pacCharset:          pacCharset,
		httpClient:          httpClient,
		parserPool:          &sync.Pool{}, // Initialize pool, will be populated on first fetch
	}

	// Perform initial fetch and parse to populate the pool and catch early errors.
	// We use singleflight here too, although less critical on init.
	// The result interface{} isn't strictly needed here, but we check the error.
	_, err, _ := p.singleflightGroup.Do("initial-fetch", p.refreshPacFile)
	if err != nil {
		// Log the error, but allow creation. findProxy will handle fallback.
		slog.Error("Initial PAC file fetch/parse failed", "uri", p.pacFileURI.String(), "error", err)
		p.lastError = err // Store the initial error
		// Don't populate the pool on initial error
	} else {
		slog.Info("Initial PAC file fetched and parsed successfully", "uri", p.pacFileURI.String())
	}

	return p, nil
}

// createPacParserInstance tries to parse the PAC script content.
func (p *PacParser) createPacParserInstance(pacFileContent []byte) (*gopac.Parser, error) {
	if len(pacFileContent) == 0 {
		return nil, errors.New("PAC file content is empty")
	}
	// gopac expects a string
	pacString := string(pacFileContent)

	parser, err := gopac.NewParser(pacString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PAC script: %w", err)
	}
	return parser, nil
}

// mustRefresh checks if the cached PAC file has expired based on its TTL.
func (p *PacParser) mustRefresh() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// Refresh if never updated or if TTL has passed
	return p.lastUpdate.IsZero() || time.Since(p.lastUpdate) > p.pacFileTTL
}

// refreshPacFile fetches and parses the PAC file if needed.
// Returns the *newly created* parser instance or an error.
// Designed to be used with singleflight.Group.
// The returned interface{} will be the *gopac.Parser.
func (p *PacParser) refreshPacFile() (interface{}, error) {
	p.mu.Lock() // Lock for write access to cache fields
	defer p.mu.Unlock()

	// Double-check TTL within the lock to avoid race after singleflight entry
	if !p.lastUpdate.IsZero() && time.Since(p.lastUpdate) <= p.pacFileTTL {
		slog.Debug("PAC refresh skipped, TTL still valid within lock", "uri", p.pacFileURI)
		// Need to return a valid parser instance. How?
		// If pool is empty, we have a problem. Assume pool has *something* if lastUpdate is non-zero.
		// This path should ideally not be hit due to the outer mustRefresh check.
		// If we *must* return a value, maybe return nil and let caller handle?
		// Let's return nil interface{} and a specific error indicating no refresh needed.
		// Or better: The singleflight.Do call only happens if mustRefresh was true.
		// So this code path implying valid TTL *should not happen*.
		// If it does, it's an unexpected state. Let's log and proceed with fetch.
		slog.Warn("Unexpected state: refreshPacFile called but TTL check inside lock passed.")
	}

	// Fetch PAC file content
	slog.Debug("Attempting to refresh PAC file", "uri", p.pacFileURI.String())
	newContent, newLastModified, err := p.fetchPACScriptContent(p.lastModifiedHeader)
	if err != nil {
		// Fetch failed. Keep old content and parser pool, update timestamp to avoid quick retries.
		p.lastUpdate = time.Now() // Mark attempt time
		p.lastError = err         // Store the fetch error
		slog.Error("Failed to fetch PAC file, keeping previous version (if any)", "uri", p.pacFileURI.String(), "error", err)
		// Do NOT clear the pool here. Fallback relies on the existing pool.
		return nil, err // Return the fetch error
	}

	// Check if content actually changed (or if it's the first time)
	if bytes.Equal(p.lastPacContent, newContent) && len(p.lastPacContent) > 0 {
		slog.Debug("PAC file content unchanged, reusing existing parser pool", "uri", p.pacFileURI.String())
		p.lastUpdate = time.Now()              // Update timestamp even if content is same
		p.lastModifiedHeader = newLastModified // Update header even if content same
		p.lastError = nil                      // Clear previous errors on successful check
		// We still need to return a parser instance.
		// Get one from the pool if possible, otherwise create a new one (should not happen ideally).
		// Since the pool wasn't cleared, Get should work if it was populated before.
		// Let FindProxy handle getting from pool. Here, return nil, nil signifies success but no *new* parser.
		// Let's adjust: create ONE new parser instance from current content and return it.
		// The pool itself isn't being actively managed *here*, only populated/cleared.
		newParser, parseErr := p.createPacParserInstance(newContent)
		if parseErr != nil {
			p.lastError = parseErr
			slog.Error("Failed to parse unchanged PAC file (should not happen)", "uri", p.pacFileURI.String(), "error", parseErr)
			return nil, parseErr // Return parsing error
		}
		return newParser, nil // Success, but content didn't change
	}

	slog.Info("PAC file content changed (or first fetch), creating new parser instance", "uri", p.pacFileURI.String(), "size", len(newContent))

	// Content changed, attempt to parse the new content
	newParser, parseErr := p.createPacParserInstance(newContent)
	if parseErr != nil {
		// Failed to parse new content. Keep old content/pool? Or clear?
		// Let's keep the old pool for fallback, but log error and update state.
		p.lastUpdate = time.Now() // Mark attempt time
		p.lastError = parseErr    // Store the parse error
		slog.Error("Failed to parse new PAC file content, previous version (if any) might be used", "uri", p.pacFileURI.String(), "error", parseErr)
		// Do NOT clear the pool.
		return nil, parseErr // Return the parse error
	}

	// Successfully parsed new content.
	// Update cache and clear the old parser pool.
	p.lastPacContent = newContent
	p.lastModifiedHeader = newLastModified
	p.lastUpdate = time.Now()
	p.lastError = nil // Clear previous errors

	// Clear the existing pool by creating a new empty one.
	// Old parsers will be garbage collected eventually.
	p.parserPool = &sync.Pool{
		New: func() interface{} {
			// The pool's New function should ideally create a parser from the *current* lastPacContent.
			// This ensures newly created items in the pool reflect the latest valid script.
			p.mu.RLock() // Need read lock to access lastPacContent safely
			content := p.lastPacContent
			p.mu.RUnlock()
			parser, err := p.createPacParserInstance(content)
			if err != nil {
				// This should not happen if the initial parse succeeded, but handle defensively.
				slog.Error("Failed to create new PAC parser instance for pool", "uri", p.pacFileURI.String(), "error", err)
				return nil // Indicate failure to create
			}
			return parser
		},
	}
	// Add the newly created parser to the pool so it's immediately available.
	p.parserPool.Put(newParser)

	slog.Debug("New PAC parser created and pool reset", "uri", p.pacFileURI.String())
	return newParser, nil // Return the newly created parser
}

// FindProxy evaluates the PAC script for the given URL and host.
// It handles refreshing the PAC file based on TTL.
func (p *PacParser) FindProxy(targetURL *url.URL) (string, error) {
	if p.pacFileURI == nil {
		slog.Debug("No PAC file configured, returning DIRECT")
		return proxyDirect, nil // No PAC file means DIRECT
	}

	host := targetURL.Hostname()
	urlString := targetURL.String()

	if p.mustRefresh() {
		// Use singleflight to ensure only one goroutine refreshes the file.
		// The returned 'v' is the *gopac.Parser instance (or nil on error).
		// 'err' is the error during fetch/parse.
		// 'shared' indicates if the result was shared from another concurrent call.
		_, err, shared := p.singleflightGroup.Do(p.pacFileURI.String(), p.refreshPacFile)
		if err != nil {
			slog.Warn("Failed to refresh PAC file, attempting fallback", "uri", p.pacFileURI.String(), "error", err, "shared_call", shared)
			// Fallback logic: Try to use an old parser from the pool.
			// If the pool is empty or Get fails, return error/DIRECT.
			parserInstance := p.parserPool.Get()
			if parserInstance == nil {
				slog.Error("PAC refresh failed and no previous parser available in pool", "uri", p.pacFileURI.String())
				// Maybe return DIRECT as ultimate fallback? Or the error?
				// Let's return the error that caused the refresh failure.
				p.mu.RLock()
				lastErr := p.lastError
				p.mu.RUnlock()
				if lastErr != nil {
					return "", fmt.Errorf("PAC unavailable: %w", lastErr)
				}
				return "", errors.New("PAC unavailable and no previous parser found")
			}
			// Use the old parser instance
			parser := parserInstance.(*gopac.Parser)
			result, evalErr := parser.FindProxy(urlString, host)
			p.parserPool.Put(parserInstance) // Put it back
			if evalErr != nil {
				slog.Error("Error executing fallback PAC script", "url", urlString, "host", host, "error", evalErr)
				// Fallback failed, return DIRECT? Or error?
				return "", fmt.Errorf("PAC fallback execution failed: %w", evalErr)
			}
			slog.Debug("Using fallback PAC result", "url", urlString, "host", host, "result", result)
			return result, nil // Return result from old parser
		}
		slog.Debug("PAC file refreshed successfully or refresh was handled by another call", "uri", p.pacFileURI.String(), "shared_call", shared)
		// Refresh successful (or done concurrently). Pool should be updated.
	}

	// Get a parser from the pool (should contain updated ones if refresh happened)
	parserInstance := p.parserPool.Get()
	if parserInstance == nil {
		// This might happen if the pool's New function failed, or if init failed badly.
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
	p.parserPool.Put(parserInstance) // Return parser to the pool

	if err != nil {
		slog.Error("Error executing PAC script", "url", urlString, "host", host, "error", err)
		// Decide on fallback behavior: return DIRECT or error?
		// Let's return an error indicating PAC execution failure.
		return "", fmt.Errorf("PAC execution failed: %w", err)
	}

	slog.Debug("PAC evaluation result", "url", urlString, "host", host, "result", result)
	return result, nil
}

// fetchPACScriptContent retrieves the PAC script content from HTTP/S or file URI.
// It uses the provided lastModified string for conditional HTTP GETs.
// Returns the content, the new Last-Modified header value, and error.
func (p *PacParser) fetchPACScriptContent(lastModified string) ([]byte, string, error) {
	var contentBytes []byte
	var err error
	var newLastModified string
	var contentType string // Store content type for charset detection

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

		// Handle "Not Modified"
		if resp.StatusCode == http.StatusNotModified {
			slog.Debug("PAC file not modified (304)", "uri", uriString)
			return nil, lastModified, nil // Return nil content to indicate no change
		}

		// Handle other non-OK statuses
		if resp.StatusCode != http.StatusOK {
			return nil, lastModified, fmt.Errorf("failed to fetch PAC file: %s returned status %s", uriString, resp.Status)
		}

		// Read response body with size limit
		limitedReader := &io.LimitedReader{R: resp.Body, N: pacMaxSizeBytes}
		contentBytes, err = ioutil.ReadAll(limitedReader)
		if err != nil {
			return nil, lastModified, fmt.Errorf("failed to read PAC response body: %w", err)
		}
		// Check if limit was actually hit
		if limitedReader.N == 0 {
			// Try reading one more byte to confirm
			n, _ := io.ReadFull(resp.Body, make([]byte, 1))
			if n > 0 {
				return nil, lastModified, fmt.Errorf("PAC file size exceeds limit (%d bytes)", pacMaxSizeBytes)
			}
		}

		newLastModified = resp.Header.Get("Last-Modified")
		contentType = resp.Header.Get("Content-Type")

	case "file":
		filePath := p.pacFileURI.Path
		// Handle potential Windows path conversion if needed (e.g., file:///C:/path)
		if strings.HasPrefix(filePath, "/") && len(filePath) > 2 && filePath[2] == ':' {
			filePath = filePath[1:] // Remove leading slash for paths like /C:/...
		}
		filePath = filepath.Clean(filePath)

		// Check file modification time for simple caching (less robust than HTTP ETag/Last-Modified)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, lastModified, fmt.Errorf("failed to stat PAC file %s: %w", filePath, err)
		}
		modTimeStr := fileInfo.ModTime().UTC().Format(http.TimeFormat)
		if modTimeStr == lastModified && lastModified != "" {
			slog.Debug("PAC file not modified (mtime)", "path", filePath)
			return nil, lastModified, nil // Return nil content to indicate no change
		}

		contentBytes, err = ioutil.ReadFile(filePath)
		if err != nil {
			return nil, modTimeStr, fmt.Errorf("failed to read PAC file %s: %w", filePath, err)
		}
		newLastModified = modTimeStr // Use modification time as the new "marker"
		contentType = ""             // No reliable content type for local files

	default:
		return nil, lastModified, fmt.Errorf("unsupported PAC file scheme: %s", p.pacFileURI.Scheme)
	}

	// --- Decode content based on charset ---
	finalBytes, err := decodeBytesWithCharset(contentBytes, contentType, p.pacCharset)
	if err != nil {
		// Log warning but return the raw bytes as fallback
		slog.Warn("Failed to decode PAC content with specified/detected charset, using raw bytes", "uri", uriString, "error", err)
		return contentBytes, newLastModified, nil // Return raw bytes on decode error
	}

	// Final check for UTF-8 validity after potential transformation
	if !utf8.Valid(finalBytes) {
		slog.Warn("PAC content is not valid UTF-8 after decoding, potential issues parsing", "uri", uriString)
		// Still return the bytes, gopac might handle it partially?
	}

	return finalBytes, newLastModified, nil
}

// decodeBytesWithCharset attempts to decode the byte slice using charset info.
func decodeBytesWithCharset(rawBytes []byte, contentTypeHeader string, charsetOverride string) ([]byte, error) {
	if len(rawBytes) == 0 {
		return rawBytes, nil
	}

	var encodingName string

	// 1. Use explicit override from config
	if charsetOverride != "" {
		encodingName = charsetOverride
		slog.Debug("Using charset from config override", "charset", encodingName)
	} else if contentTypeHeader != "" { // 2. Try Content-Type header
		_, encodingName, _ = charset.ParseMediaType(contentTypeHeader)
		slog.Debug("Using charset from Content-Type header", "charset", encodingName, "header", contentTypeHeader)
	} else { // 3. Detect from BOM (Byte Order Mark)
		encodingName, _ = charset.Lookup("utf-8") // Default assumption
		detectedEncoding, bomLength, err := charset.DetermineEncoding(rawBytes, "")
		if err == nil && bomLength > 0 {
			encodingName = detectedEncoding
			slog.Debug("Detected charset from BOM", "charset", encodingName)
			// Trim BOM if present
			rawBytes = rawBytes[bomLength:]
		} else {
			slog.Debug("No charset override, Content-Type, or BOM found. Assuming UTF-8.")
		}
	}

	// Get the encoding definition
	encoding, _ := charset.Lookup(encodingName)
	if encoding == nil {
		// If the specified/detected encoding is unknown or unsupported, default to UTF-8
		slog.Warn("Unsupported or unknown charset specified/detected, falling back to UTF-8", "charset", encodingName)
		encoding, _ = charset.Lookup("utf-8")
		if encoding == nil { // Should not happen for utf-8
			return nil, errors.New("critical: UTF-8 encoding not found")
		}
	}

	// If it's already UTF-8, no transformation needed
	if encoding == charset.Utf8 {
		slog.Debug("Charset is UTF-8, no transformation needed.")
		return rawBytes, nil
	}

	// Create a transformer to decode from the detected encoding to UTF-8
	decoder := encoding.NewDecoder()
	transformer := transform.Bytes(decoder)

	// Perform the transformation
	decodedBytes, _, err := transformer.Transform(rawBytes, true) // `true` indicates atEOF
	if err != nil {
		return nil, fmt.Errorf("failed to transform bytes from %s to UTF-8: %w", encodingName, err)
	}

	slog.Debug("Successfully decoded bytes to UTF-8", "original_charset", encodingName)
	return decodedBytes, nil
}
