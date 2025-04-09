package clientcore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/kerb"
)

var ClientVersion = "dev" // Injected during build

const (
	// Timeout for dialing the proxy server itself - make this configurable?
	// Using the constant from connection_handler for now.
	// proxyDialTimeout = 10 * time.Second

	// Max attempts for the CONNECT request (1st without auth, 2nd with if 407 received)
	maxConnectAttempts = 2
)

// establishConnectTunnel establishes a TCP tunnel via an HTTP/S proxy using CONNECT.
// It handles Kerberos/SPNEGO authentication if required by the proxy.
// It takes the specific proxyURL to connect to.
// Returns the established net.Conn to the proxy (ready for tunneling) or an error.
func establishConnectTunnel(ctx context.Context, proxyURL *url.URL, targetAddr string, krbClient *kerb.KerberosClient, logCtx *slog.Logger) (net.Conn, error) {

	var proxyConn net.Conn
	var err error

	// 1. Dial the proxy server
	dialer := net.Dialer{Timeout: proxyConnectDialTimeout} // Use timeout from handler const
	proxyConn, err = dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy server %s: %w", proxyURL.Host, err)
	}
	// Don't close proxyConn here, return it on success

	logCtx = logCtx.With("proxy_addr", proxyConn.RemoteAddr())
	logCtx.Debug("Connected to proxy server")

	var lastErr error
	for attempt := 1; attempt <= maxConnectAttempts; attempt++ {
		// Check context before each attempt
		if err := ctx.Err(); err != nil {
			proxyConn.Close()
			return nil, err // Context cancelled or deadline exceeded
		}

		logCtx.Debug("Sending CONNECT request", "target", targetAddr, "attempt", attempt)
		connectReq, err := http.NewRequestWithContext(ctx, "CONNECT", targetAddr, nil) // Use targetAddr directly
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to create CONNECT request: %w", err)
		}
		connectReq.Host = targetAddr // Host header should be the target destination
		connectReq.Header.Set("User-Agent", "KernelGatekeeper-Client/"+ClientVersion)
		connectReq.Header.Set("Proxy-Connection", "Keep-Alive") // Optional but common

		// --- Add Auth Header on Retry (Attempt 2) ---
		if attempt > 1 {
			if krbClient == nil {
				lastErr = errors.New("proxy authentication required, but Kerberos client is not available")
				logCtx.Warn(lastErr.Error())
				break // Exit loop, cannot authenticate
			}
			// Ensure ticket is fresh enough before attempting auth
			if err := krbClient.CheckAndRefreshClient(); err != nil {
				// Log error but potentially continue if ticket might still be barely valid?
				// Safer to break if refresh fails significantly.
				lastErr = fmt.Errorf("failed to refresh Kerberos ticket before auth: %w", err)
				logCtx.Error(lastErr.Error())
				break
			}
			if !krbClient.IsInitialized() {
				lastErr = errors.New("proxy authentication required, but Kerberos ticket is not initialized/valid")
				logCtx.Warn(lastErr.Error())
				break // Exit loop, cannot authenticate
			}

			spn := "" // Let gokrb5 determine SPN from proxy hostname usually (e.g., HTTP/proxy.host@REALM)
			// Construct SPNEGO token
			spnegoClient, err := spnego.NewClient(krbClient.Gokrb5Client(), nil, spn)
			if err != nil {
				lastErr = fmt.Errorf("failed to create SPNEGO client: %w", err)
				logCtx.Error(lastErr.Error())
				break // Cannot proceed with auth
			}
			err = spnegoClient.SetSPNEGOHeader(connectReq, "") // Initial token usually empty ""
			if err != nil {
				lastErr = fmt.Errorf("failed to set SPNEGO header: %w", err)
				logCtx.Error(lastErr.Error())
				break // Cannot proceed with auth
			}
			logCtx.Debug("Added Proxy-Authorization: Negotiate header")
		}

		// --- Send Request ---
		// Write request with timeout from context
		err = connectReq.Write(proxyConn)
		if err != nil {
			// Handle potential connection reset especially after 407 on retry
			if common.IsConnectionClosedErr(err) && attempt > 1 {
				lastErr = fmt.Errorf("proxy closed connection after auth attempt: %w", err)
				logCtx.Warn(lastErr.Error())
				// Optional: Could attempt redialing the proxy here before breaking?
				// For now, just break.
			} else {
				lastErr = fmt.Errorf("failed to write CONNECT request to proxy: %w", err)
			}
			break // Exit loop on write error
		}

		// --- Read Response ---
		// Read response with timeout from context
		resp, err := http.ReadResponse(bufio.NewReader(proxyConn), connectReq)
		if err != nil {
			// If we failed reading after sending auth, return the combined error
			if attempt > 1 {
				lastErr = fmt.Errorf("proxy auth attempt failed: error reading response: %w (previous error: %v)", err, lastErr)
			} else {
				lastErr = fmt.Errorf("failed to read CONNECT response from proxy: %w", err)
			}
			break // Exit loop on read error
		}
		defer resp.Body.Close()               // Ensure body is read and closed
		_, _ = io.Copy(io.Discard, resp.Body) // Consume any potential body

		// --- Process Response ---
		logCtx.Debug("Received CONNECT response", "status_code", resp.StatusCode)
		switch resp.StatusCode {
		case http.StatusOK: // 200 OK - Tunnel Established!
			logCtx.Info("CONNECT tunnel established successfully")
			return proxyConn, nil // Return the connection ready for relaying

		case http.StatusProxyAuthRequired: // 407 Proxy Authentication Required
			if attempt >= maxConnectAttempts {
				lastErr = errors.New("proxy authentication required, but max attempts reached or auth failed")
				logCtx.Warn(lastErr.Error())
				break // Exit loop
			}
			// Check for Negotiate support
			authHeader := resp.Header.Get("Proxy-Authenticate")
			if !strings.Contains(strings.ToLower(authHeader), "negotiate") {
				lastErr = fmt.Errorf("proxy requires authentication, but does not support Negotiate (Kerberos/SPNEGO). Supported: %s", authHeader)
				logCtx.Error(lastErr.Error())
				break // Exit loop, cannot authenticate with Kerberos
			}
			logCtx.Info("Proxy requires authentication (407), will attempt with Kerberos on next try")
			lastErr = errors.New("proxy authentication required (407)") // Store the 407 error
			// Continue loop for the next attempt (will add auth header)
			continue

		default: // Other Status Code
			lastErr = fmt.Errorf("proxy returned unexpected status code %d: %s", resp.StatusCode, resp.Status)
			logCtx.Error(lastErr.Error())
			break // Exit loop on unexpected status
		}
	} // End for loop

	// If loop finished without returning success
	proxyConn.Close() // Close the connection
	if lastErr != nil {
		return nil, lastErr // Return the last significant error
	}
	// Fallback error if loop finishes unexpectedly
	return nil, errors.New("failed to establish CONNECT tunnel after all attempts")
}
