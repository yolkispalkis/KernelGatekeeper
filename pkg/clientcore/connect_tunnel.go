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
	"time"

	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/kerb"
)

var ClientVersion = "dev" // Placeholder, inject actual version

func establishConnectTunnel(ctx context.Context, proxyConn net.Conn, targetAddr string, krbClient *kerb.KerberosClient) error {
	logCtx := slog.With("target_addr", targetAddr, "proxy_host", proxyConn.RemoteAddr().String())
	logCtx.Debug("Establishing CONNECT tunnel")

	var resp *http.Response
	var lastErr error

	connectCtx, cancel := context.WithTimeout(ctx, proxyCONNECTTimeout)
	defer cancel()

	for attempt := 1; attempt <= 2; attempt++ {
		select {
		case <-connectCtx.Done():
			err := ctx.Err()
			if err == nil {
				err = connectCtx.Err()
			}
			return fmt.Errorf("connect tunnel cancelled or timeout exceeded before attempt %d: %w", attempt, err)
		default:
		}

		logCtx.Debug("CONNECT attempt", "attempt", attempt)
		connectReq, err := http.NewRequestWithContext(connectCtx, "CONNECT", "http://"+targetAddr, nil)
		if err != nil {
			return fmt.Errorf("failed to create CONNECT request object: %w", err)
		}
		connectReq.Host = targetAddr
		connectReq.URL = &url.URL{Opaque: targetAddr} // Use Opaque as per RFC 7231 CONNECT

		connectReq.Header.Set("User-Agent", fmt.Sprintf("KernelGatekeeper-Client/%s", ClientVersion))
		connectReq.Header.Set("Proxy-Connection", "Keep-Alive")
		connectReq.Header.Set("Connection", "Keep-Alive")

		useKerberos := krbClient != nil && attempt > 1

		if useKerberos {
			if refreshErr := krbClient.CheckAndRefreshClient(); refreshErr != nil {
				logCtx.Error("Kerberos CheckAndRefreshClient failed unexpectedly, cannot authenticate", "error", refreshErr)
				lastErr = fmt.Errorf("kerberos refresh attempt failed: %w", refreshErr)
				// Continue without auth header, but store error. Proxy might allow fallback.
			} else if krbClient.IsInitialized() {
				gokrbCl := krbClient.Gokrb5Client()
				if gokrbCl == nil {
					lastErr = errors.New("internal kerberos error: client is initialized but Gokrb5Client() returned nil")
					logCtx.Error("Cannot add SPNEGO header", "error", lastErr)
					// Continue without auth header
				} else {
					spn := "" // Let gokrb5 determine SPN
					logCtx.Debug("Attempting to set SPNEGO header", "spn_hint", spn)
					spnegoErr := spnego.SetSPNEGOHeader(gokrbCl, connectReq, spn)

					if spnegoErr != nil {
						lastErr = fmt.Errorf("failed to set SPNEGO header on attempt %d: %w", attempt, spnegoErr)
						logCtx.Error("SPNEGO header generation failed on retry attempt", "error", lastErr)
						// Continue without auth header
					} else if connectReq.Header.Get("Proxy-Authorization") != "" {
						logCtx.Debug("SPNEGO Proxy-Authorization header added", "attempt", attempt)
						lastErr = nil // Clear previous non-fatal errors if header was successfully added
					} else {
						lastErr = errors.New("failed to generate SPNEGO token for Proxy-Authorization header")
						logCtx.Warn("SPNEGO did not add Proxy-Authorization header on retry attempt", "error", lastErr)
						// Continue without auth header
					}
				}
			} else {
				logCtx.Warn("Cannot add SPNEGO header: Kerberos client is not initialized (no valid ticket found). Proceeding without auth header.")
				if lastErr == nil {
					lastErr = errors.New("kerberos ticket not available for authentication")
				}
			}
		} else if krbClient == nil && attempt > 1 {
			logCtx.Error("Received 407 Proxy Authentication Required, but Kerberos client is not available.")
			if lastErr == nil {
				lastErr = errors.New("proxy authentication required, but Kerberos is not configured/initialized")
			}
			return lastErr // Cannot authenticate
		}

		// Send request
		if err := proxyConn.SetWriteDeadline(time.Now().Add(proxyConnectDialTimeout)); err != nil {
			logCtx.Warn("Failed to set write deadline for CONNECT request", "error", err)
		}
		writeErr := connectReq.Write(proxyConn)
		proxyConn.SetWriteDeadline(time.Time{}) // Clear deadline immediately

		if writeErr != nil {
			if errors.Is(writeErr, context.Canceled) || errors.Is(writeErr, context.DeadlineExceeded) {
				return fmt.Errorf("CONNECT write cancelled or timed out (attempt %d): %w", attempt, writeErr)
			}
			if common.IsConnectionClosedErr(writeErr) {
				return fmt.Errorf("proxy connection closed before/during writing CONNECT (attempt %d): %w", attempt, writeErr)
			}
			return fmt.Errorf("failed to send CONNECT request (attempt %d): %w", attempt, writeErr)
		}
		logCtx.Debug("CONNECT request sent", "attempt", attempt)

		// Read response
		proxyReader := bufio.NewReader(proxyConn)
		readDeadline := time.Now().Add(proxyCONNECTTimeout / 2) // Allow reasonable time for response
		if err := proxyConn.SetReadDeadline(readDeadline); err != nil {
			logCtx.Warn("Failed to set read deadline for CONNECT response", "error", err)
		}
		readRespErr := errors.New("proxy read response placeholder error") // Placeholder
		resp, readRespErr = http.ReadResponse(proxyReader, connectReq)
		proxyConn.SetReadDeadline(time.Time{}) // Clear deadline immediately

		// Handle errors during read *after* checking resp
		if readRespErr != nil {
			if errors.Is(readRespErr, context.Canceled) || errors.Is(readRespErr, context.DeadlineExceeded) || common.IsTimeoutError(readRespErr) {
				logCtx.Error("Timeout or cancellation reading CONNECT response", "attempt", attempt, "error", readRespErr)
				return fmt.Errorf("CONNECT read cancelled or timed out (attempt %d): %w", attempt, readRespErr)
			}
			if common.IsConnectionClosedErr(readRespErr) {
				logCtx.Error("Proxy closed connection unexpectedly after CONNECT request", "attempt", attempt, "error", readRespErr)
				return fmt.Errorf("proxy connection closed while reading response (attempt %d): %w", attempt, readRespErr)
			}
			logCtx.Error("Failed to read CONNECT response", "attempt", attempt, "error", readRespErr)
			return fmt.Errorf("failed reading CONNECT response (attempt %d): %w", attempt, readRespErr)
		}

		// Response received, process it
		logCtx.Debug("Received CONNECT response", "attempt", attempt, "status", resp.StatusCode)
		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body) // Consume and discard any body
			resp.Body.Close()
		}

		if resp.StatusCode == http.StatusOK {
			logCtx.Debug("CONNECT tunnel established successfully")
			return nil // Success
		}

		if resp.StatusCode == http.StatusProxyAuthRequired {
			if attempt == 1 {
				if krbClient != nil {
					logCtx.Info("Received 407 Proxy Authentication Required, will retry with Kerberos auth.")
					lastErr = fmt.Errorf("proxy authentication required (%s)", resp.Status)
					continue // Go to next attempt
				} else {
					logCtx.Error("Received 407 Proxy Authentication Required, but Kerberos support is not available.")
					lastErr = fmt.Errorf("proxy authentication required (%s), but Kerberos unavailable", resp.Status)
					return lastErr // Cannot authenticate
				}
			} else { // attempt == 2
				logCtx.Error("Received 407 Proxy Authentication Required even after attempting Kerberos auth.")
				if lastErr == nil { // If Kerberos attempt didn't set an error (e.g., ticket was valid but rejected)
					lastErr = fmt.Errorf("proxy authentication failed (%s) despite Kerberos attempt", resp.Status)
				} else { // Combine Kerberos issue with 407
					lastErr = fmt.Errorf("proxy authentication failed (%s) after Kerberos issue: %w", resp.Status, lastErr)
				}
				return lastErr // Authentication failed
			}
		}

		// Other error status codes
		errMsg := fmt.Sprintf("proxy CONNECT request failed: %s", resp.Status)
		logCtx.Error("Proxy returned error for CONNECT", "status", resp.Status)
		lastErr = errors.New(errMsg)
		return lastErr // Other proxy error
	}

	// Should not be reached if loop logic is correct, but acts as a fallback
	if lastErr == nil {
		lastErr = errors.New("failed to establish CONNECT tunnel after maximum attempts")
	}
	return lastErr
}
