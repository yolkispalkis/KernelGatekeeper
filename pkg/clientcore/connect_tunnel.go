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
	"time"

	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/kerb"
)

var ClientVersion = "dev" // Injected during build

const (
	maxConnectAttempts = 2 // Try once without auth, once with if needed
)

func establishConnectTunnel(ctx context.Context, proxyConn net.Conn, targetAddr string, krbClient *kerb.KerberosClient) error {
	logCtx := slog.With("target_addr", targetAddr, "proxy_host", proxyConn.RemoteAddr().String())
	logCtx.Debug("Establishing CONNECT tunnel")

	var resp *http.Response
	var lastErr error
	attempt := 1

	connectReq, err := http.NewRequestWithContext(ctx, "CONNECT", "http://"+targetAddr, nil)
	if err != nil {
		return fmt.Errorf("failed to create CONNECT request object: %w", err)
	}
	connectReq.Host = targetAddr
	connectReq.URL = &url.URL{Opaque: targetAddr}
	connectReq.Header.Set("User-Agent", fmt.Sprintf("KernelGatekeeper-Client/%s", ClientVersion))
	connectReq.Header.Set("Proxy-Connection", "Keep-Alive")
	connectReq.Header.Set("Connection", "Keep-Alive")

	proxyReader := bufio.NewReader(proxyConn)

	for ; attempt <= maxConnectAttempts; attempt++ {
		logCtx.Debug("CONNECT attempt", "attempt", attempt)

		select {
		case <-ctx.Done():
			logCtx.Warn("CONNECT cancelled before attempt", "attempt", attempt, "error", ctx.Err())
			return ctx.Err()
		default:
		}

		// --- Add Auth Header on Retry ---
		if attempt > 1 {
			if krbClient == nil {
				errMsg := "proxy authentication required (407 received), but Kerberos client is not configured"
				logCtx.Error(errMsg)
				if lastErr == nil || !strings.Contains(lastErr.Error(), "407") {
					lastErr = errors.New(errMsg)
				}
				return lastErr
			}

			if refreshErr := krbClient.CheckAndRefreshClient(); refreshErr != nil {
				logCtx.Error("Kerberos CheckAndRefreshClient failed before SPNEGO attempt", "error", refreshErr)
				if lastErr == nil || !strings.Contains(lastErr.Error(), "407") {
					lastErr = fmt.Errorf("kerberos refresh failed: %w", refreshErr)
				} else {
					lastErr = fmt.Errorf("%w; kerberos refresh failed: %v", lastErr, refreshErr)
				}
				return lastErr
			}
			if !krbClient.IsInitialized() {
				errMsg := "proxy authentication required, but Kerberos ticket is not available/valid after refresh"
				logCtx.Error(errMsg)
				if lastErr == nil || !strings.Contains(lastErr.Error(), "407") {
					lastErr = errors.New(errMsg)
				} else {
					lastErr = fmt.Errorf("%w; kerberos ticket unavailable after refresh", lastErr)
				}
				return lastErr
			}

			gokrbCl := krbClient.Gokrb5Client()
			if gokrbCl == nil {
				errMsg := "internal kerberos error: client is initialized but Gokrb5Client() returned nil"
				logCtx.Error(errMsg)
				if lastErr == nil || !strings.Contains(lastErr.Error(), "407") {
					lastErr = errors.New(errMsg)
				} else {
					lastErr = fmt.Errorf("%w; %s", lastErr, errMsg)
				}
				return lastErr
			}

			spn := "" // Let gokrb5 determine SPN
			logCtx.Debug("Attempting to set SPNEGO header", "spn_hint", spn)

			spnegoErr := spnego.SetSPNEGOHeader(gokrbCl, connectReq, spn)
			if spnegoErr != nil {
				errMsg := fmt.Sprintf("failed to set SPNEGO header on attempt %d: %v", attempt, spnegoErr)
				logCtx.Error(errMsg)
				lastErr = fmt.Errorf("proxy auth required (407), but SPNEGO generation failed: %w", spnegoErr)
				return lastErr
			}
			if connectReq.Header.Get("Proxy-Authorization") == "" {
				errMsg := "SPNEGO process did not add Proxy-Authorization header"
				logCtx.Error(errMsg)
				lastErr = fmt.Errorf("proxy auth required (407), but %s", errMsg)
				return lastErr
			}
			logCtx.Info("Added Proxy-Authorization header for retry.")
		}

		// --- Send Request ---
		writeDeadline := time.Now().Add(proxyConnectDialTimeout)
		if err := proxyConn.SetWriteDeadline(writeDeadline); err != nil {
			logCtx.Warn("Failed to set write deadline for CONNECT request", "attempt", attempt, "error", err)
		}
		writeErr := connectReq.Write(proxyConn)
		_ = proxyConn.SetWriteDeadline(time.Time{}) // Clear deadline immediately

		if writeErr != nil {
			// Handle potential connection reset especially after 407
			if common.IsConnectionClosedErr(writeErr) && attempt == 2 {
				logCtx.Warn("Proxy connection closed after 407 before retry could be sent. Aborting.", "error", writeErr)
				if lastErr == nil {
					lastErr = errors.New("proxy connection closed after 407")
				}
				return lastErr
			}
			logCtx.Error("Failed to send CONNECT request", "attempt", attempt, "error", writeErr)
			return fmt.Errorf("failed to send CONNECT request (attempt %d): %w", attempt, writeErr)
		}
		logCtx.Debug("CONNECT request sent", "attempt", attempt)

		// --- Read Response ---
		readDeadline := time.Now().Add(proxyCONNECTTimeout)
		if err := proxyConn.SetReadDeadline(readDeadline); err != nil {
			logCtx.Warn("Failed to set read deadline for CONNECT response", "attempt", attempt, "error", err)
		}
		resp, err = http.ReadResponse(proxyReader, connectReq)
		readErr := err                             // Store read error separately
		_ = proxyConn.SetReadDeadline(time.Time{}) // Clear deadline

		if readErr != nil {
			logCtx.Error("Failed to read CONNECT response", "attempt", attempt, "error", readErr)
			// If we failed reading after sending auth, return the combined error
			if attempt == 2 && lastErr != nil && strings.Contains(lastErr.Error(), "SPNEGO") {
				return fmt.Errorf("failed reading response after SPNEGO attempt (underlying error: %w): %w", lastErr, readErr)
			}
			return fmt.Errorf("failed reading CONNECT response (attempt %d): %w", attempt, readErr)
		}

		// --- Process Response ---
		logCtx.Info("Received CONNECT response", "attempt", attempt, "status", resp.StatusCode)
		// Ensure body is read and closed
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}

		if resp.StatusCode == http.StatusOK {
			logCtx.Info("CONNECT tunnel established successfully")
			return nil // Success!
		}

		if resp.StatusCode == http.StatusProxyAuthRequired {
			logCtx.Info("Received 407 Proxy Authentication Required", "attempt", attempt)
			lastErr = errors.New("proxy authentication required (407)") // Store the 407 error
			if attempt == maxConnectAttempts {
				logCtx.Error("Authentication failed after retry.")
				return lastErr // Failed on the last attempt
			}
			// Continue loop for the next attempt (will add auth header)
			continue
		}

		// --- Other Status Code ---
		lastErr = fmt.Errorf("proxy CONNECT request failed with status: %s", resp.Status)
		logCtx.Error("Proxy returned error for CONNECT", "status", resp.Status)
		return lastErr
	}

	// Fallback error if loop finishes unexpectedly
	if lastErr == nil {
		lastErr = fmt.Errorf("failed to establish CONNECT tunnel after %d attempts (unknown reason)", maxConnectAttempts)
	}
	logCtx.Error("CONNECT tunnel establishment failed", "error", lastErr)
	return lastErr
}
