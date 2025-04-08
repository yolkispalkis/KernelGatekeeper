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

// Version needs to be accessible, assuming it's passed or globally available (adjust as needed)
var clientVersion = "dev" // Placeholder, inject actual version

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
		connectReq.URL = &url.URL{Opaque: targetAddr}

		connectReq.Header.Set("User-Agent", fmt.Sprintf("KernelGatekeeper-Client/%s", clientVersion))
		connectReq.Header.Set("Proxy-Connection", "Keep-Alive")
		connectReq.Header.Set("Connection", "Keep-Alive")

		if krbClient != nil && attempt > 1 {
			if kerr := krbClient.CheckAndRefreshClient(); kerr != nil {
				logCtx.Warn("Kerberos ticket potentially invalid before CONNECT retry", "attempt", attempt, "error", kerr)
			}

			gokrbCl := krbClient.Gokrb5Client()
			if gokrbCl == nil {
				lastErr = errors.New("kerberos client not initialized internally, cannot add SPNEGO header on retry")
				logCtx.Error("Cannot add SPNEGO header", "error", lastErr)
				return lastErr
			}

			spn := ""
			logCtx.Debug("Attempting to set SPNEGO header", "spn_hint", spn)
			spnegoErr := spnego.SetSPNEGOHeader(gokrbCl, connectReq, spn)

			if spnegoErr != nil {
				lastErr = fmt.Errorf("failed to set SPNEGO header on attempt %d: %w", attempt, spnegoErr)
				logCtx.Error("SPNEGO header generation failed on retry attempt", "error", lastErr)
				return lastErr
			} else if connectReq.Header.Get("Proxy-Authorization") != "" {
				logCtx.Debug("SPNEGO Proxy-Authorization header added", "attempt", attempt)
			} else {
				logCtx.Warn("SPNEGO did not add Proxy-Authorization header on retry attempt")
				lastErr = errors.New("failed to generate SPNEGO token for Proxy-Authorization header")
				return lastErr
			}
		} else if krbClient == nil && attempt > 1 {
			logCtx.Error("Received 407 Proxy Authentication Required, but Kerberos client is not available.")
			if lastErr == nil {
				lastErr = errors.New("proxy authentication required, but Kerberos is not configured/initialized")
			}
			return lastErr
		}

		if err := proxyConn.SetWriteDeadline(time.Now().Add(proxyConnectDialTimeout)); err != nil {
			logCtx.Warn("Failed to set write deadline for CONNECT request", "error", err)
		}
		writeErr := connectReq.Write(proxyConn)
		proxyConn.SetWriteDeadline(time.Time{})

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

		proxyReader := bufio.NewReader(proxyConn)
		readDeadline := time.Now().Add(proxyCONNECTTimeout / 2)
		if err := proxyConn.SetReadDeadline(readDeadline); err != nil {
			logCtx.Warn("Failed to set read deadline for CONNECT response", "error", err)
		}
		resp, lastErr = http.ReadResponse(proxyReader, connectReq)
		proxyConn.SetReadDeadline(time.Time{})

		if lastErr != nil {
			if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
				return fmt.Errorf("CONNECT read cancelled or timed out (attempt %d): %w", attempt, lastErr)
			}
			if common.IsTimeoutError(lastErr) {
				logCtx.Error("Timeout reading CONNECT response", "attempt", attempt, "error", lastErr)
			} else if common.IsConnectionClosedErr(lastErr) {
				logCtx.Error("Proxy closed connection unexpectedly after CONNECT request", "attempt", attempt, "error", lastErr)
			} else {
				logCtx.Error("Failed to read CONNECT response", "attempt", attempt, "error", lastErr)
			}
			return fmt.Errorf("failed reading CONNECT response (attempt %d): %w", attempt, lastErr)
		}

		logCtx.Debug("Received CONNECT response", "attempt", attempt, "status", resp.StatusCode)

		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		if resp.StatusCode == http.StatusOK {
			logCtx.Debug("CONNECT tunnel established successfully")
			return nil
		}

		if resp.StatusCode == http.StatusProxyAuthRequired {
			if attempt == 1 && krbClient != nil {
				logCtx.Info("Received 407 Proxy Authentication Required, will retry with Kerberos auth.")
				lastErr = fmt.Errorf("proxy authentication required (%s)", resp.Status)
				continue
			} else {
				logCtx.Error("Received 407 Proxy Authentication Required, but cannot retry or Kerberos not available.")
				lastErr = fmt.Errorf("proxy authentication failed: %s (Kerberos available: %t, attempt: %d)", resp.Status, krbClient != nil, attempt)
				return lastErr
			}
		}

		errMsg := fmt.Sprintf("proxy CONNECT request failed: %s", resp.Status)
		logCtx.Error("Proxy returned error for CONNECT", "status", resp.Status)
		lastErr = errors.New(errMsg)
		return lastErr
	}

	if lastErr == nil {
		lastErr = errors.New("failed to establish CONNECT tunnel after maximum attempts")
	}
	return lastErr
}
