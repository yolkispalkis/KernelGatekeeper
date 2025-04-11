// FILE: pkg/clientcore/connect_tunnel.go
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

var ClientVersion = "dev"

const (
	maxConnectAttempts = 2
)

func establishConnectTunnel(ctx context.Context, proxyURL *url.URL, targetAddr string, krbClient *kerb.KerberosClient, logCtx *slog.Logger) (net.Conn, error) {

	var proxyConn net.Conn
	var err error

	dialer := net.Dialer{Timeout: proxyConnectDialTimeout}
	proxyConn, err = dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy server %s: %w", proxyURL.Host, err)
	}

	logCtx = logCtx.With("proxy_addr", proxyConn.RemoteAddr())
	logCtx.Debug("Connected to proxy server")

	var lastErr error
	for attempt := 1; attempt <= maxConnectAttempts; attempt++ {

		if err := ctx.Err(); err != nil {
			proxyConn.Close()
			return nil, err
		}

		if dl, ok := ctx.Deadline(); ok {
			proxyConn.SetDeadline(dl)

			defer proxyConn.SetDeadline(time.Time{})
		}

		logCtx.Debug("Sending CONNECT request", "target", targetAddr, "attempt", attempt)
		connectReq, err := http.NewRequestWithContext(ctx, "CONNECT", targetAddr, nil)
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to create CONNECT request: %w", err)
		}
		connectReq.Host = targetAddr
		connectReq.Header.Set("User-Agent", "KernelGatekeeper-Client/"+ClientVersion)
		connectReq.Header.Set("Proxy-Connection", "Keep-Alive")

		if attempt > 1 {
			if krbClient == nil {
				lastErr = errors.New("proxy authentication required, but Kerberos client is not available")
				logCtx.Warn(lastErr.Error())
				break
			}

			if err := krbClient.CheckAndRefreshClient(); err != nil {

				lastErr = fmt.Errorf("failed to refresh Kerberos ticket before auth: %w", err)
				logCtx.Error(lastErr.Error())
				break
			}
			if !krbClient.IsInitialized() {
				lastErr = errors.New("proxy authentication required, but Kerberos ticket is not initialized/valid")
				logCtx.Warn(lastErr.Error())
				break
			}

			spn := ""

			baseKrbClient := krbClient.Gokrb5Client()
			if baseKrbClient == nil {
				lastErr = errors.New("failed to get underlying Kerberos client for SPNEGO")

			} else if err = spnego.SetSPNEGOHeader(baseKrbClient, connectReq, spn); err != nil {
				lastErr = fmt.Errorf("failed to set SPNEGO header: %w", err)

			}

			if lastErr != nil {
				logCtx.Error(lastErr.Error())
				break
			}

			logCtx.Debug("Added Proxy-Authorization: Negotiate header")
		}

		err = connectReq.Write(proxyConn)
		if err != nil {

			if common.IsConnectionClosedErr(err) && attempt > 1 {
				lastErr = fmt.Errorf("proxy closed connection after auth attempt: %w", err)
				logCtx.Warn(lastErr.Error())

			} else {
				lastErr = fmt.Errorf("failed to write CONNECT request to proxy: %w", err)
			}
			break
		}

		resp, err := http.ReadResponse(bufio.NewReader(proxyConn), connectReq)
		if err != nil {

			if attempt > 1 {
				lastErr = fmt.Errorf("proxy auth attempt failed: error reading response: %w (previous error: %v)", err, lastErr)
			} else {
				lastErr = fmt.Errorf("failed to read CONNECT response from proxy: %w", err)
			}
			break
		}

		defer func() {
			if resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()

		logCtx.Debug("Received CONNECT response", "status_code", resp.StatusCode)
		switch resp.StatusCode {
		case http.StatusOK:
			logCtx.Info("CONNECT tunnel established successfully")

			proxyConn.SetDeadline(time.Time{})
			return proxyConn, nil

		case http.StatusProxyAuthRequired:
			if attempt >= maxConnectAttempts {
				lastErr = errors.New("proxy authentication required, but max attempts reached or auth failed")
				logCtx.Warn(lastErr.Error())
				break
			}

			authHeader := resp.Header.Get("Proxy-Authenticate")
			if !strings.Contains(strings.ToLower(authHeader), "negotiate") {
				lastErr = fmt.Errorf("proxy requires authentication, but does not support Negotiate (Kerberos/SPNEGO). Supported: %s", authHeader)
				logCtx.Error(lastErr.Error())
				break
			}
			logCtx.Info("Proxy requires authentication (407), will attempt with Kerberos on next try")
			lastErr = errors.New("proxy authentication required (407)")

			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			resp = nil

			continue

		default:
			lastErr = fmt.Errorf("proxy returned unexpected status code %d: %s", resp.StatusCode, resp.Status)
			logCtx.Error(lastErr.Error())
			break
		}
	}

	proxyConn.Close()
	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("failed to establish CONNECT tunnel after all attempts")
}
