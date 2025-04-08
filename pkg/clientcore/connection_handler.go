package clientcore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/pac"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/proxy"
)

const (
	maxConcurrentWorkers    = 200
	proxyConnectDialTimeout = 10 * time.Second
	proxyCONNECTTimeout     = 30 * time.Second
	relayCopyTimeout        = 5 * time.Minute
)

type ConnectionHandler struct {
	stateManager *StateManager
	semaphore    *semaphore.Weighted
}

func NewConnectionHandler(stateMgr *StateManager) *ConnectionHandler {
	return &ConnectionHandler{
		stateManager: stateMgr,
		semaphore:    semaphore.NewWeighted(maxConcurrentWorkers),
	}
}

// HandleBPFAccept is called by the IPCManager when a notify_accept is received and the connection is accepted locally.
func (h *ConnectionHandler) HandleBPFAccept(ctx context.Context, acceptedConn net.Conn, originalDest ipc.NotifyAcceptData) {
	// Acquire semaphore before starting goroutine
	if err := h.semaphore.Acquire(ctx, 1); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			slog.Info("Worker semaphore acquisition cancelled or timed out during shutdown")
		} else {
			slog.Error("Failed to acquire worker semaphore", "error", err)
		}
		acceptedConn.Close() // Close the connection if we can't handle it
		return
	}

	h.stateManager.IncActiveConnections()
	h.stateManager.AddWaitGroup(1)

	go func(conn net.Conn, dest ipc.NotifyAcceptData) {
		defer h.stateManager.WaitGroupDone()
		defer h.semaphore.Release(1)
		defer h.stateManager.DecActiveConnections()
		h.handleAcceptedConnection(ctx, conn, dest)
	}(acceptedConn, originalDest)
}

func (h *ConnectionHandler) handleAcceptedConnection(ctx context.Context, acceptedConn net.Conn, originalDest ipc.NotifyAcceptData) {
	defer acceptedConn.Close()

	targetAddr := net.JoinHostPort(originalDest.DstIP, strconv.Itoa(int(originalDest.DstPort)))
	scheme := "http"
	if originalDest.DstPort == 443 || originalDest.DstPort == 8443 {
		scheme = "https"
	}
	targetURLStr := fmt.Sprintf("%s://%s", scheme, targetAddr)
	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		slog.Error("Failed to parse target address into URL", "target_addr", targetAddr, "error", err)
		return
	}

	logCtx := slog.With("target_addr", targetAddr, "target_url", targetURLStr)
	logCtx.Info("Handling proxied connection")

	proxyMgr := h.stateManager.GetProxyManager()
	if proxyMgr == nil {
		logCtx.Error("Proxy manager is not initialized")
		return
	}

	proxyResult, err := proxyMgr.GetEffectiveProxyForURL(targetURL)
	if err != nil {
		logCtx.Error("Failed to determine effective proxy for target", "error", err)
		return
	}

	switch proxyResult.Type {
	case pac.ResultDirect:
		logCtx.Error("PAC script returned DIRECT, but KernelGatekeeper (sockops) cannot bypass proxy. Closing connection.", "pac_result", "DIRECT")
		return

	case pac.ResultUnknown:
		logCtx.Error("Error determining proxy from PAC or configuration. Closing connection.", "pac_result", "UNKNOWN/ERROR")
		return

	case pac.ResultProxy:
		if len(proxyResult.Proxies) == 0 {
			logCtx.Error("Proxy result indicates PROXY but list is empty. Closing connection.")
			return
		}
		logCtx.Info("Proxy determined for target", "proxies", proxy.UrlsToStrings(pac.UrlsFromPacResult(proxyResult)))

		var proxyConn net.Conn
		var selectedProxyURL *url.URL
		connectErr := errors.New("no proxies available or all failed")

		kerbClient := h.stateManager.GetKerberosClient() // Get Kerberos client

		for _, currentProxyInfo := range proxyResult.Proxies {
			currentProxyURL, urlErr := currentProxyInfo.URL()
			if urlErr != nil {
				logCtx.Warn("Skipping invalid proxy info from PAC result", "proxy_info", currentProxyInfo, "error", urlErr)
				connectErr = fmt.Errorf("invalid proxy %v: %w", currentProxyInfo, urlErr)
				continue
			}

			logCtx.Info("Attempting connection via proxy", "proxy_url", currentProxyURL.String())
			selectedProxyURL = currentProxyURL

			proxyDialer := net.Dialer{Timeout: proxyConnectDialTimeout}
			proxyConn, connectErr = proxyDialer.DialContext(ctx, "tcp", currentProxyURL.Host)
			if connectErr != nil {
				logCtx.Warn("Failed to connect to proxy server, trying next (if any)", "proxy_url", currentProxyURL.String(), "error", connectErr)
				continue
			}
			logCtx.Debug("Connected to proxy server", "proxy_url", currentProxyURL.String())

			connectErr = establishConnectTunnel(ctx, proxyConn, targetAddr, kerbClient) // Pass kerbClient
			if connectErr != nil {
				logCtx.Warn("Failed to establish CONNECT tunnel, trying next proxy (if any)", "proxy_url", currentProxyURL.String(), "error", connectErr)
				proxyConn.Close()
				proxyConn = nil
				continue
			}

			logCtx.Info("CONNECT tunnel established via proxy", "proxy_url", currentProxyURL.String())
			defer proxyConn.Close()
			break
		}

		if proxyConn == nil || connectErr != nil {
			logCtx.Error("Failed to establish connection through any configured/PAC-provided proxy.", "last_error", connectErr)
			return
		}

		logCtx.Debug("Starting data relay", "selected_proxy", selectedProxyURL.String())
		relayErr := h.relayDataBidirectionally(ctx, acceptedConn, proxyConn)
		if relayErr != nil && !common.IsConnectionClosedErr(relayErr) && !errors.Is(relayErr, context.Canceled) && !common.IsTimeoutError(relayErr) {
			logCtx.Warn("Data relay ended with unexpected error", "error", relayErr)
		} else if relayErr != nil {
			logCtx.Debug("Data relay ended", "reason", relayErr)
		} else {
			logCtx.Debug("Data relay completed.")
		}

	default:
		logCtx.Error("Unknown proxy result type encountered after PAC evaluation", "type", proxyResult.Type)
	}
}

func (h *ConnectionHandler) relayDataBidirectionally(ctx context.Context, conn1, conn2 net.Conn) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	copyData := func(dst, src net.Conn, tag string) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		logCtx := slog.With("relay_tag", tag)

		for {
			select {
			case <-ctx.Done():
				logCtx.Debug("Relay cancelled by context before read")
				errChan <- ctx.Err()
				if tcpDst, ok := dst.(*net.TCPConn); ok {
					tcpDst.CloseWrite()
				}
				if tcpSrc, ok := src.(*net.TCPConn); ok {
					tcpSrc.CloseRead()
				}
				return
			default:
			}

			readDeadline := time.Now().Add(relayCopyTimeout)
			if err := src.SetReadDeadline(readDeadline); err != nil {
				if !common.IsConnectionClosedErr(err) {
					logCtx.Warn("Failed to set read deadline for relay", "error", err)
					errChan <- fmt.Errorf("%s set read deadline failed: %w", tag, err)
				} else {
					errChan <- io.EOF
				}
				return
			}

			nr, readErr := src.Read(buf)
			_ = src.SetReadDeadline(time.Time{})

			if nr > 0 {
				writeDeadline := time.Now().Add(relayCopyTimeout)
				if err := dst.SetWriteDeadline(writeDeadline); err != nil {
					if !common.IsConnectionClosedErr(err) {
						logCtx.Warn("Failed to set write deadline for relay", "error", err)
						errChan <- fmt.Errorf("%s set write deadline failed: %w", tag, err)
					} else {
						errChan <- io.EOF
					}
					return
				}

				nw, writeErr := dst.Write(buf[0:nr])
				_ = dst.SetWriteDeadline(time.Time{})

				if writeErr != nil {
					if errors.Is(writeErr, context.Canceled) || errors.Is(writeErr, context.DeadlineExceeded) {
						logCtx.Debug("Relay cancelled by context during write")
						errChan <- writeErr
					} else {
						errChan <- fmt.Errorf("%s write failed: %w", tag, writeErr)
					}
					if tcpSrc, ok := src.(*net.TCPConn); ok {
						tcpSrc.CloseRead()
					}
					return
				}
				if nr != nw {
					errChan <- fmt.Errorf("%s short write: %d != %d", tag, nw, nr)
					if tcpSrc, ok := src.(*net.TCPConn); ok {
						tcpSrc.CloseRead()
					}
					return
				}
			}

			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					logCtx.Debug("Relay source closed (EOF)")
					if tcpDst, ok := dst.(*net.TCPConn); ok {
						tcpDst.CloseWrite()
					}
					errChan <- nil
				} else if common.IsTimeoutError(readErr) {
					logCtx.Warn("Relay inactivity timeout", "timeout", relayCopyTimeout)
					errChan <- fmt.Errorf("%s inactivity timeout after %s: %w", tag, relayCopyTimeout, readErr)
				} else if common.IsConnectionClosedErr(readErr) {
					logCtx.Debug("Relay source connection closed during read", "error", readErr)
					errChan <- nil
				} else if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
					logCtx.Debug("Relay cancelled by context during read")
					errChan <- readErr
				} else {
					errChan <- fmt.Errorf("%s read failed: %w", tag, readErr)
				}
				return
			}
		}
	}

	wg.Add(2)
	go copyData(conn1, conn2, "proxy->client(bpf)")
	go copyData(conn2, conn1, "client(bpf)->proxy")

	wg.Wait()
	close(errChan)

	var firstError error
	for err := range errChan {
		if err != nil && firstError == nil {
			firstError = err
		}
	}

	if firstError != nil {
		if !errors.Is(firstError, io.EOF) && !errors.Is(firstError, context.Canceled) && !common.IsConnectionClosedErr(firstError) {
			slog.Warn("Relay finished with error", "error", firstError)
		} else {
			slog.Debug("Relay finished", "reason", firstError)
		}
		return firstError
	}

	slog.Debug("Relay finished successfully.")
	return nil
}
