package clientcore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"   // Keep kerb import
	"github.com/yolkispalkis/kernelgatekeeper/pkg/proxy" // Keep proxy import
)

const (
	maxConcurrentWorkers    = 200
	proxyConnectDialTimeout = 10 * time.Second // Timeout dialing the proxy server itself
	proxyCONNECTTimeout     = 30 * time.Second // Timeout for the whole CONNECT handshake including auth
	relayCopyTimeout        = 5 * time.Minute  // Timeout for io.Copy during relay
	targetDialTimeout       = 15 * time.Second // Timeout for dialing the original target directly
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
	if !h.semaphore.TryAcquire(1) {
		slog.Warn("Too many concurrent connections, rejecting new BPF connection")
		acceptedConn.Close() // Close the connection if we can't handle it
		return
	}

	h.stateManager.AddWaitGroup(1) // Increment state manager's WaitGroup
	h.stateManager.IncActiveConnections()

	go func() {
		defer h.semaphore.Release(1)
		defer h.stateManager.DecActiveConnections()
		defer h.stateManager.WaitGroupDone() // Decrement state manager's WaitGroup

		// Use the context passed from IPCManager which might be linked to root context
		// Add connection specific details to logger
		logCtx := slog.With(
			"remote_addr", acceptedConn.RemoteAddr().String(), // This will be the local BPF listener addr
			"local_addr", acceptedConn.LocalAddr().String(), // This will be dynamic
			"original_dst_ip", originalDest.DstIP,
			"original_dst_port", originalDest.DstPort,
			"original_src_ip", originalDest.SrcIP,
			"original_src_port", originalDest.SrcPort,
		)
		logCtx.Info("Handling new BPF connection")

		h.handleAcceptedConnection(ctx, acceptedConn, originalDest, logCtx)

		logCtx.Info("BPF connection handling finished")
	}()
}

// handleAcceptedConnection determines the proxy, establishes the connection (direct or tunnel), and relays data.
func (h *ConnectionHandler) handleAcceptedConnection(ctx context.Context, acceptedConn net.Conn, originalDest ipc.NotifyAcceptData, logCtx *slog.Logger) {
	defer acceptedConn.Close() // Ensure accepted connection is always closed eventually

	targetHost := originalDest.DstIP
	targetPort := originalDest.DstPort
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	// Construct target URL (scheme doesn't matter much for CONNECT, but helps PAC)
	// Assume https for common web ports, http otherwise? Or just use host?
	// Let's use a placeholder scheme like "tcp" for PAC evaluation
	targetURL := &url.URL{
		Scheme: "tcp", // Scheme for PAC evaluation logic
		Host:   targetAddr,
	}
	// Override scheme if common ports are used, PAC might expect http/https
	if targetPort == 80 {
		targetURL.Scheme = "http"
	} else if targetPort == 443 {
		targetURL.Scheme = "https"
	}

	// 1. Determine Proxy using ProxyManager
	proxyMgr := h.stateManager.GetProxyManager()
	if proxyMgr == nil {
		logCtx.Error("ProxyManager is nil, cannot determine route")
		return
	}

	pacResult, err := proxyMgr.GetEffectiveProxyForURL(targetURL)
	if err != nil {
		logCtx.Error("Failed to determine proxy route via PAC/config", "target_url", targetURL.String(), "error", err)
		return
	}

	var upstreamConn net.Conn
	var connectErr error

	// 2. Establish Upstream Connection (Direct or via Proxy)
	switch pacResult.Type {
	case proxy.ResultDirect:
		logCtx.Info("PAC result: DIRECT connection", "target", targetAddr)
		dialer := net.Dialer{Timeout: targetDialTimeout}
		upstreamConn, connectErr = dialer.DialContext(ctx, "tcp", targetAddr)
		if connectErr != nil {
			logCtx.Error("Failed to establish direct connection", "target", targetAddr, "error", connectErr)
			return // Cannot proceed
		}
		logCtx.Info("Direct connection established", "target", targetAddr)

	case proxy.ResultProxy:
		if len(pacResult.Proxies) == 0 {
			logCtx.Error("PAC result indicated PROXY but provided no proxy servers")
			return // Cannot proceed
		}
		// Currently, only use the first proxy in the list
		selectedProxyInfo := pacResult.Proxies[0]
		selectedProxyURL := selectedProxyInfo.URL() // Convert ProxyInfo to url.URL
		if selectedProxyURL == nil {
			logCtx.Error("Failed to parse selected proxy info into URL", "proxy_info", selectedProxyInfo)
			return
		}

		logCtx.Info("PAC result: PROXY connection", "target", targetAddr, "proxy", selectedProxyURL.String())

		// Get Kerberos client from state manager (might be nil if init failed)
		kerbClient := h.stateManager.GetKerberosClient()

		// Establish tunnel via establishConnectTunnel
		// Timeout for the entire CONNECT process
		connectCtx, connectCancel := context.WithTimeout(ctx, proxyCONNECTTimeout)
		defer connectCancel()

		// establishConnectTunnel now needs the specific proxy URL
		upstreamConn, connectErr = establishConnectTunnel(connectCtx, selectedProxyURL, targetAddr, kerbClient, logCtx)
		if connectErr != nil {
			logCtx.Error("Failed to establish CONNECT tunnel via proxy", "proxy", selectedProxyURL.String(), "target", targetAddr, "error", connectErr)
			return // Cannot proceed
		}
		logCtx.Info("CONNECT tunnel established via proxy", "proxy", selectedProxyURL.String(), "target", targetAddr)

	case proxy.ResultUnknown:
		logCtx.Error("Could not determine proxy route (PAC returned Unknown or error)")
		return // Cannot proceed

	default:
		logCtx.Error("Unhandled PAC result type", "type", pacResult.Type)
		return // Cannot proceed
	}

	// Ensure upstream connection is closed if established
	defer upstreamConn.Close()

	// 3. Relay Data Bidirectionally
	logCtx.Debug("Starting bidirectional relay")
	relayErr := h.relayDataBidirectionally(ctx, acceptedConn, upstreamConn)
	if relayErr != nil {
		// Log relay error, especially if it's not just context cancellation or standard EOF
		if !errors.Is(relayErr, context.Canceled) && !errors.Is(relayErr, io.EOF) && !common.IsConnectionClosedErr(relayErr) {
			logCtx.Warn("Error during data relay", "error", relayErr)
		} else {
			logCtx.Debug("Data relay finished", "reason", relayErr)
		}
	} else {
		logCtx.Debug("Data relay completed successfully")
	}
}

// relayDataBidirectionally copies data between two connections with timeouts.
func (h *ConnectionHandler) relayDataBidirectionally(ctx context.Context, conn1, conn2 net.Conn) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2) // Buffer to prevent goroutine leak on send

	copyData := func(dst net.Conn, src net.Conn) {
		defer wg.Done()
		// Apply deadline for the copy operation
		// Set deadline based on context or fixed timeout? Let's use fixed for simplicity.
		// If context is cancelled, reads/writes should fail anyway.
		copyTimeout := relayCopyTimeout
		if dl, ok := ctx.Deadline(); ok {
			copyTimeout = time.Until(dl)
			if copyTimeout < 0 {
				copyTimeout = 0 // Expired already
			}
		}
		if copyTimeout <= 0 {
			errChan <- ctx.Err() // Context already cancelled or expired
			return
		}

		// Set read deadline on the source connection for the copy duration
		if err := src.SetReadDeadline(time.Now().Add(copyTimeout)); err != nil {
			slog.Warn("Failed to set read deadline for relay", "error", err)
			// Proceed without deadline? Or fail? Let's proceed.
		}
		defer src.SetReadDeadline(time.Time{}) // Clear deadline on exit

		// Perform the copy
		_, err := io.Copy(dst, src)

		// Check context error after copy finishes or errors out
		if ctxErr := ctx.Err(); ctxErr != nil {
			errChan <- ctxErr // Prioritize context cancellation error
			return
		}
		// Send the io.Copy error (could be nil or EOF)
		errChan <- err
	}

	wg.Add(2)
	go copyData(conn1, conn2)
	go copyData(conn2, conn1)

	// Wait for one side to finish or error
	var firstError error
	select {
	case err := <-errChan:
		firstError = err
	case <-ctx.Done():
		firstError = ctx.Err()
	}

	// Signal the other goroutine to stop by closing connections
	conn1.Close()
	conn2.Close()

	// Wait for the second goroutine to finish
	wg.Wait()

	// Collect potential second error (usually EOF or closed connection error)
	select {
	case err := <-errChan:
		// Log second error if it's different and not expected close/EOF error
		if firstError == nil || !errors.Is(err, io.EOF) && !common.IsConnectionClosedErr(err) && !errors.Is(err, context.Canceled) {
			slog.Debug("Second relay goroutine finished", "error", err)
			if firstError == nil {
				firstError = err // Capture second error if first was nil
			}
		}
	default:
		// Channel empty, second goroutine finished cleanly after Close()
	}

	// Return the first significant error encountered
	return firstError
}
