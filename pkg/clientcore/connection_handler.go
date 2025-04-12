// FILE: pkg/clientcore/connection_handler.go
package clientcore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/proxy"
)

const (
	maxConcurrentWorkers    = 200
	proxyConnectDialTimeout = 10 * time.Second
	proxyCONNECTTimeout     = 30 * time.Second
	relayCopyTimeout        = 5 * time.Minute
	targetDialTimeout       = 15 * time.Second
	soOriginalDst           = 80
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

func (h *ConnectionHandler) HandleIncomingConnection(ctx context.Context, acceptedConn net.Conn) {
	if !h.semaphore.TryAcquire(1) {
		slog.Warn("Too many concurrent connections, rejecting new redirected connection")
		acceptedConn.Close()
		return
	}

	h.stateManager.AddWaitGroup(1)
	h.stateManager.IncActiveConnections()

	go func() {
		defer h.semaphore.Release(1)
		defer h.stateManager.DecActiveConnections()
		defer h.stateManager.WaitGroupDone()
		defer acceptedConn.Close()

		logCtx := slog.With(
			"remote_addr", acceptedConn.RemoteAddr().String(),
			"local_addr", acceptedConn.LocalAddr().String(),
		)
		logCtx.Info("Handling new redirected connection")

		origDestIP, origDestPort, err := h.getOriginalDestination(acceptedConn)
		if err != nil {
			logCtx.Error("Failed to get original destination from socket", "error", err)
			return
		}

		logCtx = logCtx.With(
			"original_dst_ip", origDestIP.String(),
			"original_dst_port", origDestPort,
		)
		logCtx.Debug("Retrieved original destination")

		h.handleAcceptedConnection(ctx, acceptedConn, origDestIP.String(), origDestPort, logCtx)

		logCtx.Info("Redirected connection handling finished")
	}()
}

func (h *ConnectionHandler) getOriginalDestination(conn net.Conn) (net.IP, uint16, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("connection is not TCP: %T", conn)
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var originalDst unix.RawSockaddrInet4
	var controlErr error

	err = rawConn.Control(func(fd uintptr) {
		addrLen := uint32(unsafe.Sizeof(originalDst))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.IPPROTO_IP,
			soOriginalDst,
			uintptr(unsafe.Pointer(&originalDst)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			controlErr = fmt.Errorf("getsockopt(SO_ORIGINAL_DST) failed: %w", errno)
		}
	})

	if err != nil {
		return nil, 0, fmt.Errorf("syscallconn control error: %w", err)
	}
	if controlErr != nil {
		return nil, 0, controlErr
	}

	if originalDst.Family != syscall.AF_INET {
		return nil, 0, fmt.Errorf("original destination address family not AF_INET: %d", originalDst.Family)
	}

	ip := net.IPv4(originalDst.Addr[0], originalDst.Addr[1], originalDst.Addr[2], originalDst.Addr[3])
	portBytes := make([]byte, 2)
	// Assuming getsockopt returns port in network byte order, but the struct field Port is uint16
	// We need to read it into bytes using native endianness and then convert to host/standard BigEndian for network operations
	// common.NativeEndian.PutUint16(portBytes, originalDst.Port)
	// port := binary.BigEndian.Uint16(portBytes)
	// Correction: SO_ORIGINAL_DST typically returns the port in network byte order (BigEndian).
	// The originalDst.Port is uint16, so we need to ensure it's interpreted correctly.
	// bpf_ntohs equivalent in Go for a uint16 already in network order:
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&originalDst.Port))[:])

	return ip, port, nil
}

func (h *ConnectionHandler) handleAcceptedConnection(ctx context.Context, acceptedConn net.Conn, targetHost string, targetPort uint16, logCtx *slog.Logger) {
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	targetURL := &url.URL{
		Scheme: "tcp",
		Host:   targetAddr,
	}

	if targetPort == 80 {
		targetURL.Scheme = "http"
	} else if targetPort == 443 {
		targetURL.Scheme = "https"
	}

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

	switch pacResult.Type {
	case proxy.ResultDirect:
		logCtx.Info("PAC result: DIRECT connection", "target", targetAddr)
		dialer := net.Dialer{Timeout: targetDialTimeout}
		upstreamConn, connectErr = dialer.DialContext(ctx, "tcp", targetAddr)
		if connectErr != nil {
			logCtx.Error("Failed to establish direct connection", "target", targetAddr, "error", connectErr)
			return
		}
		logCtx.Info("Direct connection established", "target", targetAddr)

	case proxy.ResultProxy:
		if len(pacResult.Proxies) == 0 {
			logCtx.Error("PAC result indicated PROXY but provided no proxy servers")
			return
		}

		selectedProxyInfo := pacResult.Proxies[0]
		selectedProxyURL := selectedProxyInfo.URL()
		if selectedProxyURL == nil {
			logCtx.Error("Failed to parse selected proxy info into URL", "proxy_info", selectedProxyInfo)
			return
		}

		logCtx.Info("PAC result: PROXY connection", "target", targetAddr, "proxy", selectedProxyURL.String())

		kerbClient := h.stateManager.GetKerberosClient()

		connectCtx, connectCancel := context.WithTimeout(ctx, proxyCONNECTTimeout)
		defer connectCancel()

		upstreamConn, connectErr = establishConnectTunnel(connectCtx, selectedProxyURL, targetAddr, kerbClient, logCtx)
		if connectErr != nil {
			logCtx.Error("Failed to establish CONNECT tunnel via proxy", "proxy", selectedProxyURL.String(), "target", targetAddr, "error", connectErr)
			return
		}
		logCtx.Info("CONNECT tunnel established via proxy", "proxy", selectedProxyURL.String(), "target", targetAddr)

	case proxy.ResultUnknown:
		logCtx.Error("Could not determine proxy route (PAC returned Unknown or error)")
		return

	default:
		logCtx.Error("Unhandled PAC result type", "type", pacResult.Type)
		return
	}

	defer upstreamConn.Close()

	logCtx.Debug("Starting bidirectional relay")
	relayErr := h.relayDataBidirectionally(ctx, acceptedConn, upstreamConn)
	if relayErr != nil {
		if !errors.Is(relayErr, context.Canceled) && !errors.Is(relayErr, io.EOF) && !common.IsConnectionClosedErr(relayErr) {
			logCtx.Warn("Error during data relay", "error", relayErr)
		} else {
			logCtx.Debug("Data relay finished", "reason", relayErr)
		}
	} else {
		logCtx.Debug("Data relay completed successfully")
	}
}

func (h *ConnectionHandler) relayDataBidirectionally(ctx context.Context, conn1, conn2 net.Conn) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	copyData := func(dst net.Conn, src net.Conn) {
		defer wg.Done()

		// Use a reasonable buffer size
		buf := make([]byte, 32*1024) // 32KB buffer

		for {
			// Set read deadline for each read operation
			readDeadline := time.Now().Add(relayCopyTimeout)
			if dl, ok := ctx.Deadline(); ok && dl.Before(readDeadline) {
				readDeadline = dl
			}
			if time.Until(readDeadline) <= 0 {
				errChan <- ctx.Err() // Context deadline exceeded
				return
			}
			if err := src.SetReadDeadline(readDeadline); err != nil {
				if !common.IsConnectionClosedErr(err) { // Avoid logging closed errors repeatedly
					slog.Warn("Failed to set read deadline for relay", "error", err)
				}
				// Don't necessarily exit, attempt the read anyway
			}

			nr, readErr := src.Read(buf)

			// Clear deadline immediately after read attempt
			_ = src.SetReadDeadline(time.Time{})

			if nr > 0 {
				// Set write deadline based on context or a fixed timeout
				writeDeadline := time.Now().Add(relayCopyTimeout / 2) // Shorter write timeout
				if dl, ok := ctx.Deadline(); ok && dl.Before(writeDeadline) {
					writeDeadline = dl
				}
				if time.Until(writeDeadline) <= 0 {
					errChan <- ctx.Err()
					return
				}
				if err := dst.SetWriteDeadline(writeDeadline); err != nil {
					if !common.IsConnectionClosedErr(err) {
						slog.Warn("Failed to set write deadline for relay", "error", err)
					}
				}

				nw, writeErr := dst.Write(buf[0:nr])

				// Clear deadline immediately
				_ = dst.SetWriteDeadline(time.Time{})

				if writeErr != nil {
					errChan <- writeErr
					return
				}
				if nw != nr {
					errChan <- io.ErrShortWrite
					return
				}
			}

			// Handle read errors after potential write
			if readErr != nil {
				// Send EOF or context errors non-fatally, others are fatal
				if readErr == io.EOF || errors.Is(readErr, context.Canceled) || errors.Is(readErr, net.ErrClosed) {
					errChan <- readErr // Signal closure/cancellation
				} else if common.IsTimeoutError(readErr) {
					// Read timed out, continue loop to try reading again unless context is done
					select {
					case <-ctx.Done():
						errChan <- ctx.Err()
						return
					default:
						continue
					}
				} else {
					errChan <- readErr // Send other errors
				}
				return // Exit loop on any read error (EOF, timeout handled, other error)
			}

			// Check context after successful read/write cycle
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				// continue loop
			}
		}
	}

	wg.Add(2)
	go copyData(conn1, conn2)
	go copyData(conn2, conn1)

	// Wait for the first error or context cancellation
	var firstError error
	select {
	case err := <-errChan:
		firstError = err
	case <-ctx.Done():
		firstError = ctx.Err()
	}

	// Close connections to unblock the other goroutine
	conn1.Close()
	conn2.Close()

	// Wait for the second goroutine to finish and collect its error if it's more significant
	wg.Wait() // Ensure both copyData goroutines have exited

	select {
	case secondError := <-errChan: // Check the channel again for the second error
		// Ignore EOF, closed, or context errors if we already have an error
		isIgnorable := errors.Is(secondError, io.EOF) || common.IsConnectionClosedErr(secondError) || errors.Is(secondError, context.Canceled) || common.IsTimeoutError(secondError)
		if firstError == nil && !isIgnorable {
			firstError = secondError // Record the second error if it's significant and we don't have one yet
		} else if firstError != nil && !isIgnorable {
			// Optionally log the second error if it's different and significant
			slog.Debug("Second relay goroutine finished with error after first error", "first_error", firstError, "second_error", secondError)
		}
	default:
		// No second error received after waiting
	}

	return firstError
}
