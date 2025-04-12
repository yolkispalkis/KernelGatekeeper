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
	// The Port field in RawSockaddrInet4 is already in network byte order (BigEndian).
	// Directly convert the bytes to uint16 using BigEndian.
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

		buf := make([]byte, 32*1024) // 32KB buffer

		for {
			readDeadline := time.Now().Add(relayCopyTimeout)
			if dl, ok := ctx.Deadline(); ok && dl.Before(readDeadline) {
				readDeadline = dl
			}
			if time.Until(readDeadline) <= 0 {
				errChan <- ctx.Err()
				return
			}
			if err := src.SetReadDeadline(readDeadline); err != nil {
				if !common.IsConnectionClosedErr(err) {
					slog.Warn("Failed to set read deadline for relay", "error", err)
				}
			}

			nr, readErr := src.Read(buf)
			_ = src.SetReadDeadline(time.Time{})

			if nr > 0 {
				writeDeadline := time.Now().Add(relayCopyTimeout / 2)
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

			if readErr != nil {
				isNormalClosure := readErr == io.EOF || common.IsConnectionClosedErr(readErr)
				isCtxDone := errors.Is(readErr, context.Canceled) || errors.Is(readErr, net.ErrClosed) // Treat ErrClosed like context done
				isTimeout := common.IsTimeoutError(readErr)

				if isNormalClosure || isCtxDone {
					errChan <- readErr // Signal closure/cancellation
				} else if isTimeout {
					select {
					case <-ctx.Done():
						errChan <- ctx.Err()
						return
					default:
						continue // Continue loop to try reading again
					}
				} else {
					errChan <- readErr // Send other errors
				}
				return // Exit loop on any read error (EOF, timeout handled, other error)
			}

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
			}
		}
	}

	wg.Add(2)
	go copyData(conn1, conn2)
	go copyData(conn2, conn1)

	var firstError error
	select {
	case err := <-errChan:
		firstError = err
	case <-ctx.Done():
		firstError = ctx.Err()
	}

	conn1.Close()
	conn2.Close()

	wg.Wait()

	select {
	case secondError := <-errChan:
		isIgnorable := errors.Is(secondError, io.EOF) || common.IsConnectionClosedErr(secondError) || errors.Is(secondError, context.Canceled) || common.IsTimeoutError(secondError)
		if firstError == nil && !isIgnorable {
			firstError = secondError
		} else if firstError != nil && !isIgnorable {
			slog.Debug("Second relay goroutine finished with error after first error", "first_error", firstError, "second_error", secondError)
		}
	default:
	}

	return firstError
}
