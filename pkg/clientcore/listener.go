package clientcore

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

const (
	LocalListenAddr = "127.0.0.1" // Exported constant
)

type LocalListener struct {
	listener net.Listener
	address  string
}

func NewLocalListener(port uint16) *LocalListener {
	if port == 0 {
		port = config.DefaultClientListenerPort
		slog.Warn("Client listener port not configured or zero, using default", "default", port)
	}
	return &LocalListener{
		address: fmt.Sprintf("%s:%d", LocalListenAddr, port), // Use exported constant
	}
}

func (l *LocalListener) Start() error {
	listener, err := net.Listen("tcp", l.address)
	if err != nil {
		return fmt.Errorf("failed to start local listener on %s: %w", l.address, err)
	}
	l.listener = listener
	slog.Info("Started local listener for redirected connections", "address", l.address)
	return nil
}

func (l *LocalListener) GetListener() net.Listener {
	return l.listener
}

func (l *LocalListener) Close() error {
	if l.listener != nil {
		slog.Info("Closing local listener", "address", l.address)
		err := l.listener.Close()
		l.listener = nil
		return err
	}
	return nil
}

func (l *LocalListener) Addr() net.Addr {
	if l.listener != nil {
		return l.listener.Addr()
	}
	return nil
}

func (l *LocalListener) Port() uint16 {
	if l.listener == nil {
		return 0
	}
	tcpAddr, ok := l.listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	return uint16(tcpAddr.Port)
}

func (l *LocalListener) IP() net.IP {
	if l.listener == nil {
		return nil
	}
	tcpAddr, ok := l.listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	return tcpAddr.IP
}

// ParseListenerIP is deprecated if only LocalListenAddr is used, but kept for potential future use.
func ParseListenerIP(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("IP address is not IPv4: %s", ipStr)
	}
	return binary.BigEndian.Uint32(ip), nil
}
