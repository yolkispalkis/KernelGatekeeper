package clientcore

import (
	"fmt"
	"log/slog"
	"net"
)

const (
	localListenPort = 3129
	localListenAddr = "127.0.0.1"
)

type LocalListener struct {
	listener net.Listener
	address  string
}

func NewLocalListener() *LocalListener {
	return &LocalListener{
		address: fmt.Sprintf("%s:%d", localListenAddr, localListenPort),
	}
}

func (l *LocalListener) Start() error {
	listener, err := net.Listen("tcp", l.address)
	if err != nil {
		return fmt.Errorf("failed to start local listener on %s: %w", l.address, err)
	}
	l.listener = listener
	slog.Info("Started local listener for BPF connections", "address", l.address)
	return nil
}

func (l *LocalListener) GetListener() net.Listener {
	return l.listener
}

func (l *LocalListener) Close() error {
	if l.listener != nil {
		slog.Info("Closing local listener", "address", l.address)
		err := l.listener.Close()
		l.listener = nil // Avoid double close
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
