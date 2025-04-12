// FILE: pkg/servicecore/bpf_processor.go
package servicecore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	ipcSendTimeout = 2 * time.Second
)

type BpfProcessor struct {
	stateManager *StateManager
	clientMgr    *ClientManager
	notifChan    <-chan ebpf.NotificationTuple // Use the Go struct type
}

func NewBpfProcessor(stateMgr *StateManager) *BpfProcessor {
	if stateMgr == nil || stateMgr.GetClientManager() == nil || stateMgr.GetNotificationChannel() == nil {
		slog.Error("FATAL: BpfProcessor created with nil StateManager, ClientManager or NotificationChannel")
		return nil
	}

	return &BpfProcessor{
		stateManager: stateMgr,
		clientMgr:    stateMgr.GetClientManager(),
		notifChan:    stateMgr.GetNotificationChannel(), // Channel now contains Go struct
	}
}

func (bp *BpfProcessor) Run(ctx context.Context) {
	if bp == nil || bp.stateManager == nil || bp.clientMgr == nil || bp.notifChan == nil {
		slog.Error("BpfProcessor Run() called on improperly initialized instance. Exiting.")
		return
	}

	slog.Info("BPF Notification Processor starting...")

	for {
		select {
		case <-ctx.Done():
			slog.Info("BPF notification processor stopping (context cancelled).")
			return

		case notification, ok := <-bp.notifChan:
			if !ok {
				slog.Info("BPF notification channel closed. BPF processor stopping.")
				return
			}
			// Process the Go struct notification
			bp.processSingleNotification(ctx, notification)
		}
	}
}

// processSingleNotification handles one BPF event (using Go types).
func (bp *BpfProcessor) processSingleNotification(ctx context.Context, notification ebpf.NotificationTuple) {
	pidTgid := notification.PidTgid
	pid := uint32(pidTgid & 0xFFFFFFFF)

	// Use the already converted net.IP and host-order ports from the notification struct
	logCtx := slog.With(
		"src_ip", notification.SrcIP.String(), // Use String() method of net.IP
		"orig_dst_ip", notification.OrigDstIP.String(), // Use String() method of net.IP
		"orig_dst_port", notification.OrigDstPort, // Already host order
		"src_port", notification.SrcPort, // Already host order
		"pid", pid,
	)
	logCtx.Debug("Processing BPF notification tuple")

	if pid == 0 {
		logCtx.Warn("Received notification with zero PID, skipping.", "pid_tgid", pidTgid)
		return
	}

	uid, err := bpfutil.GetUidFromPid(pid)
	if err != nil {
		logCtx.Debug("Could not get UID for PID (process likely exited?), skipping notification", "error", err)
		return
	}
	logCtx = logCtx.With("uid", uid)

	clientConn := bp.clientMgr.FindClientConnByUID(uid)
	if clientConn == nil {
		logCtx.Debug("No registered client found for UID, skipping notification")
		return
	}

	logCtx.Info("Found registered client for connection, sending notify_accept.")

	// Create IPC data using the Go types from the notification
	ipcNotifData := ipc.NotifyAcceptData{
		SrcIP:    notification.SrcIP.String(),     // Use String() method
		DstIP:    notification.OrigDstIP.String(), // Use String() method
		SrcPort:  notification.SrcPort,            // Already host order
		DstPort:  notification.OrigDstPort,        // Already host order
		Protocol: notification.Protocol,
	}

	ipcCmd, err := ipc.NewCommand("notify_accept", ipcNotifData)
	if err != nil {
		logCtx.Error("Failed to create IPC notify_accept command", "error", err)
		return
	}

	bp.sendToClient(ctx, clientConn, ipcCmd, uid)
}

func (bp *BpfProcessor) sendToClient(ctx context.Context, conn net.Conn, cmd *ipc.Command, uid uint32) {
	bp.stateManager.AddWaitGroup(1)
	go func(c net.Conn, command *ipc.Command, clientUID uint32) {
		defer bp.stateManager.WaitGroupDone()

		if ctx.Err() != nil {
			slog.Debug("IPC send cancelled before write due to context", "cmd", command.Command, "client_uid", clientUID, "error", ctx.Err())
			return
		}

		logCtx := slog.With("cmd", command.Command, "client_uid", clientUID)
		encoder := json.NewEncoder(c)

		deadline := time.Now().Add(ipcSendTimeout)
		if err := c.SetWriteDeadline(deadline); err != nil {
			logCtx.Warn("Failed to set write deadline for IPC send", "error", err)
		}

		err := encoder.Encode(command)

		if errSet := c.SetWriteDeadline(time.Time{}); errSet != nil {
			logCtx.Warn("Failed to clear write deadline after IPC send", "error", errSet)
		}

		if err != nil {
			if ctx.Err() != nil {
				logCtx.Info("IPC send failed likely due to context cancellation during/after write", "error", err, "context_err", ctx.Err())
			} else if errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) || errors.Is(err, io.EOF) {
				logCtx.Info("IPC send failed: connection closed.", "error_type", fmt.Sprintf("%T", err), "error", err)
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logCtx.Warn("IPC send failed: write timeout.", "timeout", ipcSendTimeout, "error", err)
			} else {
				logCtx.Error("IPC send failed with unexpected error.", "error_type", fmt.Sprintf("%T", err), "error", err)
			}
			bp.clientMgr.RemoveClientConn(c)
		} else {
			logCtx.Debug("Sent command to client successfully.")
		}
	}(conn, cmd, uid)
}
