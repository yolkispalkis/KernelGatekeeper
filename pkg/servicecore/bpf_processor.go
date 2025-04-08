package servicecore

import (
	"context"
	"encoding/json"
	"errors"
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
	notifChan    <-chan ebpf.NotificationTuple
}

func NewBpfProcessor(stateMgr *StateManager) *BpfProcessor {
	return &BpfProcessor{
		stateManager: stateMgr,
		clientMgr:    stateMgr.GetClientManager(),
		notifChan:    stateMgr.GetNotificationChannel(),
	}
}

func (bp *BpfProcessor) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			slog.Info("BPF notification processor stopping (context cancelled).")
			return
		case notification, ok := <-bp.notifChan:
			if !ok {
				slog.Info("BPF notification channel closed.")
				return
			}

			pidTgid := notification.PidTgid
			pid := uint32(pidTgid & 0xFFFFFFFF)
			tgid := uint32(pidTgid >> 32)

			logCtx := slog.With(
				"src_ip", notification.SrcIP.String(),
				"orig_dst_ip", notification.OrigDstIP.String(),
				"orig_dst_port", notification.OrigDstPort,
				"src_port", notification.SrcPort,
				"pid", pid,
				"tgid", tgid,
			)
			logCtx.Debug("Received BPF notification tuple")

			if pid == 0 {
				logCtx.Warn("Received notification with zero PID, skipping.", "pid_tgid", pidTgid)
				continue
			}

			// UID lookup now likely done in ClientManager when adding client?
			// If not, it needs bpfutil.GetUidFromPid(pid) here.
			// Assuming UID is readily available via client manager state.

			// Find client by PID/TGID or UID (ClientManager needs methods for this)
			// Placeholder: Assume finding by PID for now
			// uid, err := bpfutil.GetUidFromPid(pid)
			// if err != nil {
			//	 logCtx.Warn("Could not get UID for PID (process likely exited?)", "error", err)
			//	 continue
			// }
			// clientConn := bp.clientMgr.FindClientConnByUID(uid) // Use UID

			// Let's assume we need UID lookup here for simplicity now
			uid, err := bpfutil.GetUidFromPid(pid)
			if err != nil {
				logCtx.Warn("Could not get UID for PID (process likely exited?)", "error", err)
				continue
			}
			logCtx = logCtx.With("uid", uid)

			clientConn := bp.clientMgr.FindClientConnByUID(uid)

			if clientConn == nil {
				logCtx.Debug("No registered client found for UID")
				continue
			}

			logCtx.Info("Found registered client for connection, sending notification.")

			ipcNotifData := ipc.NotifyAcceptData{
				SrcIP:    notification.SrcIP.String(),
				DstIP:    notification.OrigDstIP.String(),
				SrcPort:  notification.SrcPort,
				DstPort:  notification.OrigDstPort,
				Protocol: notification.Protocol,
			}

			ipcCmd, err := ipc.NewCommand("notify_accept", ipcNotifData)
			if err != nil {
				logCtx.Error("Failed to create IPC notification command", "error", err)
				continue
			}

			bp.sendToClient(clientConn, ipcCmd, uid) // Pass UID for logging
		}
	}
}

func (bp *BpfProcessor) sendToClient(conn net.Conn, cmd *ipc.Command, uid uint32) {
	go func(c net.Conn, command *ipc.Command, clientUID uint32) {
		logCtx := slog.With("cmd", command.Command, "client_uid", clientUID)

		encoder := json.NewEncoder(c)
		c.SetWriteDeadline(time.Now().Add(ipcSendTimeout))
		err := encoder.Encode(command)
		c.SetWriteDeadline(time.Time{})

		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) {
				logCtx.Info("IPC send cancelled or connection closed during send", "error", err)
			} else {
				logCtx.Warn("Failed to send command to client, removing client.", "error", err)
			}
			// Remove client on any send error
			bp.clientMgr.RemoveClientConn(c)
		} else {
			logCtx.Debug("Sent command to client successfully.")
		}
	}(conn, cmd, uid)
}
