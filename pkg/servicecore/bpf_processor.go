package servicecore

import (
	"context"
	"encoding/json"
	"errors" // Import fmt for error formatting
	"log/slog"
	"net" // Import runtime for Gosched
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	ipcSendTimeout = 2 * time.Second
	// How often to check for config changes (e.g., excluded paths)
	configCheckInterval = 10 * time.Second
)

type BpfProcessor struct {
	stateManager *StateManager
	clientMgr    *ClientManager
	notifChan    <-chan ebpf.NotificationTuple // Use the type from ebpf package
}

func NewBpfProcessor(stateMgr *StateManager) *BpfProcessor {
	// Ensure stateManager and its components are valid
	if stateMgr == nil {
		slog.Error("FATAL: BpfProcessor created with nil StateManager")
		// This should ideally panic or be prevented earlier
		return nil
	}
	if stateMgr.GetClientManager() == nil {
		slog.Error("FATAL: BpfProcessor created with nil ClientManager in StateManager")
		return nil
	}
	if stateMgr.GetNotificationChannel() == nil { // Call the new method
		slog.Error("FATAL: BpfProcessor created with nil NotificationChannel in StateManager")
		return nil
	}

	return &BpfProcessor{
		stateManager: stateMgr,
		clientMgr:    stateMgr.GetClientManager(),
		notifChan:    stateMgr.GetNotificationChannel(), // Call the new method
	}
}

// Run processes BPF notifications and handles dynamic config updates for excluded paths.
func (bp *BpfProcessor) Run(ctx context.Context) {
	if bp == nil || bp.stateManager == nil || bp.clientMgr == nil || bp.notifChan == nil {
		slog.Error("BpfProcessor Run() called on improperly initialized instance. Exiting.")
		return
	}

	cfg := bp.stateManager.GetConfig() // Get initial config
	excludedPaths := cfg.EBPF.Excluded
	slog.Info("BPF Processor starting", "initial_excluded_paths_count", len(excludedPaths))

	configCheckTicker := time.NewTicker(configCheckInterval)
	defer configCheckTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("BPF notification processor stopping (context cancelled).")
			return

		case notification, ok := <-bp.notifChan:
			if !ok {
				slog.Info("BPF notification channel closed. BPF processor stopping.")
				return // Exit loop when channel is closed
			}

			// Process the BPF notification
			bp.processSingleNotification(ctx, notification, excludedPaths)

		case <-configCheckTicker.C:
			// Periodically check if excluded paths in config have changed
			newCfg := bp.stateManager.GetConfig()
			newExcludedPaths := newCfg.EBPF.Excluded
			// Use a helper to compare string slices for equality
			if !stringSlicesEqual(excludedPaths, newExcludedPaths) {
				slog.Info("Reloading executable exclusion paths", "old_count", len(excludedPaths), "new_count", len(newExcludedPaths))
				excludedPaths = newExcludedPaths // Update local cache
			}
		}
		// Yield slightly to prevent tight loop if channel is very busy
		// runtime.Gosched()
	}
}

// processSingleNotification handles one BPF event.
func (bp *BpfProcessor) processSingleNotification(ctx context.Context, notification ebpf.NotificationTuple, excludedPaths []string) { // Use the type from ebpf package
	pidTgid := notification.PidTgid
	pid := uint32(pidTgid & 0xFFFFFFFF) // Extract PID

	logCtx := slog.With(
		"src_ip", notification.SrcIP.String(),
		"orig_dst_ip", notification.OrigDstIP.String(),
		"orig_dst_port", notification.OrigDstPort,
		"src_port", notification.SrcPort,
		"pid", pid,
	)
	logCtx.Debug("Received BPF notification tuple")

	if pid == 0 {
		logCtx.Warn("Received notification with zero PID, skipping.", "pid_tgid", pidTgid)
		return
	}

	// --- Check Excluded Executables ---
	// This check is now potentially done against the latest `excludedPaths`
	if len(excludedPaths) > 0 {
		execPath, err := bpfutil.GetExecutablePathFromPid(pid)
		if err != nil {
			// Log error, but decide whether to proceed or block.
			// If we can't get the path, should we risk proxying something excluded?
			// For now, log and proceed, assuming it's not excluded.
			logCtx.Warn("Could not get executable path for PID, proceeding with potential proxying", "error", err)
		} else {
			logCtx = logCtx.With("exec_path", execPath) // Add path to context for logging
			isExcluded := false
			for _, excluded := range excludedPaths {
				// Use filepath.Clean? For now, direct comparison.
				if execPath == excluded {
					isExcluded = true
					break
				}
			}
			if isExcluded {
				logCtx.Info("Ignoring connection from excluded executable")
				return // Stop processing this notification
			}
		}
	}

	// --- Find Client by UID ---
	uid, err := bpfutil.GetUidFromPid(pid)
	if err != nil {
		// If we can't get UID, we can't find the client. Process might have exited.
		logCtx.Warn("Could not get UID for PID (process likely exited?), skipping notification", "error", err)
		return
	}
	logCtx = logCtx.With("uid", uid) // Add UID to log context

	clientConn := bp.clientMgr.FindClientConnByUID(uid) // Call the new method
	if clientConn == nil {
		logCtx.Debug("No registered client found for UID, skipping notification")
		return // No client to send the notification to
	}

	// --- Send Notification to Client ---
	logCtx.Info("Found registered client for connection, sending notify_accept.")

	// Ensure ports are in expected format (assuming BPF gives network byte order, IPC wants host?)
	// Let's assume IPC expects host byte order for ports for now.
	ipcNotifData := ipc.NotifyAcceptData{ // Use the newly defined struct
		SrcIP:    notification.SrcIP.String(),
		DstIP:    notification.OrigDstIP.String(),
		SrcPort:  notification.SrcPort,     // Keep as is if BPF outputs host byte order
		DstPort:  notification.OrigDstPort, // Keep as is if BPF outputs host byte order
		Protocol: notification.Protocol,
	}

	ipcCmd, err := ipc.NewCommand("notify_accept", ipcNotifData)
	if err != nil {
		logCtx.Error("Failed to create IPC notify_accept command", "error", err)
		return // Cannot proceed if command creation fails
	}

	// Send the command asynchronously
	bp.sendToClient(ctx, clientConn, ipcCmd, uid)
}

// sendToClient sends an IPC command to a specific client connection.
// Runs in its own goroutine to avoid blocking the main processor loop.
// Uses context for potential cancellation during send.
func (bp *BpfProcessor) sendToClient(ctx context.Context, conn net.Conn, cmd *ipc.Command, uid uint32) {
	// Add to WaitGroup to ensure sends complete during shutdown
	bp.stateManager.AddWaitGroup(1)
	go func(c net.Conn, command *ipc.Command, clientUID uint32) {
		defer bp.stateManager.WaitGroupDone()

		// Check context before attempting to send
		if ctx.Err() != nil {
			slog.Debug("IPC send cancelled before write due to context", "cmd", command.Command, "client_uid", clientUID, "error", ctx.Err())
			return
		}

		logCtx := slog.With("cmd", command.Command, "client_uid", clientUID)
		encoder := json.NewEncoder(c)

		// Set write deadline
		c.SetWriteDeadline(time.Now().Add(ipcSendTimeout))
		err := encoder.Encode(command)
		c.SetWriteDeadline(time.Time{}) // Clear deadline immediately

		if err != nil {
			// Check context error *after* write error
			if ctx.Err() != nil {
				logCtx.Info("IPC send failed likely due to context cancellation", "error", err, "context_err", ctx.Err())
			} else if errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) {
				logCtx.Info("IPC send failed: connection closed by client or network.", "error", err)
			} else if common.IsTimeoutError(err) {
				logCtx.Warn("IPC send failed: write timeout.", "timeout", ipcSendTimeout, "error", err)
			} else {
				logCtx.Error("IPC send failed with unexpected error.", "error", err)
			}
			// If send fails, assume client is gone and remove it.
			// Run RemoveClientConn in a separate goroutine to avoid potential deadlock
			// if RemoveClientConn tries to acquire a lock held elsewhere. Less likely now.
			// go bp.clientMgr.RemoveClientConn(c)
			// Or simpler: just call it directly. The lock order should be okay.
			bp.clientMgr.RemoveClientConn(c)
		} else {
			logCtx.Debug("Sent command to client successfully.")
		}
	}(conn, cmd, uid)
}

// stringSlicesEqual checks if two string slices contain the same elements in the same order.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
