package clientcore

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	kerberosCheckInterval = 5 * time.Minute
	// Removed configRefreshInterval
	// statusPingInterval is defined in ipc_manager.go
)

type BackgroundTasks struct {
	stateManager *StateManager // Needs access to KerberosClient and connection count
	ipcManager   *IPCManager   // Needs access to send pings
	ctx          context.Context
	wg           *sync.WaitGroup // Use stateManager's WaitGroup
}

func NewBackgroundTasks(ctx context.Context, stateMgr *StateManager, ipcMgr *IPCManager) *BackgroundTasks {
	return &BackgroundTasks{
		stateManager: stateMgr,
		ipcManager:   ipcMgr,
		ctx:          ctx,
		wg:           &stateMgr.wg, // Reference the WaitGroup from StateManager
	}
}

func (bt *BackgroundTasks) Run() {
	bt.wg.Add(1)
	go func() {
		defer bt.wg.Done()
		defer slog.Info("Background task runner stopped.")
		bt.runLoop()
	}()
}

func (bt *BackgroundTasks) runLoop() {
	// Removed configRefreshTicker
	kerbCheckTicker := time.NewTicker(kerberosCheckInterval)
	defer kerbCheckTicker.Stop()
	statusPingTicker := time.NewTicker(statusPingInterval)
	defer statusPingTicker.Stop()

	// Run initial Kerberos check immediately after setup (which now happens in main)
	bt.checkKerberosTicket()

	for {
		select {
		case <-bt.ctx.Done():
			return

		// Removed config refresh case

		case <-kerbCheckTicker.C:
			bt.checkKerberosTicket()

		case <-statusPingTicker.C:
			bt.sendClientStatusPing()
		}
	}
}

// Removed RefreshConfiguration

func (bt *BackgroundTasks) checkKerberosTicket() {
	kc := bt.stateManager.GetKerberosClient()
	if kc != nil {
		slog.Debug("Performing periodic Kerberos ticket check/refresh...")
		if err := kc.CheckAndRefreshClient(); err != nil {
			slog.Warn("Periodic Kerberos check/refresh failed", "error", err)
		} else {
			slog.Debug("Kerberos ticket check/refresh successful.")
		}
	} else {
		slog.Debug("Skipping Kerberos check: client not initialized.")
	}
}

func (bt *BackgroundTasks) sendClientStatusPing() {
	if !bt.ipcManager.IsConnected() {
		slog.Debug("Cannot send status ping, IPC disconnected.") // Debug level as it's expected often
		return
	}
	slog.Debug("Sending status ping to service...")

	var kStatus ipc.ClientKerberosStatus
	kc := bt.stateManager.GetKerberosClient()
	if kc != nil {
		kStatus = ipc.ClientKerberosStatusToIPC(kc.GetStatus())
	} else {
		kStatus.Initialized = false
	}

	pingData := ipc.PingStatusData{
		ActiveConnections: bt.stateManager.GetActiveConnections(),
		KerberosStatus:    kStatus,
	}

	cmd, err := ipc.NewCommand("ping_status", pingData)
	if err != nil {
		slog.Error("Failed to create ping_status command", "error", err)
		return
	}

	if err := bt.ipcManager.SendIPCCommand(cmd); err != nil {
		// Error is logged within SendIPCCommand if connection drops etc.
		slog.Warn("Failed to send status ping to service", "error", err) // Warn level for send failure
	} else {
		slog.Debug("Status ping sent successfully.")
	}
}
