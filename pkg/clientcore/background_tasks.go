// FILE: pkg/clientcore/background_tasks.go
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
)

type BackgroundTasks struct {
	stateManager *StateManager
	ipcManager   *IPCManager
	ctx          context.Context
	wg           *sync.WaitGroup
}

func NewBackgroundTasks(ctx context.Context, stateMgr *StateManager, ipcMgr *IPCManager) *BackgroundTasks {
	return &BackgroundTasks{
		stateManager: stateMgr,
		ipcManager:   ipcMgr,
		ctx:          ctx,
		wg:           &stateMgr.wg,
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

	kerbCheckTicker := time.NewTicker(kerberosCheckInterval)
	defer kerbCheckTicker.Stop()
	statusPingTicker := time.NewTicker(statusPingInterval)
	defer statusPingTicker.Stop()

	bt.checkKerberosTicket()

	for {
		select {
		case <-bt.ctx.Done():
			return

		case <-kerbCheckTicker.C:
			bt.checkKerberosTicket()

		case <-statusPingTicker.C:
			bt.sendClientStatusPing()
		}
	}
}

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
		slog.Debug("Cannot send status ping, IPC disconnected.")
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

		slog.Warn("Failed to send status ping to service", "error", err)
	} else {
		slog.Debug("Status ping sent successfully.")
	}
}
