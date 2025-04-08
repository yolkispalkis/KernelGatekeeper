package clientcore

import (
	"context"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/yolki/kernelgatekeeper/pkg/ipc"
)

const (
	kerberosCheckInterval = 5 * time.Minute
	configRefreshInterval = 15 * time.Minute
	// statusPingInterval is defined in ipc_manager.go
)

type BackgroundTasks struct {
	stateManager *StateManager
	ipcManager   *IPCManager
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
	configRefreshTicker := time.NewTicker(configRefreshInterval)
	defer configRefreshTicker.Stop()
	kerbCheckTicker := time.NewTicker(kerberosCheckInterval)
	defer kerbCheckTicker.Stop()
	statusPingTicker := time.NewTicker(statusPingInterval)
	defer statusPingTicker.Stop()

	// Run initial checks immediately if possible after setup
	if err := bt.stateManager.WaitForInitialSetup(); err == nil {
		bt.RefreshConfiguration() // Run first refresh after setup succeeds
		bt.checkKerberosTicket()
	} else {
		slog.Warn("Skipping initial background checks due to setup error", "error", err)
	}

	for {
		select {
		case <-bt.ctx.Done():
			return

		case <-configRefreshTicker.C:
			bt.RefreshConfiguration()

		case <-kerbCheckTicker.C:
			bt.checkKerberosTicket()

		case <-statusPingTicker.C:
			bt.sendClientStatusPing()
		}
	}
}

func (bt *BackgroundTasks) RefreshConfiguration() {
	slog.Info("Attempting configuration refresh...")
	if !bt.ipcManager.IsConnected() {
		slog.Warn("Cannot refresh config, IPC disconnected.")
		return
	}

	newCfg, err := bt.ipcManager.GetConfigFromService()
	if err != nil {
		slog.Error("Failed to refresh configuration from service", "error", err)
		// IPCManager's connection loop will handle disconnects
		return
	}

	currentCfg := bt.stateManager.GetConfig()
	configChanged := !reflect.DeepEqual(currentCfg.Proxy, newCfg.Proxy) ||
		!reflect.DeepEqual(currentCfg.Kerberos, newCfg.Kerberos)

	if configChanged {
		slog.Info("Configuration change detected, applying...")
		bt.stateManager.Reconfigure(newCfg) // Use StateManager method to reconfigure
	} else {
		slog.Info("Configuration unchanged after refresh check.")
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
	}
}

func (bt *BackgroundTasks) sendClientStatusPing() {
	if !bt.ipcManager.IsConnected() {
		slog.Warn("Cannot send status ping, IPC disconnected.")
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
		// Error is logged within SendIPCCommand if needed
		slog.Error("Failed to send status ping to service", "error", err)
	} else {
		slog.Debug("Status ping sent successfully.")
	}
}

// Add this method to StateManager struct definition in state.go
// backgroundTasks BackgroundTasks
