// FILE: pkg/clientcore/background_tasks.go
package clientcore

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/kerb"
)

const (
	clientPingInterval = 30 * time.Second
)

// BackgroundTasks manages periodic background operations for the client.
type BackgroundTasks struct {
	ctx          context.Context
	stateManager *StateManager
	ipcManager   *IPCManager
	wg           sync.WaitGroup
}

// NewBackgroundTasks creates a new BackgroundTasks manager.
func NewBackgroundTasks(ctx context.Context, stateMgr *StateManager, ipcMgr *IPCManager) *BackgroundTasks {
	return &BackgroundTasks{
		ctx:          ctx,
		stateManager: stateMgr,
		ipcManager:   ipcMgr,
	}
}

// Run starts the background tasks.
func (bt *BackgroundTasks) Run() {
	slog.Debug("Starting client background tasks")
	bt.wg.Add(1)
	go bt.runStatusPinger()

	bt.wg.Add(1)
	go bt.runKerberosRefresher()

	// Add other background tasks here if needed

	// Goroutine to wait for all background tasks to finish on context cancellation
	go func() {
		<-bt.ctx.Done()
		slog.Debug("Client background tasks context cancelled, waiting for tasks to stop.")
		bt.wg.Wait()
		slog.Debug("All client background tasks stopped.")
	}()
}

// runStatusPinger periodically sends status updates to the service via IPC.
func (bt *BackgroundTasks) runStatusPinger() {
	defer bt.wg.Done()
	slog.Debug("Starting client status pinger task", "interval", clientPingInterval)
	ticker := time.NewTicker(clientPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-bt.ctx.Done():
			slog.Info("Stopping client status pinger task (context cancelled)")
			return
		case <-ticker.C:
			if bt.ipcManager.IsConnected() {
				bt.sendStatusPing()
			} else {
				slog.Debug("Skipping status ping: IPC disconnected")
			}
		}
	}
}

// runKerberosRefresher periodically checks and refreshes the Kerberos ticket.
func (bt *BackgroundTasks) runKerberosRefresher() {
	defer bt.wg.Done()
	slog.Debug("Starting Kerberos refresher task")

	// Initial check almost immediately
	initialDelay := 5 * time.Second
	timer := time.NewTimer(initialDelay)

	for {
		select {
		case <-bt.ctx.Done():
			slog.Info("Stopping Kerberos refresher task (context cancelled)")
			timer.Stop()
			return
		case <-timer.C:
			kClient := bt.stateManager.GetKerberosClient()
			if kClient != nil {
				if err := kClient.CheckAndRefreshClient(); err != nil {
					// CheckAndRefreshClient logs errors internally
					slog.Warn("Error during periodic Kerberos refresh check", "error", err)
				}
			} else {
				slog.Debug("Skipping Kerberos refresh check: client not initialized")
			}

			// Determine next refresh interval based on current ticket expiry
			nextCheck := calculateNextKerberosCheck(kClient)
			slog.Debug("Next Kerberos refresh check scheduled", "delay", nextCheck)
			timer.Reset(nextCheck)
		}
	}
}

// sendStatusPing gathers status and sends it via IPC.
func (bt *BackgroundTasks) sendStatusPing() {
	statusData := bt.gatherStatusData()
	cmd, err := ipc.NewCommand("ping_status", statusData)
	if err != nil {
		slog.Error("Failed to create ping_status IPC command", "error", err)
		return
	}

	if err := bt.ipcManager.SendIPCCommand(cmd); err != nil {
		// SendIPCCommand handles logging appropriately
		slog.Warn("Failed to send status ping via IPC", "error", err)
	} else {
		slog.Debug("Sent status ping to service")
	}
}

// gatherStatusData collects current client status.
func (bt *BackgroundTasks) gatherStatusData() ipc.PingStatusData {
	kClient := bt.stateManager.GetKerberosClient()
	var kStatus ipc.ClientKerberosStatus
	if kClient != nil {
		// GetStatus returns a map, convert it
		clientKStatusMap := kClient.GetStatus()
		kStatus = ipc.ClientKerberosStatusToIPC(clientKStatusMap)
	}

	return ipc.PingStatusData{
		ActiveConnections: bt.stateManager.GetActiveConnections(),
		KerberosStatus:    kStatus,
	}
}

// calculateNextKerberosCheck determines how long to wait before the next check.
func calculateNextKerberosCheck(kClient *kerb.KerberosClient) time.Duration {
	const minCheckInterval = 1 * time.Minute
	const maxCheckInterval = 15 * time.Minute
	const checkBeforeExpiry = 5 * time.Minute

	if kClient == nil || !kClient.IsInitialized() {
		// If not initialized, check frequently hoping for a ticket
		return minCheckInterval
	}

	status := kClient.GetStatus()
	expiryStr, ok := status["tgt_expiry"].(string)
	if !ok || expiryStr == "N/A" || expiryStr == "Unknown (lookup failed)" {
		// Expiry unknown, check reasonably frequently
		return 5 * time.Minute
	}

	expiryTime, err := time.Parse(time.RFC3339, expiryStr)
	if err != nil {
		// Parse error, check reasonably frequently
		slog.Warn("Failed to parse TGT expiry time string for scheduling", "expiry_string", expiryStr, "error", err)
		return 5 * time.Minute
	}

	timeToExpiry := time.Until(expiryTime)

	if timeToExpiry <= checkBeforeExpiry {
		// Close to expiry, check very frequently
		return minCheckInterval
	}

	// Check sometime before expiry, but not too often
	checkInterval := timeToExpiry - checkBeforeExpiry
	if checkInterval > maxCheckInterval {
		checkInterval = maxCheckInterval
	}
	if checkInterval < minCheckInterval {
		checkInterval = minCheckInterval
	}

	return checkInterval
}
