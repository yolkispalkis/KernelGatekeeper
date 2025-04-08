package clientcore

import (
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/kerb"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/proxy"
)

type StateManager struct {
	configPtr        atomic.Pointer[config.Config]
	kerberosClient   atomic.Pointer[kerb.KerberosClient]
	proxyManager     atomic.Pointer[proxy.ProxyManager]
	activeConns      atomic.Int64
	wg               sync.WaitGroup
	initialSetupDone chan struct{}
	initialSetupErr  atomic.Pointer[error] // Store error during setup
}

func NewStateManager(initialConfig *config.Config) *StateManager {
	sm := &StateManager{
		initialSetupDone: make(chan struct{}),
	}
	if initialConfig != nil {
		sm.SetConfig(initialConfig)
	}
	return sm
}

func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.configPtr.Load()
	if cfg == nil {
		return &config.Config{} // Return empty config if not set
	}
	// Return a copy to prevent modification? For now, assume caller doesn't modify.
	return cfg
}

func (sm *StateManager) SetConfig(cfg *config.Config) {
	sm.configPtr.Store(cfg)
}

func (sm *StateManager) GetKerberosClient() *kerb.KerberosClient {
	return sm.kerberosClient.Load()
}

func (sm *StateManager) GetProxyManager() *proxy.ProxyManager {
	return sm.proxyManager.Load()
}

func (sm *StateManager) IncActiveConnections() {
	sm.activeConns.Add(1)
}

func (sm *StateManager) DecActiveConnections() {
	sm.activeConns.Add(-1)
}

func (sm *StateManager) GetActiveConnections() int64 {
	return sm.activeConns.Load()
}

func (sm *StateManager) AddWaitGroup(delta int) {
	sm.wg.Add(delta)
}

func (sm *StateManager) WaitGroupDone() {
	sm.wg.Done()
}

// PerformInitialSetup retrieves config via IPC and initializes Kerberos/Proxy managers.
// It signals completion or error via initialSetupDone and initialSetupErr.
func (sm *StateManager) PerformInitialSetup(ipc *IPCManager) {
	var setupErr error
	defer func() {
		if setupErr != nil {
			sm.initialSetupErr.Store(&setupErr)
		}
		close(sm.initialSetupDone) // Signal completion regardless of error
	}()

	slog.Info("Performing initial setup...")
	initialConfig, err := ipc.GetConfigFromService()
	if err != nil {
		setupErr = err
		slog.Error("Failed to get initial config from service", "error", setupErr)
		return
	}
	sm.SetConfig(initialConfig)

	kClient, kerr := kerb.NewKerberosClient(&initialConfig.Kerberos)
	if kerr != nil {
		setupErr = kerr
		slog.Error("Failed to initialize Kerberos client", "error", setupErr)
		return
	}
	sm.kerberosClient.Store(kClient)
	slog.Info("Kerberos client initialized.")

	pMgr, perr := proxy.NewProxyManager(&initialConfig.Proxy)
	if perr != nil {
		setupErr = perr
		slog.Error("Failed to initialize Proxy Manager", "error", setupErr)
		if kClient != nil {
			kClient.Close()
		}
		sm.kerberosClient.Store(nil)
		return
	}
	sm.proxyManager.Store(pMgr)
	slog.Info("Proxy Manager initialized.")
}

// WaitForInitialSetup blocks until initial setup is complete and returns any error.
func (sm *StateManager) WaitForInitialSetup() error {
	<-sm.initialSetupDone
	errPtr := sm.initialSetupErr.Load()
	if errPtr != nil {
		return *errPtr
	}
	return nil
}

func (sm *StateManager) Cleanup() {
	slog.Debug("Waiting for all client goroutines to complete...")
	sm.wg.Wait()
	slog.Debug("All client goroutines finished.")

	slog.Debug("Cleaning up client resources...")
	pm := sm.proxyManager.Load()
	if pm != nil {
		if err := pm.Close(); err != nil {
			slog.Error("Error closing proxy manager", "error", err)
		} else {
			slog.Debug("Proxy manager closed.")
		}
	}
	kc := sm.kerberosClient.Load()
	if kc != nil {
		kc.Close()
		slog.Debug("Kerberos client closed.")
	}
}

// Reconfigure applies changes from a new configuration.
func (sm *StateManager) Reconfigure(newCfg *config.Config) {
	currentCfg := sm.GetConfig()

	// Apply Proxy changes
	if !reflect.DeepEqual(currentCfg.Proxy, newCfg.Proxy) {
		slog.Info("Proxy configuration changed, re-initializing proxy manager.")
		oldPM := sm.proxyManager.Load()
		if oldPM != nil {
			oldPM.Close()
		}
		newPM, err := proxy.NewProxyManager(&newCfg.Proxy)
		if err != nil {
			slog.Error("Failed to re-initialize proxy manager after config refresh", "error", err)
			sm.proxyManager.Store(nil) // Ensure old one isn't used
		} else {
			sm.proxyManager.Store(newPM)
			slog.Info("Proxy manager re-initialized.")
		}
	}

	// Apply Kerberos changes
	if !reflect.DeepEqual(currentCfg.Kerberos, newCfg.Kerberos) {
		slog.Info("Kerberos configuration changed, re-initializing Kerberos client.")
		oldKC := sm.kerberosClient.Load()
		if oldKC != nil {
			oldKC.Close()
		}
		newKC, err := kerb.NewKerberosClient(&newCfg.Kerberos)
		if err != nil {
			slog.Error("Failed to re-initialize Kerberos client after config refresh", "error", err)
			sm.kerberosClient.Store(nil)
		} else {
			sm.kerberosClient.Store(newKC)
			slog.Info("Kerberos client re-initialized.")
		}
	}

	// Update the config atomically
	sm.SetConfig(newCfg)
	slog.Info("Client configuration updated.")
}
