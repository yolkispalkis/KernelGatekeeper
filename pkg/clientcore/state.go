package clientcore

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/kerb"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/proxy"
)

type StateManager struct {
	configPtr      atomic.Pointer[config.Config]
	kerberosClient atomic.Pointer[kerb.KerberosClient]
	proxyManager   atomic.Pointer[proxy.ProxyManager]
	activeConns    atomic.Int64
	wg             sync.WaitGroup
	// Removed initialSetupDone and initialSetupErr as setup happens synchronously in main
}

func NewStateManager(initialConfig *config.Config) *StateManager {
	sm := &StateManager{}
	if initialConfig != nil {
		sm.configPtr.Store(initialConfig)
	} else {
		// Store an empty config to avoid nil panics, though main should provide one
		sm.configPtr.Store(&config.Config{})
		slog.Error("StateManager initialized with nil configuration!")
	}
	return sm
}

func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.configPtr.Load()
	if cfg == nil {
		// Should not happen
		return &config.Config{}
	}
	// Return a shallow copy for safety, deep copy if needed later
	cfgCopy := *cfg
	if cfg.EBPF.TargetPorts != nil {
		cfgCopy.EBPF.TargetPorts = make([]int, len(cfg.EBPF.TargetPorts))
		copy(cfgCopy.EBPF.TargetPorts, cfg.EBPF.TargetPorts)
	} else {
		cfgCopy.EBPF.TargetPorts = []int{}
	}
	return &cfgCopy
}

// SetConfig allows updating the configuration, e.g., if client reloads its own config file.
func (sm *StateManager) SetConfig(cfg *config.Config) {
	sm.configPtr.Store(cfg)
	slog.Info("Client configuration updated in StateManager.")
	// Re-initialize Kerberos and Proxy Managers based on the new config?
	// This logic might need to be added if client-side config reload is implemented.
	// For now, assume config is set once at startup.
}

func (sm *StateManager) GetKerberosClient() *kerb.KerberosClient {
	return sm.kerberosClient.Load()
}

func (sm *StateManager) SetKerberosClient(k *kerb.KerberosClient) {
	sm.kerberosClient.Store(k)
}

func (sm *StateManager) GetProxyManager() *proxy.ProxyManager {
	return sm.proxyManager.Load()
}

func (sm *StateManager) SetProxyManager(p *proxy.ProxyManager) {
	sm.proxyManager.Store(p)
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

// Removed PerformInitialSetup and WaitForInitialSetup

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

// Removed Reconfigure, SetBackgroundTasks, GetBackgroundTasks as config refresh via IPC is removed.
// Background tasks still run but don't need explicit linking for config updates this way.
