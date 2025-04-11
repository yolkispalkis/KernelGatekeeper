// FILE: pkg/clientcore/state.go
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
}

func NewStateManager(initialConfig *config.Config) *StateManager {
	sm := &StateManager{}
	if initialConfig != nil {
		sm.configPtr.Store(initialConfig)
	} else {

		sm.configPtr.Store(&config.Config{})
		slog.Error("StateManager initialized with nil configuration!")
	}
	return sm
}

func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.configPtr.Load()
	if cfg == nil {

		return &config.Config{}
	}

	cfgCopy := *cfg
	if cfg.EBPF.TargetPorts != nil {
		cfgCopy.EBPF.TargetPorts = make([]int, len(cfg.EBPF.TargetPorts))
		copy(cfgCopy.EBPF.TargetPorts, cfg.EBPF.TargetPorts)
	} else {
		cfgCopy.EBPF.TargetPorts = []int{}
	}
	return &cfgCopy
}

func (sm *StateManager) SetConfig(cfg *config.Config) {
	sm.configPtr.Store(cfg)
	slog.Info("Client configuration updated in StateManager.")

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
