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

// StateManager holds the shared state for the client application components.
type StateManager struct {
	configPtr      atomic.Pointer[config.Config]
	kerberosClient atomic.Pointer[kerb.KerberosClient]
	proxyManager   atomic.Pointer[proxy.ProxyManager]
	activeConns    atomic.Int64   // Tracks number of active proxied connections
	wg             sync.WaitGroup // Coordinates graceful shutdown
}

// NewStateManager creates a new StateManager instance.
// It requires a non-nil initial configuration.
func NewStateManager(initialConfig *config.Config) *StateManager {
	sm := &StateManager{}
	if initialConfig == nil {
		// This should ideally be prevented by the caller, but handle defensively.
		slog.Error("StateManager initialized with nil configuration! Using empty default.")
		sm.configPtr.Store(&config.Config{}) // Store an empty config to prevent nil panics later
	} else {
		sm.configPtr.Store(initialConfig)
	}
	return sm
}

// GetConfig returns a *copy* of the current configuration.
// This prevents modification of the shared state via the returned pointer.
func (sm *StateManager) GetConfig() *config.Config {
	cfg := sm.configPtr.Load()
	if cfg == nil {
		// Should not happen if constructor ensures non-nil, but handle defensively.
		slog.Error("GetConfig called when internal configuration pointer was nil!")
		return &config.Config{} // Return empty config
	}

	// Create a shallow copy. Deep copy specific fields if necessary.
	cfgCopy := *cfg

	// Example: Deep copy slices if they might be modified by the caller
	if cfg.EBPF.TargetPorts != nil {
		cfgCopy.EBPF.TargetPorts = make([]int, len(cfg.EBPF.TargetPorts))
		copy(cfgCopy.EBPF.TargetPorts, cfg.EBPF.TargetPorts)
	} else {
		cfgCopy.EBPF.TargetPorts = []int{} // Ensure it's not nil
	}
	// Add deep copies for other relevant fields (like EBPF.Excluded) if needed.

	return &cfgCopy
}

// SetConfig updates the configuration atomically.
// Note: Client currently does not support dynamic config reloading. This is for completeness.
func (sm *StateManager) SetConfig(cfg *config.Config) {
	if cfg == nil {
		slog.Error("Attempted to set nil configuration in StateManager")
		return
	}
	sm.configPtr.Store(cfg)
	slog.Info("Client configuration updated in StateManager (Note: dynamic reload not fully supported).")
}

// GetKerberosClient returns the current Kerberos client instance.
func (sm *StateManager) GetKerberosClient() *kerb.KerberosClient {
	return sm.kerberosClient.Load()
}

// SetKerberosClient sets the Kerberos client instance.
func (sm *StateManager) SetKerberosClient(k *kerb.KerberosClient) {
	sm.kerberosClient.Store(k)
}

// GetProxyManager returns the current ProxyManager instance.
func (sm *StateManager) GetProxyManager() *proxy.ProxyManager {
	return sm.proxyManager.Load()
}

// SetProxyManager sets the ProxyManager instance.
func (sm *StateManager) SetProxyManager(p *proxy.ProxyManager) {
	sm.proxyManager.Store(p)
}

// IncActiveConnections increments the count of active proxied connections.
func (sm *StateManager) IncActiveConnections() {
	sm.activeConns.Add(1)
}

// DecActiveConnections decrements the count of active proxied connections.
func (sm *StateManager) DecActiveConnections() {
	sm.activeConns.Add(-1)
}

// GetActiveConnections returns the current count of active proxied connections.
func (sm *StateManager) GetActiveConnections() int64 {
	return sm.activeConns.Load()
}

// AddWaitGroup adds delta to the WaitGroup counter. Used by goroutines to signal activity.
func (sm *StateManager) AddWaitGroup(delta int) {
	sm.wg.Add(delta)
}

// WaitGroupDone decrements the WaitGroup counter. Called when a goroutine finishes.
func (sm *StateManager) WaitGroupDone() {
	sm.wg.Done()
}

// Cleanup waits for all managed goroutines to finish and cleans up resources.
func (sm *StateManager) Cleanup() {
	slog.Debug("Waiting for all client goroutines to complete...")
	sm.wg.Wait() // Wait for AddWaitGroup/WaitGroupDone pairs
	slog.Debug("All client goroutines finished.")

	slog.Debug("Cleaning up client resources...")

	// Close Proxy Manager
	pm := sm.proxyManager.Load()
	if pm != nil {
		if err := pm.Close(); err != nil {
			slog.Error("Error closing proxy manager", "error", err)
		} else {
			slog.Debug("Proxy manager closed.")
		}
		sm.proxyManager.Store(nil) // Clear pointer
	}

	// Close Kerberos Client
	kc := sm.kerberosClient.Load()
	if kc != nil {
		kc.Close()
		slog.Debug("Kerberos client closed.")
		sm.kerberosClient.Store(nil) // Clear pointer
	}

	slog.Debug("Client resource cleanup finished.")
}
