package ebpf

import (
	"errors"
	"log/slog"

	"github.com/cilium/ebpf"
)

func (m *BPFManager) UpdateTargetPorts(ports []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	targetPortsMap := m.objs.TargetPorts
	if targetPortsMap == nil {
		return errors.New("BPF target_ports map not initialized (was it loaded?)")
	}
	currentPortsMap := make(map[uint16]bool)
	var mapKey uint16
	var mapValue uint8
	iter := targetPortsMap.Iterate()
	for iter.Next(&mapKey, &mapValue) {
		if mapValue == 1 {
			currentPortsMap[mapKey] = true
		}
	}
	if err := iter.Err(); err != nil {
		slog.Warn("Failed to fully iterate existing BPF target_ports map, proceeding with update anyway", "error", err)
		currentPortsMap = make(map[uint16]bool)
	}
	desiredPortsSet := make(map[uint16]bool)
	validNewPortsList := make([]int, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			portKey := uint16(p)
			desiredPortsSet[portKey] = true
			validNewPortsList = append(validNewPortsList, p)
		} else {
			slog.Warn("Invalid port number ignored in UpdateTargetPorts", "port", p)
		}
	}
	deletedCount := 0
	for portKey := range currentPortsMap {
		if !desiredPortsSet[portKey] {
			if err := targetPortsMap.Delete(portKey); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					slog.Error("Failed to delete target port from BPF map", "port", portKey, "error", err)
				}
			} else {
				slog.Debug("Deleted target port from BPF map", "port", portKey)
				deletedCount++
			}
		}
	}
	addedCount := 0
	var mapValueOne uint8 = 1
	for portKey := range desiredPortsSet {
		if !currentPortsMap[portKey] {
			if err := targetPortsMap.Put(portKey, mapValueOne); err != nil {
				slog.Error("Failed to add target port to BPF map", "port", portKey, "error", err)
			} else {
				slog.Debug("Added target port to BPF map", "port", portKey)
				addedCount++
			}
		}
	}
	if addedCount > 0 || deletedCount > 0 {
		slog.Info("BPF target ports map updated", "added", addedCount, "deleted", deletedCount, "final_list", validNewPortsList)
	} else {
		slog.Debug("BPF target ports map remains unchanged", "current_list", validNewPortsList)
	}
	if m.cfg != nil {
		m.cfg.TargetPorts = validNewPortsList
	}
	return nil
}
