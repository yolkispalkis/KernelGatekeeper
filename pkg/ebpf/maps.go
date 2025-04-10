// FILE: pkg/ebpf/maps.go
package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"

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

func (m *BPFManager) UpdateConfigMap(listenerIP net.IP, listenerPort uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	configMap := m.objs.KgConfig
	if configMap == nil {
		return errors.New("BPF kg_config map not initialized")
	}

	ipv4 := listenerIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("listener IP is not IPv4: %s", listenerIP.String())
	}

	var listenerIPInt uint32
	buf := bytes.NewReader(ipv4)
	err := binary.Read(buf, binary.BigEndian, &listenerIPInt)
	if err != nil {
		return fmt.Errorf("failed to convert listener IP to uint32: %w", err)
	}

	cfgValue := BpfKgConfigT{
		ListenerIp:   listenerIPInt,
		ListenerPort: listenerPort,
		Padding:      0,
	}

	var mapKey uint32 = 0
	if err := configMap.Update(mapKey, cfgValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update kg_config BPF map: %w", err)
	}

	slog.Info("BPF config map updated", "listener_ip", listenerIP, "listener_port", listenerPort)
	return nil
}

func (m *BPFManager) AddExcludedPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clientPidsMap := m.objs.KgClientPids
	if clientPidsMap == nil {
		return errors.New("BPF kg_client_pids map not initialized")
	}

	var mapValue uint8 = 1
	if err := clientPidsMap.Put(pid, mapValue); err != nil {
		return fmt.Errorf("failed to add excluded PID %d to BPF map: %w", pid, err)
	}
	slog.Debug("Added excluded PID to BPF map", "pid", pid)
	return nil
}

func (m *BPFManager) RemoveExcludedPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clientPidsMap := m.objs.KgClientPids
	if clientPidsMap == nil {
		return errors.New("BPF kg_client_pids map not initialized")
	}

	if err := clientPidsMap.Delete(pid); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Debug("Attempted to remove non-existent excluded PID from BPF map", "pid", pid)
			return nil
		}
		return fmt.Errorf("failed to delete excluded PID %d from BPF map: %w", pid, err)
	}
	slog.Debug("Removed excluded PID from BPF map", "pid", pid)
	return nil
}
