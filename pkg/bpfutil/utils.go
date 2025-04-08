package bpfutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
)

func IpFromInt(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip
}

func Ntohs(n uint16) uint16 {
	if common.NativeEndian == binary.LittleEndian {
		return (n >> 8) | (n << 8)
	}
	return n
}

func Htons(n uint16) uint16 {
	if common.NativeEndian == binary.LittleEndian {
		return (n >> 8) | (n << 8)
	}
	return n
}

func GetAvailableInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	var names []string
	for _, i := range interfaces {
		if (i.Flags&net.FlagUp == 0) || (i.Flags&net.FlagLoopback != 0) || (i.Flags&net.FlagPointToPoint != 0) {
			continue
		}
		if strings.HasPrefix(i.Name, "veth") || strings.HasPrefix(i.Name, "docker") ||
			strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "lo") ||
			strings.HasPrefix(i.Name, "virbr") || strings.HasPrefix(i.Name, "vnet") ||
			strings.HasPrefix(i.Name, "cni") || strings.HasPrefix(i.Name, "flannel") ||
			strings.HasPrefix(i.Name, "cali") || strings.HasPrefix(i.Name, "weave") {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil || len(addrs) == 0 {
			slog.Debug("Skipping interface with no addresses or error fetching them", "interface", i.Name, "error", err)
			continue
		}
		hasValidIP := false
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsInterfaceLocalMulticast() {
				hasValidIP = true
				break
			}
		}
		if !hasValidIP {
			slog.Debug("Skipping interface with no valid global IP address", "interface", i.Name)
			continue
		}

		names = append(names, i.Name)
	}
	if len(names) == 0 {
		slog.Warn("No suitable non-loopback, active network interfaces with global IP addresses found.")
	}
	return names, nil
}

func GetUidFromPid(pid uint32) (uint32, error) {
	statusFilePath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("process %d not found (likely exited): %w", pid, err)
		}
		return 0, fmt.Errorf("failed to read process status file %s: %w", statusFilePath, err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uidVal, err := strconv.ParseUint(fields[1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("failed to parse Real UID from status line '%s': %w", line, err)
				}
				return uint32(uidVal), nil
			}
		}
	}
	return 0, fmt.Errorf("uid not found in process status file %s", statusFilePath)
}
