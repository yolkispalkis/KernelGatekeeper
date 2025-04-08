package ebpf

//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf" bpf_connect4 ./bpf/connect4.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf" bpf_sockops ./bpf/sockops.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf" bpf_skmsg ./bpf/skmsg.c -- -I./bpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

const (
	GlobalStatsMatchedIndex uint32 = 1
	DefaultCgroupPath              = "/sys/fs/cgroup"
	verifierLogSize                = 2 * 1024 * 1024 // Ensure this is an int or uint, not a specific type incompatible with LogSize if LogSize has a specific underlying type (though it's likely `uint`)
)

type GlobalStats struct {
	Packets uint64
	Bytes   uint64
}

type NotificationTuple struct {
	PidTgid     uint64
	SrcIP       net.IP
	OrigDstIP   net.IP
	SrcPort     uint16
	OrigDstPort uint16
	Protocol    uint8
}

type BpfConnectionDetailsT = bpf_connect4ConnectionDetailsT

type BpfNotificationTupleT struct {
	PidTgid     uint64
	SrcIp       uint32
	OrigDstIp   uint32
	SrcPort     uint16
	OrigDstPort uint16
	Protocol    uint8
	Padding     [5]uint8
}

type BpfGlobalStatsT = bpf_connect4GlobalStatsT

type bpfObjects struct {
	bpf_connect4Objects
	bpf_sockopsObjects
	bpf_skmsgObjects

	KernelgatekeeperConnect4 *ebpf.Program `ebpf:"kernelgatekeeper_connect4"`
	KernelgatekeeperSockops  *ebpf.Program `ebpf:"kernelgatekeeper_sockops"`
	KernelgatekeeperSkmsg    *ebpf.Program `ebpf:"kernelgatekeeper_skmsg"`
	ConnectionDetailsMap     *ebpf.Map     `ebpf:"connection_details_map"`
	TargetPorts              *ebpf.Map     `ebpf:"target_ports"`
	ProxySockMap             *ebpf.Map     `ebpf:"proxy_sock_map"`
	NotificationRingbuf      *ebpf.Map     `ebpf:"notification_ringbuf"`
	GlobalStats              *ebpf.Map     `ebpf:"global_stats"`
}

func (o *bpfObjects) Close() error {
	closers := []io.Closer{
		&o.bpf_connect4Objects,
		&o.bpf_sockopsObjects,
		&o.bpf_skmsgObjects,
	}
	var errs []error
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil {
			if !errors.Is(err, os.ErrClosed) {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		finalErr := errors.New("errors closing BPF objects")
		for _, err := range errs {
			finalErr = fmt.Errorf("%w; %w", finalErr, err)
		}
		return finalErr
	}
	return nil
}

type BPFManager struct {
	cfg                 *config.EBPFConfig
	objs                bpfObjects
	connect4Link        link.Link
	cgroupLink          link.Link
	skMsgLink           link.Link
	notificationReader  *ringbuf.Reader
	notificationChannel chan<- NotificationTuple
	stopOnce            sync.Once
	stopChan            chan struct{}
	statsCache          StatsCache
	mu                  sync.Mutex
}

func NewBPFManager(cfg *config.EBPFConfig, notifChan chan<- NotificationTuple) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "connect4/sockops/skmsg")
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	var objs bpfObjects
	// This structure aligns with cilium/ebpf v0.18.0 documentation
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  verifierLogSize, // LogSize is a field of ProgramOptions
		},
	}

	specConnect4, err := loadBpf_connect4()
	if err != nil {
		return nil, fmt.Errorf("failed to load connect4 BPF spec: %w", err)
	}
	specSockops, err := loadBpf_sockops()
	if err != nil {
		return nil, fmt.Errorf("failed to load sockops BPF spec: %w", err)
	}
	specSkmsg, err := loadBpf_skmsg()
	if err != nil {
		return nil, fmt.Errorf("failed to load skmsg BPF spec: %w", err)
	}

	if err := specConnect4.LoadAndAssign(&objs.bpf_connect4Objects, opts); err != nil {
		handleVerifierError("connect4", err)
		return nil, fmt.Errorf("failed to load eBPF connect4 objects: %w", err)
	}
	slog.Debug("eBPF connect4 objects loaded successfully.")
	objs.KernelgatekeeperConnect4 = objs.bpf_connect4Objects.KernelgatekeeperConnect4
	objs.ConnectionDetailsMap = objs.bpf_connect4Objects.ConnectionDetailsMap
	objs.TargetPorts = objs.bpf_connect4Objects.TargetPorts
	objs.ProxySockMap = objs.bpf_connect4Objects.ProxySockMap
	objs.NotificationRingbuf = objs.bpf_connect4Objects.NotificationRingbuf
	objs.GlobalStats = objs.bpf_connect4Objects.GlobalStats

	opts.MapReplacements = map[string]*ebpf.Map{
		"connection_details_map": objs.ConnectionDetailsMap,
		"target_ports":           objs.TargetPorts,
		"proxy_sock_map":         objs.ProxySockMap,
		"notification_ringbuf":   objs.NotificationRingbuf,
		"global_stats":           objs.GlobalStats,
	}
	if err := specSockops.LoadAndAssign(&objs.bpf_sockopsObjects, opts); err != nil {
		handleVerifierError("sockops", err)
		objs.bpf_connect4Objects.Close()
		return nil, fmt.Errorf("failed to load eBPF sockops objects: %w", err)
	}
	slog.Debug("eBPF sockops objects loaded successfully.")
	objs.KernelgatekeeperSockops = objs.bpf_sockopsObjects.KernelgatekeeperSockops

	opts.MapReplacements = map[string]*ebpf.Map{
		"proxy_sock_map": objs.ProxySockMap,
	}
	if err := specSkmsg.LoadAndAssign(&objs.bpf_skmsgObjects, opts); err != nil {
		handleVerifierError("skmsg", err)
		objs.bpf_connect4Objects.Close()
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load eBPF skmsg objects: %w", err)
	}
	slog.Debug("eBPF skmsg objects loaded successfully.")
	objs.KernelgatekeeperSkmsg = objs.bpf_skmsgObjects.KernelgatekeeperSkmsg

	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs,
		notificationChannel: notifChan,
		stopChan:            make(chan struct{}),
	}
	manager.statsCache.lastStatsTime = time.Now()

	if objs.KernelgatekeeperConnect4 == nil || objs.KernelgatekeeperSockops == nil || objs.KernelgatekeeperSkmsg == nil ||
		objs.ConnectionDetailsMap == nil || objs.TargetPorts == nil || objs.ProxySockMap == nil ||
		objs.NotificationRingbuf == nil || objs.GlobalStats == nil {
		manager.objs.Close()
		return nil, errors.New("one or more required BPF programs or maps failed to load or assign after merging objects")
	}

	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close()
		return nil, err
	}

	var ringbufErr error
	manager.notificationReader, ringbufErr = ringbuf.NewReader(objs.NotificationRingbuf)
	if ringbufErr != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", ringbufErr)
	}
	slog.Info("BPF ring buffer reader initialized")

	if err := manager.UpdateTargetPorts(cfg.TargetPorts); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial target ports in BPF map: %w", err)
	}

	slog.Info("BPF Manager initialized and programs attached successfully.")
	return manager, nil
}

func handleVerifierError(objType string, err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		slog.Error(fmt.Sprintf("eBPF Verifier error (loading %s objects)", objType), "log", fmt.Sprintf("%+v", verr))
	}
}

func (m *BPFManager) attachPrograms(cgroupPath string) error {
	connect4Prog := m.objs.KernelgatekeeperConnect4
	sockopsProg := m.objs.KernelgatekeeperSockops
	skmsgProg := m.objs.KernelgatekeeperSkmsg
	sockMap := m.objs.ProxySockMap
	if connect4Prog == nil || sockopsProg == nil || skmsgProg == nil || sockMap == nil {
		return errors.New("internal error: one or more required BPF programs or the sockmap are nil during attach phase")
	}
	fi, err := os.Stat(cgroupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("cgroup v2 path '%s' does not exist", cgroupPath)
		}
		return fmt.Errorf("failed to stat cgroup v2 path '%s': %w", cgroupPath, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("cgroup v2 path '%s' is not a directory", cgroupPath)
	}
	var linkErr error
	m.connect4Link, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: connect4Prog, Attach: ebpf.AttachCGroupInet4Connect})
	if linkErr != nil {
		return fmt.Errorf("failed to attach connect4 program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF connect4 program attached to cgroup", "path", cgroupPath)
	m.cgroupLink, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: sockopsProg, Attach: ebpf.AttachCGroupSockOps})
	if linkErr != nil {
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sock_ops program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF sock_ops program attached to cgroup", "path", cgroupPath)
	m.skMsgLink, linkErr = link.AttachRawLink(link.RawLinkOptions{Program: skmsgProg, Attach: ebpf.AttachSkMsgVerdict, Target: sockMap.FD(), Flags: 0})
	if linkErr != nil {
		m.cgroupLink.Close()
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sk_msg program to proxy_sock_map (FD %d): %w", sockMap.FD(), linkErr)
	}
	slog.Info("eBPF sk_msg program attached to proxy_sock_map", "map_fd", sockMap.FD())
	return nil
}

func (m *BPFManager) Start(ctx context.Context, wg *sync.WaitGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.notificationReader == nil {
		return errors.New("BPF manager not fully initialized (notificationReader is nil), cannot start tasks")
	}
	slog.Info("Starting BPF Manager background tasks (ring buffer reader, stats updater)...")
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("BPF ring buffer reader task started.")
		m.readNotifications(ctx)
		slog.Info("BPF ring buffer reader task stopped.")
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("BPF statistics updater task started.")
		m.statsUpdater(ctx)
		slog.Info("BPF statistics updater task stopped.")
	}()
	return nil
}

func (m *BPFManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	m.stopOnce.Do(func() {
		slog.Info("Closing BPF Manager...")
		select {
		case <-m.stopChan:
		default:
			close(m.stopChan)
		}

		if m.notificationReader != nil {
			slog.Debug("Closing BPF ring buffer reader...")
			if err := m.notificationReader.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, ringbuf.ErrClosed) {
				slog.Error("Error closing BPF ringbuf reader", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("ringbuf close: %w", err)
				}
			}
			m.notificationReader = nil
		}

		if m.skMsgLink != nil {
			slog.Debug("Closing BPF sk_msg link...")
			if err := m.skMsgLink.Close(); err != nil {
				slog.Error("Error closing BPF sk_msg link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("sk_msg link close: %w", err)
				}
			}
			m.skMsgLink = nil
		}
		if m.cgroupLink != nil {
			slog.Debug("Closing BPF cgroup sock_ops link...")
			if err := m.cgroupLink.Close(); err != nil {
				slog.Error("Error closing BPF cgroup sock_ops link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("cgroup sock_ops link close: %w", err)
				}
			}
			m.cgroupLink = nil
		}
		if m.connect4Link != nil {
			slog.Debug("Closing BPF cgroup connect4 link...")
			if err := m.connect4Link.Close(); err != nil {
				slog.Error("Error closing BPF cgroup connect4 link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("cgroup connect4 link close: %w", err)
				}
			}
			m.connect4Link = nil
		}

		slog.Debug("Closing all BPF objects (programs and maps)...")
		if err := m.objs.Close(); err != nil {
			slog.Error("Error closing BPF objects", "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("bpf objects close: %w", err)
			} else {
				firstErr = fmt.Errorf("%w; bpf objects close: %w", firstErr, err)
			}
		}
		slog.Info("BPF Manager closed.")
	})
	return firstErr
}
