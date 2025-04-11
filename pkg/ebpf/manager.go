package ebpf

//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_connect4 ./bpf/connect4.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_sockops ./bpf/sockops.c -- -I./bpf
//go:generate go run -tags linux github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -DDEBUG -I./bpf -I/usr/include/bpf -I/usr/include -I/usr/include/x86_64-linux-gnu" bpf_getsockopt ./bpf/getsockopt.c -- -I./bpf

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
	"github.com/cilium/ebpf/rlimit"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

const (
	StatsRedirectedIndex     uint32 = 1
	StatsGetsockoptOkIndex   uint32 = 2
	StatsGetsockoptFailIndex uint32 = 3
	DefaultCgroupPath               = "/sys/fs/cgroup"
)

type GlobalStats struct {
	Packets        uint64
	Bytes          uint64
	Redirected     uint64
	GetsockoptOk   uint64
	GetsockoptFail uint64
}

type OriginalDestT = bpf_connect4OriginalDestT

type BpfGlobalStatsT = bpf_connect4GlobalStatsT
type BpfKgConfigT = bpf_connect4KgConfigT

type bpfObjects struct {
	bpf_connect4Objects
	bpf_sockopsObjects
	bpf_getsockoptObjects

	KernelgatekeeperConnect4   *ebpf.Program `ebpf:"kernelgatekeeper_connect4"`
	KernelgatekeeperSockops    *ebpf.Program `ebpf:"kernelgatekeeper_sockops"`
	KernelgatekeeperGetsockopt *ebpf.Program `ebpf:"kernelgatekeeper_getsockopt"`
	KgOrigDest                 *ebpf.Map     `ebpf:"kg_orig_dest"`
	KgPortToCookie             *ebpf.Map     `ebpf:"kg_port_to_cookie"`
	TargetPorts                *ebpf.Map     `ebpf:"target_ports"`
	KgClientPids               *ebpf.Map     `ebpf:"kg_client_pids"`
	KgConfig                   *ebpf.Map     `ebpf:"kg_config"`
	KgStats                    *ebpf.Map     `ebpf:"kg_stats"`
}

func (o *bpfObjects) Close() error {
	closers := []io.Closer{
		&o.bpf_connect4Objects,
		&o.bpf_sockopsObjects,
		&o.bpf_getsockoptObjects,
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
	sockopsLink         link.Link
	getsockoptLink      link.Link
	stopOnce            sync.Once
	stopChan            chan struct{}
	statsCache          StatsCache
	mu                  sync.Mutex
	notificationReader  *ringbuf.Reader             // Added field
	notificationChannel chan ebpf.NotificationTuple // Added field
}

func NewBPFManager(cfg *config.EBPFConfig, listenerIP net.IP, listenerPort uint16) (*BPFManager, error) {
	slog.Info("Initializing BPF Manager", "mode", "connect4/sockops/getsockopt")
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	var objs bpfObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/kernelgatekeeper",
		},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}

	opts.MapReplacements = map[string]*ebpf.MapSpec{
		"kg_orig_dest":      {Name: "kg_orig_dest", MaxEntries: uint32(cfg.OrigDestMapSize)},
		"kg_port_to_cookie": {Name: "kg_port_to_cookie", MaxEntries: uint32(cfg.PortMapSize)},
	}

	specConnect4, err := loadBpf_connect4()
	if err != nil {
		return nil, fmt.Errorf("failed to load connect4 BPF spec: %w", err)
	}
	specSockops, err := loadBpf_sockops()
	if err != nil {
		return nil, fmt.Errorf("failed to load sockops BPF spec: %w", err)
	}
	specGetsockopt, err := loadBpf_getsockopt()
	if err != nil {
		return nil, fmt.Errorf("failed to load getsockopt BPF spec: %w", err)
	}

	if err := specConnect4.LoadAndAssign(&objs.bpf_connect4Objects, opts); err != nil {
		handleVerifierError("connect4", err)
		return nil, fmt.Errorf("failed to load eBPF connect4 objects: %w", err)
	}
	slog.Debug("eBPF connect4 objects loaded successfully.")

	objs.KernelgatekeeperConnect4 = objs.bpf_connect4Objects.KernelgatekeeperConnect4
	objs.KgOrigDest = objs.bpf_connect4Objects.KgOrigDest
	objs.KgPortToCookie = objs.bpf_connect4Objects.KgPortToCookie
	objs.TargetPorts = objs.bpf_connect4Objects.TargetPorts
	objs.KgClientPids = objs.bpf_connect4Objects.KgClientPids
	objs.KgConfig = objs.bpf_connect4Objects.KgConfig
	objs.KgStats = objs.bpf_connect4Objects.KgStats

	opts.MapReplacements = map[string]*ebpf.Map{
		"kg_orig_dest":      objs.KgOrigDest,
		"kg_port_to_cookie": objs.KgPortToCookie,
		"target_ports":      objs.TargetPorts,
		"kg_client_pids":    objs.KgClientPids,
		"kg_config":         objs.KgConfig,
		"kg_stats":          objs.KgStats,
	}
	if err := specSockops.LoadAndAssign(&objs.bpf_sockopsObjects, opts); err != nil {
		handleVerifierError("sockops", err)
		objs.bpf_connect4Objects.Close()
		return nil, fmt.Errorf("failed to load eBPF sockops objects: %w", err)
	}
	slog.Debug("eBPF sockops objects loaded successfully.")
	objs.KernelgatekeeperSockops = objs.bpf_sockopsObjects.KernelgatekeeperSockops

	opts.MapReplacements = map[string]*ebpf.Map{
		"kg_orig_dest":      objs.KgOrigDest,
		"kg_port_to_cookie": objs.KgPortToCookie,
		"kg_stats":          objs.KgStats,
	}
	if err := specGetsockopt.LoadAndAssign(&objs.bpf_getsockoptObjects, opts); err != nil {
		handleVerifierError("getsockopt", err)
		objs.bpf_connect4Objects.Close()
		objs.bpf_sockopsObjects.Close()
		return nil, fmt.Errorf("failed to load eBPF getsockopt objects: %w", err)
	}
	slog.Debug("eBPF getsockopt objects loaded successfully.")
	objs.KernelgatekeeperGetsockopt = objs.bpf_getsockoptObjects.KernelgatekeeperGetsockopt

	manager := &BPFManager{
		cfg:                 cfg,
		objs:                objs,
		stopChan:            make(chan struct{}),
		notificationChannel: make(chan NotificationTuple, cfg.NotificationChannelSize), // Initialize channel
	}
	manager.statsCache.lastStatsTime = time.Now()

	if objs.KernelgatekeeperConnect4 == nil || objs.KernelgatekeeperSockops == nil || objs.KernelgatekeeperGetsockopt == nil ||
		objs.KgOrigDest == nil || objs.KgPortToCookie == nil || objs.TargetPorts == nil || objs.KgClientPids == nil ||
		objs.KgConfig == nil || objs.KgStats == nil {
		manager.objs.Close()
		return nil, errors.New("one or more required BPF programs or maps failed to load or assign after merging objects")
	}

	// Initialize ring buffer reader if the map exists
	if objs.KgNotifRb != nil {
		rd, err := ringbuf.NewReader(objs.KgNotifRb)
		if err != nil {
			manager.Close()
			return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
		}
		manager.notificationReader = rd
		slog.Info("BPF ring buffer reader initialized.")
	} else {
		slog.Warn("BPF map 'kg_notif_rb' not found, notification reader will not be started.")
	}

	if err := manager.UpdateConfigMap(listenerIP, listenerPort); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to set initial BPF config map: %w", err)
	}

	if err := manager.attachPrograms(DefaultCgroupPath); err != nil {
		manager.Close()
		return nil, err
	}

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
	getsockoptProg := m.objs.KernelgatekeeperGetsockopt

	if connect4Prog == nil || sockopsProg == nil || getsockoptProg == nil {
		return errors.New("internal error: one or more required BPF programs are nil during attach phase")
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

	m.sockopsLink, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: sockopsProg, Attach: ebpf.AttachCGroupSockOps})
	if linkErr != nil {
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach sock_ops program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF sock_ops program attached to cgroup", "path", cgroupPath)

	m.getsockoptLink, linkErr = link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: getsockoptProg, Attach: ebpf.AttachCGroupGetsockopt})
	if linkErr != nil {
		m.sockopsLink.Close()
		m.connect4Link.Close()
		return fmt.Errorf("failed to attach getsockopt program to cgroup '%s': %w", cgroupPath, linkErr)
	}
	slog.Info("eBPF getsockopt program attached to cgroup", "path", cgroupPath)

	return nil
}

func (m *BPFManager) Start(ctx context.Context, wg *sync.WaitGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	slog.Info("Starting BPF Manager background tasks (stats updater)...")

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("BPF statistics updater task started.")
		m.statsUpdater(ctx)
		slog.Info("BPF statistics updater task stopped.")
	}()

	// Start the ring buffer reader only if it was initialized
	if m.notificationReader != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("BPF ring buffer notification reader task started.")
			m.readNotifications(ctx)
			slog.Info("BPF ring buffer notification reader task stopped.")
		}()
	} else {
		slog.Warn("BPF notification reader task not started (reader not initialized).")
	}

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

		// Close the ring buffer reader first
		if m.notificationReader != nil {
			slog.Debug("Closing BPF ring buffer reader...")
			if err := m.notificationReader.Close(); err != nil {
				slog.Error("Error closing BPF ring buffer reader", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("ring buffer reader close: %w", err)
				}
			}
			m.notificationReader = nil
		}

		if m.getsockoptLink != nil {
			slog.Debug("Closing BPF getsockopt link...")
			if err := m.getsockoptLink.Close(); err != nil {
				slog.Error("Error closing BPF getsockopt link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("getsockopt link close: %w", err)
				}
			}
			m.getsockoptLink = nil
		}
		if m.sockopsLink != nil {
			slog.Debug("Closing BPF cgroup sock_ops link...")
			if err := m.sockopsLink.Close(); err != nil {
				slog.Error("Error closing BPF cgroup sock_ops link", "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("cgroup sock_ops link close: %w", err)
				}
			}
			m.sockopsLink = nil
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

		// Close the notification channel
		if m.notificationChannel != nil {
			close(m.notificationChannel)
			m.notificationChannel = nil
		}

		slog.Info("BPF Manager closed.")
	})
	return firstErr
}

// GetNotificationChannel returns the channel for receiving BPF notifications.
func (m *BPFManager) GetNotificationChannel() <-chan NotificationTuple {
	return m.notificationChannel
}
