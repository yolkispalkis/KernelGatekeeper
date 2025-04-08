package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/yolki/kernelgatekeeper/pkg/bpfutil"
)

func (m *BPFManager) readNotifications(ctx context.Context) {
	var bpfTuple BpfNotificationTupleT
	tupleSize := int(unsafe.Sizeof(bpfTuple))
	if tupleSize <= 0 {
		bsize := binary.Size(bpfTuple)
		if bsize <= 0 {
			slog.Error("Could not determine size of BpfNotificationTupleT (binary.Size and unsafe.Sizeof failed)", "size", bsize)
			return
		}
		tupleSize = bsize
	}
	slog.Debug("BPF ring buffer reader expecting record size", "size", tupleSize)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader due to context cancellation.")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF ring buffer reader due to stop signal.")
			return
		default:
		}

		record, err := m.notificationReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				slog.Info("BPF ring buffer reader closed.")
				return
			}
			if errors.Is(err, context.Canceled) {
				slog.Info("BPF ring buffer reading cancelled by context.")
				return
			}
			slog.Error("Error reading from BPF ring buffer", "error", err)
			select {
			case <-time.After(100 * time.Millisecond):
				continue
			case <-ctx.Done():
				return
			case <-m.stopChan:
				return
			}
		}
		slog.Debug("Received raw BPF ring buffer record", "len", len(record.RawSample))

		if len(record.RawSample) < tupleSize {
			slog.Warn("Received BPF ring buffer event with unexpected size, skipping.", "expected_min", tupleSize, "received", len(record.RawSample))
			continue
		}

		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, binary.NativeEndian, &bpfTuple); err != nil {
			slog.Error("Failed to decode BPF ring buffer event data into BpfNotificationTupleT", "error", err)
			continue
		}

		event := NotificationTuple{
			PidTgid:     bpfTuple.PidTgid,
			SrcIP:       bpfutil.IpFromInt(bpfTuple.SrcIp),
			OrigDstIP:   bpfutil.IpFromInt(bpfTuple.OrigDstIp),
			SrcPort:     bpfutil.Ntohs(bpfTuple.SrcPort),
			OrigDstPort: bpfutil.Ntohs(bpfTuple.OrigDstPort),
			Protocol:    bpfTuple.Protocol,
		}

		select {
		case m.notificationChannel <- event:
			slog.Debug("Sent BPF connection notification to service processor", "pid_tgid", event.PidTgid, "src_ip", event.SrcIP, "src_port", event.SrcPort, "orig_dst_ip", event.OrigDstIP, "orig_dst_port", event.OrigDstPort)
		case <-ctx.Done():
			slog.Info("Stopping BPF ring buffer reader while sending notification (context cancelled).")
			return
		case <-m.stopChan:
			slog.Info("Stopping BPF ring buffer reader while sending notification (stop signal).")
			return
		default:
			slog.Warn("BPF notification channel is full, dropping event.", "channel_cap", cap(m.notificationChannel), "channel_len", len(m.notificationChannel), "event_dst_port", event.OrigDstPort)
		}
	}
}
