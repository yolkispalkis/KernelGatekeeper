// FILE: pkg/servicecore/bpf_processor.go
package servicecore

import (
	"context"
	"encoding/json"
	"errors" // Используется для net.ErrClosed
	"fmt"
	"io"
	"log/slog"
	"net" // Используется для net.Conn, net.ErrClosed
	"time"

	"github.com/yolkispalkis/kernelgatekeeper/pkg/bpfutil"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/common"
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ebpf" // Import ebpf
	"github.com/yolkispalkis/kernelgatekeeper/pkg/ipc"
)

const (
	ipcSendTimeout = 2 * time.Second
	// Интервал проверки конфига больше не нужен для excludedPaths здесь
	// configCheckInterval = 10 * time.Second
)

type BpfProcessor struct {
	stateManager *StateManager
	clientMgr    *ClientManager
	// FIX: Use the correct type from ebpf package
	notifChan <-chan ebpf.NotificationTuple // Используем тип из ebpf
}

func NewBpfProcessor(stateMgr *StateManager) *BpfProcessor {
	if stateMgr == nil || stateMgr.GetClientManager() == nil || stateMgr.GetNotificationChannel() == nil {
		slog.Error("FATAL: BpfProcessor created with nil StateManager, ClientManager or NotificationChannel")
		// В реальном коде здесь лучше паниковать или возвращать ошибку
		return nil
	}

	return &BpfProcessor{
		stateManager: stateMgr,
		clientMgr:    stateMgr.GetClientManager(),
		notifChan:    stateMgr.GetNotificationChannel(),
	}
}

// Run обрабатывает уведомления BPF. Больше НЕ проверяет excludedPaths.
func (bp *BpfProcessor) Run(ctx context.Context) {
	if bp == nil || bp.stateManager == nil || bp.clientMgr == nil || bp.notifChan == nil {
		slog.Error("BpfProcessor Run() called on improperly initialized instance. Exiting.")
		return
	}

	slog.Info("BPF Notification Processor starting...")
	// configCheckTicker больше не нужен для excludedPaths

	for {
		select {
		case <-ctx.Done():
			slog.Info("BPF notification processor stopping (context cancelled).")
			return

		case notification, ok := <-bp.notifChan:
			if !ok {
				slog.Info("BPF notification channel closed. BPF processor stopping.")
				return // Выход из цикла при закрытии канала
			}

			// Обрабатываем уведомление БЕЗ проверки excludedPaths
			bp.processSingleNotification(ctx, notification)

			// case <-configCheckTicker.C: // Удалено
			// 	// Логика проверки excludedPaths удалена отсюда
		}
		// runtime.Gosched() // Можно раскомментировать при очень высокой нагрузке
	}
}

// processSingleNotification обрабатывает одно событие BPF.
// Больше НЕ принимает excludedPaths.
// FIX: Use the correct type from ebpf package
func (bp *BpfProcessor) processSingleNotification(ctx context.Context, notification ebpf.NotificationTuple) {

	pidTgid := notification.PidTgid
	pid := uint32(pidTgid & 0xFFFFFFFF) // Извлекаем PID

	logCtx := slog.With(
		"src_ip", notification.SrcIP.String(),
		"orig_dst_ip", notification.OrigDstIP.String(),
		"orig_dst_port", notification.OrigDstPort,
		"src_port", notification.SrcPort,
		"pid", pid,
	)
	logCtx.Debug("Processing BPF notification tuple")

	if pid == 0 {
		logCtx.Warn("Received notification with zero PID, skipping.", "pid_tgid", pidTgid)
		return
	}

	// <<< Логика проверки excludedPaths УДАЛЕНА отсюда >>>
	// BPF должен был отфильтровать их сам

	// --- Поиск клиента по UID ---
	uid, err := bpfutil.GetUidFromPid(pid)
	if err != nil {
		// Если не можем получить UID, не можем найти клиента. Процесс мог завершиться.
		// Это ожидаемое состояние, если процесс был короткоживущим. Логируем как Debug.
		logCtx.Debug("Could not get UID for PID (process likely exited?), skipping notification", "error", err)
		return
	}
	logCtx = logCtx.With("uid", uid) // Добавляем UID в лог

	clientConn := bp.clientMgr.FindClientConnByUID(uid)
	if clientConn == nil {
		logCtx.Debug("No registered client found for UID, skipping notification")
		return // Нет клиента для отправки уведомления
	}

	// --- Отправка уведомления клиенту ---
	logCtx.Info("Found registered client for connection, sending notify_accept.")

	// Предполагаем, что BPF и IPC используют Host Byte Order для портов
	ipcNotifData := ipc.NotifyAcceptData{
		SrcIP:    notification.SrcIP.String(),
		DstIP:    notification.OrigDstIP.String(),
		SrcPort:  notification.SrcPort,
		DstPort:  notification.OrigDstPort,
		Protocol: notification.Protocol,
	}

	ipcCmd, err := ipc.NewCommand("notify_accept", ipcNotifData)
	if err != nil {
		logCtx.Error("Failed to create IPC notify_accept command", "error", err)
		return // Не можем продолжить, если команда не создана
	}

	// Отправляем команду асинхронно
	bp.sendToClient(ctx, clientConn, ipcCmd, uid)
}

// sendToClient отправляет команду IPC конкретному клиенту.
// Работает в горутине.
func (bp *BpfProcessor) sendToClient(ctx context.Context, conn net.Conn, cmd *ipc.Command, uid uint32) {
	// Добавляем в WaitGroup для корректного завершения при shutdown
	bp.stateManager.AddWaitGroup(1)
	go func(c net.Conn, command *ipc.Command, clientUID uint32) {
		defer bp.stateManager.WaitGroupDone()

		// Проверка контекста перед отправкой
		if ctx.Err() != nil {
			slog.Debug("IPC send cancelled before write due to context", "cmd", command.Command, "client_uid", clientUID, "error", ctx.Err())
			return
		}

		logCtx := slog.With("cmd", command.Command, "client_uid", clientUID)
		encoder := json.NewEncoder(c)

		// Установка таймаута на запись
		deadline := time.Now().Add(ipcSendTimeout)
		if err := c.SetWriteDeadline(deadline); err != nil {
			logCtx.Warn("Failed to set write deadline for IPC send", "error", err)
			// Продолжаем попытку отправки
		}

		err := encoder.Encode(command)

		// Сброс таймаута сразу после операции
		if errSet := c.SetWriteDeadline(time.Time{}); errSet != nil {
			// Логируем, но не считаем фатальным, если не удалось сбросить
			logCtx.Warn("Failed to clear write deadline after IPC send", "error", errSet)
		}

		if err != nil {
			// Проверяем контекст *после* ошибки записи
			if ctx.Err() != nil {
				logCtx.Info("IPC send failed likely due to context cancellation during/after write", "error", err, "context_err", ctx.Err())
			} else if errors.Is(err, net.ErrClosed) || common.IsConnectionClosedErr(err) || errors.Is(err, io.EOF) {
				// Ожидаемые ошибки при закрытии соединения клиентом
				logCtx.Info("IPC send failed: connection closed.", "error_type", fmt.Sprintf("%T", err), "error", err)
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Ошибка таймаута
				logCtx.Warn("IPC send failed: write timeout.", "timeout", ipcSendTimeout, "error", err)
			} else {
				// Другие неожиданные ошибки
				logCtx.Error("IPC send failed with unexpected error.", "error_type", fmt.Sprintf("%T", err), "error", err)
			}
			// Если отправка не удалась, считаем клиента отключенным и удаляем его
			bp.clientMgr.RemoveClientConn(c) // Вызываем синхронно
		} else {
			logCtx.Debug("Sent command to client successfully.")
		}
	}(conn, cmd, uid)
}

// stringSlicesEqual - больше не нужна здесь
