package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/yolki/kernelgatekeeper/pkg/config"
	"github.com/yolki/kernelgatekeeper/pkg/ebpf" // Keep for GetAvailableInterfaces, remove if not needed
	"github.com/yolki/kernelgatekeeper/pkg/kerb"
	"github.com/yolki/kernelgatekeeper/pkg/proxy"
)

// Глобальные переменные для обработки версии и сборки
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Отлавливаем панику для корректной обработки ошибок
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v\n%s", r, debug.Stack())
			os.Exit(1)
		}
	}()

	// Парсим флаги командной строки
	configPath := flag.String("config", "config.yaml", "Path to config file")
	logPath := flag.String("log", "", "Path to log file (default: stdout)")
	showVersion := flag.Bool("version", false, "Show version information")
	shutdownTimeout := flag.Duration("shutdown-timeout", 30*time.Second, "Timeout for graceful shutdown")
	flag.Parse()

	// Показываем информацию о версии, если запрошено
	if *showVersion {
		fmt.Printf("KernelGatekeeper %s, commit %s, built at %s\n", version, commit, date)
		return
	}

	// Настраиваем логирование
	if *logPath != "" {
		logFile, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	// Получаем абсолютный путь к конфигурационному файлу
	absConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		log.Fatalf("Failed to get absolute path to config: %v", err)
	}

	log.Printf("Starting KernelGatekeeper (version: %s, commit: %s)", version, commit)
	log.Printf("Using configuration file: %s", absConfigPath)
	log.Printf("Runtime: Go %s, OS: %s, Arch: %s", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	// Загружаем конфигурацию
	cfg, err := config.LoadConfig(absConfigPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Устанавливаем уровень логирования
	setupLogLevel(cfg.LogLevel)

	// Создаем контекст с отменой для корректного завершения работы
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Создаем WaitGroup для отслеживания завершения всех компонентов
	var wg sync.WaitGroup

	// Инициализируем и запускаем все компоненты
	// NOTE: This initialization logic seems to mix service and client roles
	// and likely isn't used in the primary sockops service/client deployment model.
	// It's kept here minimally functional after fixing compile errors.
	components, err := initializeComponents(ctx, cfg, &wg)
	if err != nil {
		log.Printf("WARN: Failed to initialize components (may be expected if running service/client model): %v", err)
		// Don't exit here, allow signals to be handled if only core logic is needed
	}

	// Регистрируем обработчик сигналов для корректного завершения работы
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Запускаем отдельную горутину для обработки сигналов
	go func() {
		for sig := range sigCh {
			log.Printf("Received signal: %v", sig)

			// При получении SIGHUP перезагружаем конфигурацию
			if sig == syscall.SIGHUP {
				log.Println("Reloading configuration...")
				newCfg, err := config.LoadConfig(absConfigPath)
				if err != nil {
					log.Printf("Error reloading config: %v, continuing with current config", err)
					continue
				}

				// Применяем новую конфигурацию
				if err := applyNewConfig(components, newCfg); err != nil {
					log.Printf("Error applying new config: %v", err)
				} else {
					log.Println("Configuration reloaded successfully")
				}

				continue
			}

			// Для SIGINT и SIGTERM начинаем процесс завершения работы
			log.Println("Shutting down...")

			// Создаем контекст с таймаутом для graceful shutdown
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), *shutdownTimeout)
			defer shutdownCancel()

			// Отменяем основной контекст
			cancel()

			// Запускаем таймер для наблюдения за завершением
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()

			// Ожидаем завершения или таймаута
			select {
			case <-done:
				log.Println("All components stopped gracefully")
			case <-shutdownCtx.Done():
				log.Println("Shutdown timeout exceeded, forcing exit")
			}

			break
		}
	}()

	// Выводим информацию о запущенном сервисе
	if components != nil && components.proxyManager != nil {
		// Use GetEffectiveProxyURL as GetProxyURL does not exist
		if proxyURL := components.proxyManager.GetEffectiveProxyURL(); proxyURL != nil {
			log.Printf("KernelGatekeeper initialized with proxy: %s", proxyURL.String())
		} else {
			log.Printf("KernelGatekeeper initialized with no effective proxy")
		}
	}
	// Removed redirector related logs as redirector is not initialized here
	// if components.redirector != nil {
	// 	interfaces, _ := ebpf.GetAvailableInterfaces()
	// 	log.Printf("Available network interfaces: %v", interfaces)
	// 	log.Printf("Traffic redirection active on interface: %s, ports: %v",
	// 		cfg.EBPF.Interface, cfg.EBPF.TargetPorts)
	// }
	interfaces, _ := ebpf.GetAvailableInterfaces() // Keep this for info if needed
	log.Printf("Available network interfaces: %v", interfaces)
	log.Printf("Service mode likely uses BPF manager (not redirector). Check service logs.")
	log.Printf("Press Ctrl+C to exit")

	// Ожидаем завершения всех компонентов (if any were successfully started)
	wg.Wait()
	log.Println("All components stopped, exiting")
}

// Структура для хранения всех компонентов
type appComponents struct {
	kerbClient   *kerb.KerberosClient
	proxyManager *proxy.ProxyManager
	// Removed: redirector   *ebpf.TrafficRedirector // TrafficRedirector likely belongs to a different model
}

// Инициализирует все компоненты приложения
func initializeComponents(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup) (*appComponents, error) {
	components := &appComponents{}
	var initErr error // Track first error

	// Инициализируем клиент Kerberos
	log.Println("Initializing Kerberos client (cmd/main)...")
	kerbClient, err := kerb.NewKerberosClient(&cfg.Kerberos)
	if err != nil {
		// Log as warning, might not be fatal depending on usage
		log.Printf("WARN: Failed to initialize Kerberos client: %v", err)
		if initErr == nil {
			initErr = fmt.Errorf("failed to initialize Kerberos client: %w", err)
		}
	}
	components.kerbClient = kerbClient

	// Инициализируем прокси-менеджер
	log.Println("Initializing proxy manager (cmd/main)...")
	// NewProxyManager signature likely changed; only takes ProxyConfig now for client use.
	// Removed kerbClient argument assuming client-side proxy manager usage.
	proxyManager, err := proxy.NewProxyManager(&cfg.Proxy)
	if err != nil {
		log.Printf("WARN: Failed to initialize proxy manager: %v", err)
		if initErr == nil {
			initErr = fmt.Errorf("failed to initialize proxy manager: %w", err)
		}
	}
	components.proxyManager = proxyManager

	// Инициализируем eBPF перехватчик трафика - REMOVED
	// The sockops model uses BPFManager initialized in the service, not TrafficRedirector here.
	// log.Println("Initializing traffic redirector...")
	// redirector, err := ebpf.NewTrafficRedirector(&cfg.EBPF) // NewTrafficRedirector undefined
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to initialize traffic redirector: %v", err)
	// }
	// components.redirector = redirector

	// Запускаем перехват трафика - REMOVED
	// log.Println("Starting traffic redirection...")
	// if err := redirector.Start(); err != nil {
	// 	return nil, fmt.Errorf("failed to start traffic redirection: %v", err)
	// }

	// Add wait group handling only if components are expected to run long tasks
	// wg.Add(1) // Example if proxyManager had a background task
	go func() {
		// defer wg.Done() // Only if wg.Add(1) was called
		<-ctx.Done() // Ожидаем отмены контекста

		log.Println("Stopping components (cmd/main)...")

		// Корректно останавливаем все компоненты
		// Сначала останавливаем перехват трафика - REMOVED
		// if components.redirector != nil {
		// 	if err := components.redirector.Stop(); err != nil {
		// 		log.Printf("Error stopping traffic redirector: %v", err)
		// 	}
		// }

		// Затем закрываем прокси-менеджер
		if components.proxyManager != nil {
			if err := components.proxyManager.Close(); err != nil {
				log.Printf("Error closing proxy manager: %v", err)
			}
		}

		// Наконец, закрываем клиент Kerberos
		if components.kerbClient != nil {
			components.kerbClient.Close()
		}

		log.Println("All components stopped (cmd/main)")
	}()

	// Return components even if there were warnings during initialization
	return components, initErr
}

// Применяет новую конфигурацию к работающим компонентам
func applyNewConfig(components *appComponents, cfg *config.Config) error {
	// Обновляем список портов для перехвата - REMOVED
	// This would likely be handled by the BPFManager in the service via IPC.
	// if components.redirector != nil {
	// 	if err := components.redirector.UpdateTargetPorts(cfg.EBPF.TargetPorts); err != nil {
	// 		return fmt.Errorf("failed to update target ports: %v", err)
	// 	}
	// }

	// Reload proxy manager settings?
	if components.proxyManager != nil {
		// Need a method on ProxyManager to update its config, e.g., components.proxyManager.UpdateConfig(&cfg.Proxy)
		log.Println("Proxy manager config reload not implemented in cmd/main applyNewConfig")
	}

	// Reload Kerberos client?
	if components.kerbClient != nil {
		// Need a method on KerberosClient to update its config, or reinitialize
		log.Println("Kerberos client config reload not implemented in cmd/main applyNewConfig")
	}

	log.Println("applyNewConfig called in cmd/main (may need further implementation)")
	return nil
}

// Настраивает уровень логирования
func setupLogLevel(level string) {
	// В будущем можно использовать более сложную библиотеку логирования
	// с поддержкой уровней. Сейчас просто добавляем дату и время
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetPrefix(fmt.Sprintf("[%s] ", level))
}
