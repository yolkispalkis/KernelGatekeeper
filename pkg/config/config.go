package config

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	DefaultProxyType              = "http"
	DefaultProxyConnectionTimeout = 10
	DefaultProxyRequestTimeout    = 30
	DefaultProxyMaxRetries        = 3
	DefaultKerberosEnableCache    = true
	DefaultEBPFInterface          = "eth0"
	DefaultEBPFLoadMode           = "sockops"
	DefaultEBPFAllowDynamicPorts  = true
	DefaultEBPFStatsInterval      = 15
	DefaultEBPFNotifChanSize      = 4096
	DefaultLogLevel               = "info"
	DefaultLogPath                = "/var/log/kernelgatekeeper.log"
	DefaultShutdownTimeout        = 30
	DefaultSocketPath             = "/var/run/kernelgatekeeper.sock"
)

type Config struct {
	Proxy           ProxyConfig    `mapstructure:"proxy"`
	Kerberos        KerberosConfig `mapstructure:"kerberos"`
	EBPF            EBPFConfig     `mapstructure:"ebpf"`
	LogLevel        string         `mapstructure:"log_level"`
	LogPath         string         `mapstructure:"log_path"`
	ShutdownTimeout time.Duration  `mapstructure:"shutdown_timeout"`
	SocketPath      string         `mapstructure:"socket_path"`
}

type ProxyConfig struct {
	Type                string `mapstructure:"type"`
	URL                 string `mapstructure:"url"`
	WpadURL             string `mapstructure:"wpad_url"`
	ConnectionTimeout   int    `mapstructure:"connection_timeout"`
	RequestTimeout      int    `mapstructure:"request_timeout"`
	MaxRetries          int    `mapstructure:"max_retries"`
	PacCharset          string `mapstructure:"pac_charset"`
	PacExecutionTimeout int    `mapstructure:"pac_execution_timeout"`
}

type KerberosConfig struct {
	Realm          string `mapstructure:"realm"`
	KDCHost        string `mapstructure:"kdc_host"`
	Principal      string `mapstructure:"principal"`
	KeytabPath     string `mapstructure:"keytab_path"`
	EnableCache    bool   `mapstructure:"enable_cache"`
	TicketLifetime int    `mapstructure:"ticket_lifetime"`
	CachePath      string `mapstructure:"cache_path"`
}

type EBPFConfig struct {
	Interface               string `mapstructure:"interface"`
	ProgramPath             string `mapstructure:"program_path"`
	TargetPorts             []int  `mapstructure:"target_ports"`
	LoadMode                string `mapstructure:"load_mode"`
	AllowDynamicPorts       bool   `mapstructure:"allow_dynamic_ports"`
	StatsInterval           int    `mapstructure:"stats_interval"`
	NotificationChannelSize int    `mapstructure:"notification_channel_size"`
}

func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		slog.Warn("Could not get absolute config path, using provided path", "path", configPath, "error", err)
		absPath = configPath
	}

	v.SetConfigFile(absPath)
	v.SetConfigType("yaml")

	setDefaults(v)

	v.SetEnvPrefix("KG")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	err = v.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Warn("Config file not found, using defaults and environment variables.", "path", absPath)
		} else {
			return nil, fmt.Errorf("failed to read config file %s: %w", absPath, err)
		}
	} else {
		slog.Info("Loaded configuration file", "path", absPath)
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	config.ShutdownTimeout = time.Duration(v.GetInt("shutdown_timeout")) * time.Second

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

func validateConfig(cfg *Config) error {
	proxyType := strings.ToLower(cfg.Proxy.Type)
	validProxyTypes := map[string]bool{"none": true, "http": true, "https": true, "wpad": true}
	if !validProxyTypes[proxyType] {
		return fmt.Errorf("invalid proxy.type '%s', must be one of: none, http, https, wpad", cfg.Proxy.Type)
	}
	if (proxyType == "http" || proxyType == "https") && cfg.Proxy.URL == "" {
		return errors.New("proxy.url is required when proxy.type is http or https")
	}
	if proxyType == "wpad" && cfg.Proxy.WpadURL == "" {
		return errors.New("proxy.wpad_url is required when proxy.type is wpad")
	}
	if cfg.Proxy.ConnectionTimeout <= 0 {
		return errors.New("proxy.connection_timeout must be a positive number of seconds")
	}
	if cfg.Proxy.RequestTimeout <= 0 {
		return errors.New("proxy.request_timeout must be a positive number of seconds")
	}
	if cfg.Proxy.MaxRetries < 0 {
		return errors.New("proxy.max_retries cannot be negative")
	}
	if cfg.Proxy.PacExecutionTimeout <= 0 {
		return errors.New("proxy.pac_execution_timeout must be positive")
	}

	if cfg.Kerberos.Realm == "" {
		slog.Warn("Kerberos realm is not explicitly set in config, relying on system defaults or auto-detection.")
	}

	if len(cfg.EBPF.TargetPorts) == 0 {
		slog.Warn("ebpf.target_ports is empty, BPF sockops will not redirect any connections.")
	}
	for i, port := range cfg.EBPF.TargetPorts {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("invalid port %d found at index %d in ebpf.target_ports (must be 1-65535)", port, i)
		}
	}
	if cfg.EBPF.StatsInterval <= 0 {
		return errors.New("ebpf.stats_interval must be a positive number of seconds")
	}
	if cfg.EBPF.NotificationChannelSize <= 0 {
		return errors.New("ebpf.notification_channel_size must be positive")
	}

	if cfg.SocketPath == "" {
		return errors.New("socket_path must be specified for IPC")
	}
	if cfg.ShutdownTimeout <= 0 {
		return errors.New("shutdown_timeout must be a positive number of seconds")
	}

	return nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("proxy.type", DefaultProxyType)
	v.SetDefault("proxy.url", "")
	v.SetDefault("proxy.wpad_url", "")
	v.SetDefault("proxy.connection_timeout", DefaultProxyConnectionTimeout)
	v.SetDefault("proxy.request_timeout", DefaultProxyRequestTimeout)
	v.SetDefault("proxy.max_retries", DefaultProxyMaxRetries)
	v.SetDefault("proxy.pac_charset", "utf-8")
	v.SetDefault("proxy.pac_execution_timeout", 5)

	v.SetDefault("kerberos.realm", "")
	v.SetDefault("kerberos.kdc_host", "")
	v.SetDefault("kerberos.principal", "")
	v.SetDefault("kerberos.keytab_path", "")
	v.SetDefault("kerberos.enable_cache", DefaultKerberosEnableCache)
	v.SetDefault("kerberos.ticket_lifetime", 24)
	v.SetDefault("kerberos.cache_path", "")

	v.SetDefault("ebpf.interface", DefaultEBPFInterface)
	v.SetDefault("ebpf.program_path", "")
	v.SetDefault("ebpf.target_ports", []int{80, 443})
	v.SetDefault("ebpf.load_mode", DefaultEBPFLoadMode)
	v.SetDefault("ebpf.allow_dynamic_ports", DefaultEBPFAllowDynamicPorts)
	v.SetDefault("ebpf.stats_interval", DefaultEBPFStatsInterval)
	v.SetDefault("ebpf.notification_channel_size", DefaultEBPFNotifChanSize)

	v.SetDefault("log_level", DefaultLogLevel)
	v.SetDefault("log_path", DefaultLogPath)
	v.SetDefault("shutdown_timeout", DefaultShutdownTimeout)
	v.SetDefault("socket_path", DefaultSocketPath)
}
