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
	LogLevel        string         `mapstructure:"logLevel"`
	LogPath         string         `mapstructure:"logPath"`
	ShutdownTimeout time.Duration  `mapstructure:"shutdownTimeout"`
	SocketPath      string         `mapstructure:"socketPath"`
}

type ProxyConfig struct {
	Type                string `mapstructure:"type"`
	URL                 string `mapstructure:"url"`
	WpadURL             string `mapstructure:"wpadUrl"`
	ConnectionTimeout   int    `mapstructure:"connectionTimeout"`
	RequestTimeout      int    `mapstructure:"requestTimeout"`
	MaxRetries          int    `mapstructure:"maxRetries"`
	PacCharset          string `mapstructure:"pacCharset"`
	PacExecutionTimeout int    `mapstructure:"pacExecutionTimeout"`
}

// KerberosConfig for client mode primarily uses CachePath. Realm/KDCHost are optional.
type KerberosConfig struct {
	Realm     string `mapstructure:"realm"`
	KDCHost   string `mapstructure:"kdcHost"`
	CachePath string `mapstructure:"cachePath"` // Path pattern for ccache (optional)
}

type EBPFConfig struct {
	Interface               string   `mapstructure:"interface"`
	ProgramPath             string   `mapstructure:"programPath"`
	TargetPorts             []int    `mapstructure:"targetPorts"`
	LoadMode                string   `mapstructure:"loadMode"`
	AllowDynamicPorts       bool     `mapstructure:"allowDynamicPorts"`
	StatsInterval           int      `mapstructure:"statsInterval"`
	NotificationChannelSize int      `mapstructure:"notificationChannelSize"`
	Excluded                []string `mapstructure:"excluded"`
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

	config.ShutdownTimeout = time.Duration(v.GetInt("shutdownTimeout")) * time.Second

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
		return errors.New("proxy.wpadUrl is required when proxy.type is wpad")
	}
	if cfg.Proxy.ConnectionTimeout <= 0 {
		return errors.New("proxy.connectionTimeout must be a positive number of seconds")
	}
	if cfg.Proxy.RequestTimeout <= 0 {
		return errors.New("proxy.requestTimeout must be a positive number of seconds")
	}
	if cfg.Proxy.MaxRetries < 0 {
		return errors.New("proxy.maxRetries cannot be negative")
	}
	if cfg.Proxy.PacExecutionTimeout <= 0 {
		return errors.New("proxy.pacExecutionTimeout must be positive")
	}

	if strings.Contains(cfg.Kerberos.CachePath, "%{null}") {
		slog.Warn("kerberos.cachePath contains '%{null}', which is unsupported. Ignoring cachePath setting.")
		cfg.Kerberos.CachePath = ""
	}

	if len(cfg.EBPF.TargetPorts) == 0 {
		slog.Warn("ebpf.targetPorts is empty, BPF sockops will not redirect any connections.")
	}
	for i, port := range cfg.EBPF.TargetPorts {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("invalid port %d found at index %d in ebpf.targetPorts (must be 1-65535)", port, i)
		}
	}
	if cfg.EBPF.StatsInterval <= 0 {
		return errors.New("ebpf.statsInterval must be a positive number of seconds")
	}
	if cfg.EBPF.NotificationChannelSize <= 0 {
		return errors.New("ebpf.notificationChannelSize must be positive")
	}

	cleanedPaths := make([]string, 0, len(cfg.EBPF.Excluded))
	for _, p := range cfg.EBPF.Excluded {
		cleaned := filepath.Clean(p)
		if cleaned != "" && cleaned != "." && cleaned != "/" {
			cleanedPaths = append(cleanedPaths, cleaned)
		} else {
			slog.Warn("Ignoring invalid or potentially insecure excluded path", "path", p)
		}
	}
	cfg.EBPF.Excluded = cleanedPaths
	if len(cfg.EBPF.Excluded) > 0 {
		slog.Info("Executable exclusion paths loaded", "paths", cfg.EBPF.Excluded)
	}

	if cfg.SocketPath == "" {
		return errors.New("socketPath must be specified for IPC")
	}
	if cfg.ShutdownTimeout <= 0 {
		return errors.New("shutdownTimeout must be a positive number of seconds")
	}

	return nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("proxy.type", DefaultProxyType)
	v.SetDefault("proxy.url", "")
	v.SetDefault("proxy.wpadUrl", "")
	v.SetDefault("proxy.connectionTimeout", DefaultProxyConnectionTimeout)
	v.SetDefault("proxy.requestTimeout", DefaultProxyRequestTimeout)
	v.SetDefault("proxy.maxRetries", DefaultProxyMaxRetries)
	v.SetDefault("proxy.pacCharset", "utf-8")
	v.SetDefault("proxy.pacExecutionTimeout", 5)

	v.SetDefault("kerberos.realm", "")
	v.SetDefault("kerberos.kdcHost", "")
	v.SetDefault("kerberos.cachePath", "")

	v.SetDefault("ebpf.interface", DefaultEBPFInterface)
	v.SetDefault("ebpf.programPath", "")
	v.SetDefault("ebpf.targetPorts", []int{80, 443})
	v.SetDefault("ebpf.loadMode", DefaultEBPFLoadMode)
	v.SetDefault("ebpf.allowDynamicPorts", DefaultEBPFAllowDynamicPorts)
	v.SetDefault("ebpf.statsInterval", DefaultEBPFStatsInterval)
	v.SetDefault("ebpf.notificationChannelSize", DefaultEBPFNotifChanSize)
	v.SetDefault("ebpf.excluded", []string{})

	v.SetDefault("logLevel", DefaultLogLevel)
	v.SetDefault("logPath", DefaultLogPath)
	v.SetDefault("shutdownTimeout", DefaultShutdownTimeout)
	v.SetDefault("socketPath", DefaultSocketPath)
}
