package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url" // Import net/url
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	DefaultProxyType              = "http"
	DefaultProxyConnectionTimeout = 10 // seconds
	DefaultProxyRequestTimeout    = 30 // seconds
	DefaultProxyMaxRetries        = 3
	DefaultPacFileTTL             = 60 // seconds
	DefaultPacExecTimeout         = 5  // seconds
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
	ShutdownTimeout time.Duration  `mapstructure:"shutdownTimeout"` // Use time.Duration directly
	SocketPath      string         `mapstructure:"socketPath"`
}

type ProxyConfig struct {
	Type                string `mapstructure:"type"`                // "http", "https", "wpad", "none"
	URL                 string `mapstructure:"url"`                 // URL for static proxy (http://proxy:port)
	WpadURL             string `mapstructure:"wpadUrl"`             // URL for PAC/WPAD discovery (http://wpad/wpad.dat or file:///...)
	ConnectionTimeout   int    `mapstructure:"connectionTimeout"`   // Timeout for connecting to the proxy (seconds)
	RequestTimeout      int    `mapstructure:"requestTimeout"`      // Timeout for the CONNECT request (seconds)
	MaxRetries          int    `mapstructure:"maxRetries"`          // Max retries for CONNECT request (currently unused in tunnel logic)
	PacCharset          string `mapstructure:"pacCharset"`          // Optional: Charset of the PAC file (e.g., "windows-1251")
	PacExecutionTimeout int    `mapstructure:"pacExecutionTimeout"` // Timeout for FindProxyForURL execution (seconds) - Handled by gopac? Check docs.
	PacFileTTL          int    `mapstructure:"pacFileTtl"`          // <<< Добавлено: TTL for caching the PAC file (seconds)
}

// KerberosConfig for client mode primarily uses CachePath. Realm/KDCHost are optional.
type KerberosConfig struct {
	Realm     string `mapstructure:"realm"`
	KDCHost   string `mapstructure:"kdcHost"`
	CachePath string `mapstructure:"cachePath"` // Path pattern for ccache (optional)
}

type EBPFConfig struct {
	Interface               string   `mapstructure:"interface"`   // Primarily informational in sockops mode
	ProgramPath             string   `mapstructure:"programPath"` // Usually embedded, path optional
	TargetPorts             []int    `mapstructure:"targetPorts"`
	LoadMode                string   `mapstructure:"loadMode"` // Should be "sockops"
	AllowDynamicPorts       bool     `mapstructure:"allowDynamicPorts"`
	StatsInterval           int      `mapstructure:"statsInterval"`           // BPF map stats update interval (seconds)
	NotificationChannelSize int      `mapstructure:"notificationChannelSize"` // Size of ring buffer -> userspace channel
	Excluded                []string `mapstructure:"excluded"`                // Full paths to executables to exclude
}

func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()
	if configPath != "" {
		v.SetConfigFile(configPath)
		v.SetConfigType(filepath.Ext(configPath)[1:]) // e.g., "yaml"
	} else {
		// Default locations if no path provided
		v.AddConfigPath("/etc/kernelgatekeeper/")
		v.AddConfigPath("$HOME/.config/kernelgatekeeper") // User-specific config
		v.AddConfigPath(".")
		v.SetConfigName("config") // name of config file (without extension)
		v.SetConfigType("yaml")
	}

	// Set default values
	setDefaults(v)

	// Read environment variables (optional)
	v.SetEnvPrefix("KG") // e.g., KG_LOGLEVEL=debug
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) && configPath == "" {
			// Config file not found in default locations, proceed with defaults only
			slog.Warn("Configuration file not found in default locations, using defaults and environment variables.")
		} else if errors.As(err, &configFileNotFoundError) && configPath != "" {
			// Specific config file path provided but not found
			return nil, fmt.Errorf("configuration file not found at specified path %s: %w", configPath, err)
		} else {
			// Some other error reading the config file
			return nil, fmt.Errorf("error reading configuration file %s: %w", v.ConfigFileUsed(), err)
		}
	} else {
		slog.Info("Using configuration file", "path", v.ConfigFileUsed())
	}

	var config Config
	// Unmarshal the config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshalling configuration: %w", err)
	}

	// Convert shutdown timeout from seconds (int) to time.Duration
	config.ShutdownTimeout = time.Duration(v.GetInt("shutdownTimeout")) * time.Second

	// Validate the loaded configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

func validateConfig(cfg *Config) error {
	// Proxy validation
	validProxyTypes := map[string]bool{"http": true, "https": true, "wpad": true, "none": true}
	if !validProxyTypes[strings.ToLower(cfg.Proxy.Type)] {
		return fmt.Errorf("invalid proxy.type: '%s', must be one of: http, https, wpad, none", cfg.Proxy.Type)
	}
	if cfg.Proxy.Type == "http" || cfg.Proxy.Type == "https" {
		if cfg.Proxy.URL == "" {
			return errors.New("proxy.url is required when proxy.type is 'http' or 'https'")
		}
		_, err := url.ParseRequestURI(cfg.Proxy.URL)
		if err != nil {
			return fmt.Errorf("invalid proxy.url: %w", err)
		}
	}
	if cfg.Proxy.Type == "wpad" {
		if cfg.Proxy.WpadURL == "" {
			return errors.New("proxy.wpadUrl is required when proxy.type is 'wpad'")
		}
		// Allow file:// or http(s)://
		u, err := url.Parse(cfg.Proxy.WpadURL)
		if err != nil {
			return fmt.Errorf("invalid proxy.wpadUrl: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "file" {
			return fmt.Errorf("invalid scheme in proxy.wpadUrl: '%s', must be http, https, or file", u.Scheme)
		}
	}
	if cfg.Proxy.ConnectionTimeout <= 0 {
		return errors.New("proxy.connectionTimeout must be positive")
	}
	if cfg.Proxy.RequestTimeout <= 0 {
		return errors.New("proxy.requestTimeout must be positive")
	}
	if cfg.Proxy.PacFileTTL <= 0 && cfg.Proxy.Type == "wpad" {
		slog.Warn("proxy.pacFileTtl is not positive, using default", "default", DefaultPacFileTTL)
		cfg.Proxy.PacFileTTL = DefaultPacFileTTL // Apply default if invalid
	}
	// PacExecutionTimeout validation? gopac might handle its own timeout.

	// Kerberos validation (minimal for client)

	// EBPF validation
	if len(cfg.EBPF.TargetPorts) == 0 {
		slog.Warn("ebpf.targetPorts is empty, no connections will be proxied by default")
	}
	for _, port := range cfg.EBPF.TargetPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d in ebpf.targetPorts, must be between 1 and 65535", port)
		}
	}
	if strings.ToLower(cfg.EBPF.LoadMode) != "sockops" {
		return fmt.Errorf("invalid ebpf.loadMode: '%s', currently only 'sockops' is supported", cfg.EBPF.LoadMode)
	}
	if cfg.EBPF.StatsInterval <= 0 {
		slog.Warn("ebpf.statsInterval is not positive, using default", "default", DefaultEBPFStatsInterval)
		cfg.EBPF.StatsInterval = DefaultEBPFStatsInterval
	}
	if cfg.EBPF.NotificationChannelSize <= 0 {
		slog.Warn("ebpf.notificationChannelSize is not positive, using default", "default", DefaultEBPFNotifChanSize)
		cfg.EBPF.NotificationChannelSize = DefaultEBPFNotifChanSize
	}
	// Validate excluded paths are absolute?

	// Logging validation
	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[strings.ToLower(cfg.LogLevel)] {
		slog.Warn("Invalid logLevel in config, using default", "configured", cfg.LogLevel, "default", DefaultLogLevel)
		cfg.LogLevel = DefaultLogLevel
	}
	// LogPath validation? Check if writable? Defer to logging setup.

	// Other validation
	if cfg.ShutdownTimeout <= 0 {
		slog.Warn("shutdownTimeout must be positive, using default", "default", DefaultShutdownTimeout)
		cfg.ShutdownTimeout = time.Duration(DefaultShutdownTimeout) * time.Second
	}
	if cfg.SocketPath == "" {
		return errors.New("socketPath cannot be empty")
	}

	return nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("proxy.type", DefaultProxyType)
	v.SetDefault("proxy.connectionTimeout", DefaultProxyConnectionTimeout)
	v.SetDefault("proxy.requestTimeout", DefaultProxyRequestTimeout)
	v.SetDefault("proxy.maxRetries", DefaultProxyMaxRetries)
	v.SetDefault("proxy.pacCharset", "")
	v.SetDefault("proxy.pacExecutionTimeout", DefaultPacExecTimeout)
	v.SetDefault("proxy.pacFileTtl", DefaultPacFileTTL) // <<< Добавлено

	v.SetDefault("kerberos.enableCache", true) // Default client to use ccache

	v.SetDefault("ebpf.interface", DefaultEBPFInterface)
	v.SetDefault("ebpf.loadMode", DefaultEBPFLoadMode)
	v.SetDefault("ebpf.allowDynamicPorts", DefaultEBPFAllowDynamicPorts)
	v.SetDefault("ebpf.statsInterval", DefaultEBPFStatsInterval)
	v.SetDefault("ebpf.notificationChannelSize", DefaultEBPFNotifChanSize)
	v.SetDefault("ebpf.targetPorts", []int{80, 443}) // Default ports
	v.SetDefault("ebpf.excluded", []string{})        // Default empty exclude list

	v.SetDefault("logLevel", DefaultLogLevel)
	v.SetDefault("logPath", DefaultLogPath)
	v.SetDefault("shutdownTimeout", DefaultShutdownTimeout) // Store as int initially
	v.SetDefault("socketPath", DefaultSocketPath)
}
