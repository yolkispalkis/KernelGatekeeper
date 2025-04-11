// FILE: pkg/config/config.go
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
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
	DefaultPacFileTTL             = 60
	DefaultPacExecTimeout         = 5
	DefaultEBPFLoadMode           = "getsockopt"
	DefaultEBPFStatsInterval      = 15
	DefaultLogLevel               = "info"
	DefaultLogPath                = "/var/log/kernelgatekeeper.log"
	DefaultShutdownTimeout        = 30
	DefaultSocketPath             = "/var/run/kernelgatekeeper.sock"
	DefaultClientListenerPort     = 3129
	DefaultEBPFMapSize            = 8192
)

type Config struct {
	Proxy              ProxyConfig    `mapstructure:"proxy"`
	Kerberos           KerberosConfig `mapstructure:"kerberos"`
	EBPF               EBPFConfig     `mapstructure:"ebpf"`
	LogLevel           string         `mapstructure:"logLevel"`
	LogPath            string         `mapstructure:"logPath"`
	ShutdownTimeout    time.Duration  `mapstructure:"shutdownTimeout"`
	SocketPath         string         `mapstructure:"socketPath"`
	ClientListenerPort uint16         `mapstructure:"clientListenerPort"`
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
	PacFileTTL          int    `mapstructure:"pacFileTtl"`
}

type KerberosConfig struct {
	Realm     string `mapstructure:"realm"`
	KDCHost   string `mapstructure:"kdcHost"`
	CachePath string `mapstructure:"cachePath"`
}

type EBPFConfig struct {
	ProgramPath     string   `mapstructure:"programPath"`
	TargetPorts     []int    `mapstructure:"targetPorts"`
	LoadMode        string   `mapstructure:"loadMode"`
	StatsInterval   int      `mapstructure:"statsInterval"`
	Excluded        []string `mapstructure:"excluded"`
	OrigDestMapSize int      `mapstructure:"origDestMapSize"`
	PortMapSize     int      `mapstructure:"portMapSize"`
}

func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()
	if configPath != "" {
		v.SetConfigFile(configPath)
		v.SetConfigType(filepath.Ext(configPath)[1:])
	} else {

		v.AddConfigPath("/etc/kernelgatekeeper/")
		v.AddConfigPath("$HOME/.config/kernelgatekeeper")
		v.AddConfigPath(".")
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	setDefaults(v)

	v.SetEnvPrefix("KG")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) && configPath == "" {

			slog.Warn("Configuration file not found in default locations, using defaults and environment variables.")
		} else if errors.As(err, &configFileNotFoundError) && configPath != "" {

			return nil, fmt.Errorf("configuration file not found at specified path %s: %w", configPath, err)
		} else {

			return nil, fmt.Errorf("error reading configuration file %s: %w", v.ConfigFileUsed(), err)
		}
	} else {
		slog.Info("Using configuration file", "path", v.ConfigFileUsed())
	}

	var config Config

	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshalling configuration: %w", err)
	}

	config.ShutdownTimeout = time.Duration(v.GetInt("shutdownTimeout")) * time.Second

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

func validateConfig(cfg *Config) error {

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
		cfg.Proxy.PacFileTTL = DefaultPacFileTTL
	}

	if len(cfg.EBPF.TargetPorts) == 0 {
		slog.Warn("ebpf.targetPorts is empty, no connections will be proxied by default")
	}
	for _, port := range cfg.EBPF.TargetPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d in ebpf.targetPorts, must be between 1 and 65535", port)
		}
	}
	if strings.ToLower(cfg.EBPF.LoadMode) != "getsockopt" {
		return fmt.Errorf("invalid ebpf.loadMode: '%s', currently only 'getsockopt' is supported", cfg.EBPF.LoadMode)
	}
	if cfg.EBPF.StatsInterval <= 0 {
		slog.Warn("ebpf.statsInterval is not positive, using default", "default", DefaultEBPFStatsInterval)
		cfg.EBPF.StatsInterval = DefaultEBPFStatsInterval
	}
	if cfg.EBPF.OrigDestMapSize <= 0 {
		slog.Warn("ebpf.origDestMapSize is not positive, using default", "default", DefaultEBPFMapSize)
		cfg.EBPF.OrigDestMapSize = DefaultEBPFMapSize
	}
	if cfg.EBPF.PortMapSize <= 0 {
		slog.Warn("ebpf.portMapSize is not positive, using default", "default", DefaultEBPFMapSize)
		cfg.EBPF.PortMapSize = DefaultEBPFMapSize
	}

	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[strings.ToLower(cfg.LogLevel)] {
		slog.Warn("Invalid logLevel in config, using default", "configured", cfg.LogLevel, "default", DefaultLogLevel)
		cfg.LogLevel = DefaultLogLevel
	}

	if cfg.ShutdownTimeout <= 0 {
		slog.Warn("shutdownTimeout must be positive, using default", "default", DefaultShutdownTimeout)
		cfg.ShutdownTimeout = time.Duration(DefaultShutdownTimeout) * time.Second
	}
	if cfg.SocketPath == "" {
		return errors.New("socketPath cannot be empty")
	}
	if cfg.ClientListenerPort == 0 {
		slog.Warn("clientListenerPort is not configured or zero, using default", "default", DefaultClientListenerPort)
		cfg.ClientListenerPort = DefaultClientListenerPort
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
	v.SetDefault("proxy.pacFileTtl", DefaultPacFileTTL)

	v.SetDefault("kerberos.enableCache", true)

	v.SetDefault("ebpf.loadMode", DefaultEBPFLoadMode)
	v.SetDefault("ebpf.statsInterval", DefaultEBPFStatsInterval)
	v.SetDefault("ebpf.targetPorts", []int{80, 443})
	v.SetDefault("ebpf.excluded", []string{})
	v.SetDefault("ebpf.origDestMapSize", DefaultEBPFMapSize)
	v.SetDefault("ebpf.portMapSize", DefaultEBPFMapSize)

	v.SetDefault("logLevel", DefaultLogLevel)
	v.SetDefault("logPath", DefaultLogPath)
	v.SetDefault("shutdownTimeout", DefaultShutdownTimeout)
	v.SetDefault("socketPath", DefaultSocketPath)
	v.SetDefault("clientListenerPort", DefaultClientListenerPort)
}
