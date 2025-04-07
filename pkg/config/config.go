// pkg/config/config.go
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
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
	Type              string `mapstructure:"type"`
	URL               string `mapstructure:"url"`
	WpadURL           string `mapstructure:"wpad_url"`
	ConnectionTimeout int    `mapstructure:"connection_timeout"`
	RequestTimeout    int    `mapstructure:"request_timeout"`
	MaxRetries        int    `mapstructure:"max_retries"`
}

type KerberosConfig struct {
	Realm          string `mapstructure:"realm"`
	KDCHost        string `mapstructure:"kdc_host"`        // Informational hint only
	Principal      string `mapstructure:"principal"`       // Informational hint only
	KeytabPath     string `mapstructure:"keytab_path"`     // Informational hint only
	EnableCache    bool   `mapstructure:"enable_cache"`    // Client always uses cache
	TicketLifetime int    `mapstructure:"ticket_lifetime"` // Informational hint only
	CachePath      string `mapstructure:"cache_path"`      // Informational hint only
}

type EBPFConfig struct {
	Interface         string `mapstructure:"interface"`    // Hint for stats/logging
	ProgramPath       string `mapstructure:"program_path"` // Not used by sockops model directly
	TargetPorts       []int  `mapstructure:"target_ports"`
	LoadMode          string `mapstructure:"load_mode"` // Should be "sockops" or similar
	AllowDynamicPorts bool   `mapstructure:"allow_dynamic_ports"`
	StatsInterval     int    `mapstructure:"stats_interval"`
}

func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		slog.Warn("Could not get absolute config path", "path", configPath, "error", err)
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
			slog.Warn("Config file not found, using defaults/env.", "path", absPath)
		} else {
			return nil, fmt.Errorf("read config %s failed: %w", absPath, err)
		}
	} else {
		slog.Info("Loaded configuration", "path", absPath)
	}
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("decode config failed: %w", err)
	}
	config.ShutdownTimeout = time.Duration(v.GetInt("shutdown_timeout")) * time.Second
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	return &config, nil
}

func validateConfig(cfg *Config) error {
	proxyType := strings.ToLower(cfg.Proxy.Type)
	if proxyType != "none" && proxyType != "http" && proxyType != "https" && proxyType != "wpad" {
		return fmt.Errorf("invalid proxy.type '%s'", cfg.Proxy.Type)
	}
	if (proxyType == "http" || proxyType == "https") && cfg.Proxy.URL == "" {
		return errors.New("proxy.url required for http/https")
	}
	if proxyType == "wpad" && cfg.Proxy.WpadURL == "" {
		return errors.New("proxy.wpad_url required for wpad")
	}
	if cfg.Proxy.ConnectionTimeout <= 0 {
		return errors.New("proxy.connection_timeout must be positive")
	}
	if cfg.Proxy.RequestTimeout <= 0 {
		return errors.New("proxy.request_timeout must be positive")
	}
	if cfg.Proxy.MaxRetries < 0 {
		return errors.New("proxy.max_retries cannot be negative")
	}

	// EBPF validation (LoadMode less critical now, Interface is informational)
	// if cfg.EBPF.LoadMode != "sockops" { slog.Warn("ebpf.load_mode is not 'sockops', but code uses sockops model", "mode", cfg.EBPF.LoadMode) }
	if len(cfg.EBPF.TargetPorts) == 0 {
		slog.Warn("ebpf.target_ports is empty, BPF will not redirect any ports")
	}
	for _, port := range cfg.EBPF.TargetPorts {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("invalid port %d in ebpf.target_ports", port)
		}
	}
	if cfg.EBPF.StatsInterval <= 0 {
		return errors.New("ebpf.stats_interval must be positive")
	}

	if cfg.SocketPath == "" {
		return errors.New("socket_path must be specified")
	}
	if cfg.ShutdownTimeout <= 0 {
		return errors.New("shutdown_timeout must be positive")
	}

	return nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("proxy.type", "http")
	v.SetDefault("proxy.connection_timeout", 10)
	v.SetDefault("proxy.request_timeout", 30)
	v.SetDefault("proxy.max_retries", 3)
	v.SetDefault("kerberos.enable_cache", true)
	v.SetDefault("ebpf.interface", "eth0") // Informational default
	v.SetDefault("ebpf.target_ports", []int{80, 443})
	v.SetDefault("ebpf.load_mode", "sockops")
	v.SetDefault("ebpf.allow_dynamic_ports", true)
	v.SetDefault("ebpf.stats_interval", 15)
	v.SetDefault("log_level", "info")
	v.SetDefault("log_path", "/var/log/kernelgatekeeper.log")
	v.SetDefault("shutdown_timeout", 30)
	v.SetDefault("socket_path", "/var/run/kernelgatekeeper.sock")
}

func SaveConfig(cfg *Config, path string) error {
	slog.Info("Saving configuration", "path", path)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("mkdir %s failed: %w", dir, err)
	}
	v := viper.New()
	v.SetConfigType("yaml")
	settings := map[string]interface{}{
		"proxy": cfg.Proxy, "kerberos": cfg.Kerberos, "ebpf": cfg.EBPF,
		"log_level": cfg.LogLevel, "log_path": cfg.LogPath,
		"shutdown_timeout": int(cfg.ShutdownTimeout.Seconds()), "socket_path": cfg.SocketPath,
	}
	if err := v.MergeConfigMap(settings); err != nil {
		return fmt.Errorf("prepare config map failed: %w", err)
	}
	if err := v.WriteConfigAs(path); err != nil {
		return fmt.Errorf("save config %s failed: %w", path, err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		slog.Warn("Failed set saved config permissions", "path", path, "error", err)
	}
	slog.Info("Configuration saved successfully", "path", path)
	return nil
}
