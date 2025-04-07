// pkg/config/config.go
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Default values for configuration
const (
	DefaultProxyType              = "http"
	DefaultProxyConnectionTimeout = 10 // seconds
	DefaultProxyRequestTimeout    = 30 // seconds
	DefaultProxyMaxRetries        = 3
	DefaultKerberosEnableCache    = true
	DefaultEBPFInterface          = "eth0" // Informational default
	DefaultEBPFLoadMode           = "sockops"
	DefaultEBPFAllowDynamicPorts  = true
	DefaultEBPFStatsInterval      = 15   // seconds
	DefaultEBPFNotifChanSize      = 4096 // Size of the channel buffering BPF notifications
	DefaultLogLevel               = "info"
	DefaultLogPath                = "/var/log/kernelgatekeeper.log"
	DefaultShutdownTimeout        = 30 // seconds
	DefaultSocketPath             = "/var/run/kernelgatekeeper.sock"
)

// Config holds the main application configuration.
type Config struct {
	Proxy           ProxyConfig    `mapstructure:"proxy"`
	Kerberos        KerberosConfig `mapstructure:"kerberos"`
	EBPF            EBPFConfig     `mapstructure:"ebpf"`
	LogLevel        string         `mapstructure:"log_level"`
	LogPath         string         `mapstructure:"log_path"`
	ShutdownTimeout time.Duration  `mapstructure:"shutdown_timeout"` // Parsed separately
	SocketPath      string         `mapstructure:"socket_path"`
}

// ProxyConfig defines settings for the outbound proxy used by the client.
type ProxyConfig struct {
	Type                string `mapstructure:"type"`                  // http, https, wpad, none
	URL                 string `mapstructure:"url"`                   // For type=http/https
	WpadURL             string `mapstructure:"wpad_url"`              // For type=wpad
	ConnectionTimeout   int    `mapstructure:"connection_timeout"`    // In seconds
	RequestTimeout      int    `mapstructure:"request_timeout"`       // In seconds
	MaxRetries          int    `mapstructure:"max_retries"`           // Connection retries for the client
	PacCharset          string `mapstructure:"pac_charset"`           // Optional: Charset for decoding PAC file (e.g., "windows-1251"), defaults to UTF-8
	PacExecutionTimeout int    `mapstructure:"pac_execution_timeout"` // Max time for PAC script execution (seconds)
}

// KerberosConfig defines settings related to Kerberos authentication (mostly hints for the client).
type KerberosConfig struct {
	Realm          string `mapstructure:"realm"`           // Optional hint for client
	KDCHost        string `mapstructure:"kdc_host"`        // Informational hint only
	Principal      string `mapstructure:"principal"`       // Informational hint only
	KeytabPath     string `mapstructure:"keytab_path"`     // Informational hint only
	EnableCache    bool   `mapstructure:"enable_cache"`    // Client always uses cache in sockops model
	TicketLifetime int    `mapstructure:"ticket_lifetime"` // Informational hint only
	CachePath      string `mapstructure:"cache_path"`      // Informational, client uses system default or KRB5CCNAME
}

// EBPFConfig defines settings for the eBPF programs and maps managed by the service.
type EBPFConfig struct {
	Interface               string `mapstructure:"interface"`                 // Hint for stats/logging (sockops attaches to cgroup)
	ProgramPath             string `mapstructure:"program_path"`              // Not used by sockops model directly
	TargetPorts             []int  `mapstructure:"target_ports"`              // Ports BPF sockops should redirect
	LoadMode                string `mapstructure:"load_mode"`                 // Should be "sockops" or similar
	AllowDynamicPorts       bool   `mapstructure:"allow_dynamic_ports"`       // Allow service to update target_ports map via IPC
	StatsInterval           int    `mapstructure:"stats_interval"`            // Service BPF stats logging interval (seconds)
	NotificationChannelSize int    `mapstructure:"notification_channel_size"` // Buffer size between BPF ringbuf reader and service processor
}

// LoadConfig reads configuration from a file, environment variables, and defaults.
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		slog.Warn("Could not get absolute config path, using provided path", "path", configPath, "error", err)
		absPath = configPath // Use original path if Abs fails
	}

	v.SetConfigFile(absPath)
	v.SetConfigType("yaml") // Or viper will guess from extension

	// Set default values
	setDefaults(v)

	// Enable environment variable overrides
	// KG_PROXY_URL, KG_EBPF_TARGETPORTS="80,8080", etc.
	v.SetEnvPrefix("KG")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read the configuration file
	err = v.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Warn("Config file not found, using defaults and environment variables.", "path", absPath)
			// Continue without error if file not found
		} else {
			// More serious error reading the config file
			return nil, fmt.Errorf("failed to read config file %s: %w", absPath, err)
		}
	} else {
		slog.Info("Loaded configuration file", "path", absPath)
	}

	// Unmarshal the config into the struct
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	// Handle duration parsing separately as viper doesn't do it automatically from int
	config.ShutdownTimeout = time.Duration(v.GetInt("shutdown_timeout")) * time.Second

	// Validate the loaded configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Log the effective configuration at debug level? Maybe too verbose.
	// rawSettings := v.AllSettings()
	// slog.Debug("Effective configuration loaded", "settings", rawSettings)

	return &config, nil
}

// validateConfig checks the consistency and validity of the configuration.
func validateConfig(cfg *Config) error {
	// Proxy Validation
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

	// Kerberos Validation (mostly informational, less critical checks)
	if cfg.Kerberos.Realm == "" {
		slog.Warn("Kerberos realm is not explicitly set in config, relying on system defaults or auto-detection.")
	}

	// EBPF Validation
	// Interface is informational, no validation needed
	// LoadMode is informational, no validation needed
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

	// General Validation
	if cfg.SocketPath == "" {
		return errors.New("socket_path must be specified for IPC")
	}
	if cfg.ShutdownTimeout <= 0 {
		return errors.New("shutdown_timeout must be a positive number of seconds")
	}

	// Log level validation isn't strictly necessary as slog handles unknown levels gracefully,
	// but could be added if specific levels are required.

	return nil
}

// setDefaults configures the default values in viper.
func setDefaults(v *viper.Viper) {
	v.SetDefault("proxy.type", DefaultProxyType)
	v.SetDefault("proxy.url", "")
	v.SetDefault("proxy.wpad_url", "")
	v.SetDefault("proxy.connection_timeout", DefaultProxyConnectionTimeout)
	v.SetDefault("proxy.request_timeout", DefaultProxyRequestTimeout)
	v.SetDefault("proxy.max_retries", DefaultProxyMaxRetries)
	v.SetDefault("proxy.pac_charset", "utf-8")     // Default to UTF-8 for PAC files
	v.SetDefault("proxy.pac_execution_timeout", 5) // 5 second default for PAC execution

	v.SetDefault("kerberos.realm", "") // Rely on system default / auto-detect
	v.SetDefault("kerberos.kdc_host", "")
	v.SetDefault("kerberos.principal", "")
	v.SetDefault("kerberos.keytab_path", "")
	v.SetDefault("kerberos.enable_cache", DefaultKerberosEnableCache)
	v.SetDefault("kerberos.ticket_lifetime", 24) // Informational
	v.SetDefault("kerberos.cache_path", "")      // Use system default / KRB5CCNAME

	v.SetDefault("ebpf.interface", DefaultEBPFInterface)
	v.SetDefault("ebpf.program_path", "") // Not used
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

// SaveConfig saves the current configuration struct back to a file.
// Note: This is primarily for potential future use (e.g., a config update command)
// and is not typically used during normal operation.
func SaveConfig(cfg *Config, path string) error {
	slog.Info("Saving configuration", "path", path)

	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Use Viper to write the config, preserving structure
	v := viper.New()
	v.SetConfigType("yaml")

	// Marshal the config struct into a map[string]interface{} for Viper
	// Using a intermediate JSON marshal/unmarshal is a common way if direct struct doesn't work well
	cfgMap := make(map[string]interface{})
	tmpBytes, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config for saving: %w", err)
	}
	if err := json.Unmarshal(tmpBytes, &cfgMap); err != nil {
		return fmt.Errorf("failed to unmarshal config map for saving: %w", err)
	}

	// Viper handles shutdown_timeout as int, convert back
	if cfgMap != nil {
		cfgMap["shutdown_timeout"] = int(cfg.ShutdownTimeout.Seconds())
	}

	// Merge the map into Viper
	if err := v.MergeConfigMap(cfgMap); err != nil {
		return fmt.Errorf("failed to prepare config map for saving: %w", err)
	}

	// Write the config file
	if err := v.WriteConfigAs(path); err != nil {
		return fmt.Errorf("failed to save configuration to %s: %w", path, err)
	}

	// Set appropriate permissions (e.g., readable by service user/group)
	if err := os.Chmod(path, 0640); err != nil {
		// Log as warning, saving still succeeded
		slog.Warn("Failed to set permissions on saved config file", "path", path, "error", err)
	}

	slog.Info("Configuration saved successfully", "path", path)
	return nil
}
