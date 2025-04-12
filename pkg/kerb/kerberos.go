// FILE: pkg/kerb/kerberos.go
package kerb

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	gokrb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"

	// Import the actual config package
	pkgconfig "github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

// KerberosClient manages Kerberos authentication using user ccache.
type KerberosClient struct {
	// config is kept minimally for potential future use (e.g. realm/kdc hints)
	// but cachePath is NOT used from here anymore.
	config *pkgconfig.KerberosConfig // Use the imported config type

	client        *gokrb5client.Client
	mu            sync.Mutex
	ticketExpiry  time.Time
	isInitialized bool
	ccacheName    string // Store the determined ccache name
}

// NewKerberosClient creates a Kerberos client configured to use the user's ccache.
// Accepts the KerberosConfig part from the main application config.
func NewKerberosClient(cfg *pkgconfig.KerberosConfig) (*KerberosClient, error) { // Use imported config type
	slog.Info("Initializing Kerberos client context (user ccache mode)")

	k := &KerberosClient{
		config: cfg, // Store config, but don't rely on CachePath from it
	}

	// Determine cache name based *only* on environment and defaults
	k.ccacheName = determineEffectiveCacheName()

	// Attempt initial load
	loadErr := k.initializeFromCCache()
	if loadErr != nil {
		slog.Error("Unexpected error during initial Kerberos client setup from ccache",
			"ccache", k.ccacheName, "error", loadErr)
		// Return k even on error, CheckAndRefreshClient can retry
	} else if !k.isInitialized {
		slog.Info("Kerberos client configured, but no valid credentials found in ccache initially.", "ccache", k.ccacheName)
	} else {
		slog.Info("Kerberos client successfully initialized with credentials from ccache.", "ccache", k.ccacheName)
	}

	slog.Info("Kerberos client initialization sequence complete.")
	return k, nil // Return client instance regardless of initial ticket state
}

// initializeFromCCache attempts to load credentials and create a gokrb5 client.
// Must be called with the mutex held.
func (k *KerberosClient) initializeFromCCache() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Destroy previous client if exists
	if k.client != nil {
		k.client.Destroy()
		k.client = nil
		slog.Debug("Destroyed previous Kerberos client instance before reloading ccache")
	}
	// Reset state before attempting load
	k.isInitialized = false
	k.ticketExpiry = time.Time{}

	// Determine ccache name again inside lock to be sure (though unlikely to change)
	k.ccacheName = determineEffectiveCacheName()
	effectiveCacheName := k.ccacheName

	slog.Info("Attempting Kerberos init/refresh using credential cache", "name", effectiveCacheName)

	cc, err := credentials.LoadCCache(effectiveCacheName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Info("Credential cache not found.", "path", effectiveCacheName)
			return nil // Not an error, just no ticket to load
		}
		slog.Error("Failed to load user ccache", "path", effectiveCacheName, "error", err)
		return fmt.Errorf("unexpected error loading ccache '%s': %w", effectiveCacheName, err)
	}

	// Try creating client without explicit config first
	cl, err := gokrb5client.NewFromCCache(cc, nil, gokrb5client.DisablePAFXFAST(true))
	if err != nil {
		slog.Warn("Failed to create client from loaded ccache (auto config detection), trying with explicit system krb5.conf", "ccache", effectiveCacheName, "error", err)

		systemConf, confErr := krb5config.Load(getDefaultKrb5ConfPath())
		if confErr == nil && systemConf != nil {
			clRetry, retryErr := gokrb5client.NewFromCCache(cc, systemConf, gokrb5client.DisablePAFXFAST(true))
			if retryErr == nil {
				slog.Info("Successfully created client from ccache using explicitly loaded system krb5.conf")
				cl = clRetry
				err = nil // Success after retry
			} else {
				slog.Error("Retry with explicit system krb5.conf also failed", "error", retryErr)
				// Keep the original error 'err'
			}
		} else if confErr != nil && !errors.Is(confErr, os.ErrNotExist) {
			slog.Warn("Failed to load system krb5.conf during retry", "path", getDefaultKrb5ConfPath(), "error", confErr)
		}

		// If still error after retry attempts
		if err != nil {
			return fmt.Errorf("failed create client from ccache '%s': %w", effectiveCacheName, err)
		}
	}

	// Check if the loaded credentials are valid
	if cl.Credentials == nil || cl.Credentials.Expired() {
		errMsg := "No valid credentials found in loaded ccache or credentials expired."
		slog.Warn(errMsg, "ccache", effectiveCacheName)
		if cl.Credentials != nil {
			slog.Warn("Credentials details", "principal", strings.Join(cl.Credentials.CName().NameString, "/"), "realm", cl.Credentials.Realm())
		}
		cl.Destroy() // Clean up the client instance
		return nil   // Not an error, just invalid ticket state
	}

	// Success - valid credentials loaded
	k.client = cl
	k.isInitialized = true
	k.ticketExpiry = cl.Credentials.ValidUntil()
	slog.Debug("Using actual credential end time from ccache", "expiry", k.ticketExpiry.Format(time.RFC3339))

	slog.Info("Kerberos context initialized successfully from ccache",
		"principal", strings.Join(k.client.Credentials.CName().NameString, "/"),
		"realm", k.client.Credentials.Realm(),
		"tgt_expiry", k.ticketExpiry.Format(time.RFC3339))

	return nil
}

// IsInitialized returns true if the client has successfully loaded a valid, non-expired ccache.
func (k *KerberosClient) IsInitialized() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	// Check all conditions: flag set, client exists, expiry known and not passed
	return k.isInitialized && k.client != nil && !k.ticketExpiry.IsZero() && time.Now().Before(k.ticketExpiry)
}

// CheckAndRefreshClient checks the ticket status and attempts to refresh by reloading the ccache.
func (k *KerberosClient) CheckAndRefreshClient() error {
	k.mu.Lock()
	isInit := k.isInitialized
	expiry := k.ticketExpiry
	ccName := k.ccacheName
	k.mu.Unlock()

	// Refresh if not initialized, expiry is unknown, or nearing expiry (e.g., within 5 mins)
	needsRefresh := !isInit || expiry.IsZero() || time.Now().Add(5*time.Minute).After(expiry)

	if needsRefresh {
		slog.Info("Kerberos ticket check: requires refresh/initialization attempt.",
			"ccache", ccName,
			"reason_needs_init", !isInit,
			"reason_expiry_near_or_zero", expiry.IsZero() || time.Now().Add(5*time.Minute).After(expiry))

		// Reload from ccache (initializeFromCCache handles locking internally)
		err := k.initializeFromCCache()
		if err != nil {
			slog.Error("Failed to refresh Kerberos client from ccache", "ccache", ccName, "error", err)
			return fmt.Errorf("ccache reload attempt failed unexpectedly: %w", err)
		}

		// Check the state *after* the attempt
		k.mu.Lock()
		reloadedInit := k.isInitialized
		reloadedExpiry := k.ticketExpiry
		k.mu.Unlock()

		if reloadedInit {
			slog.Info("Kerberos client state refreshed successfully from ccache.", "new_expiry", reloadedExpiry.Format(time.RFC3339))
		} else {
			slog.Warn("Kerberos client refresh attempt completed, but still no valid credentials found.")
		}
		return nil // Return nil even if no valid ticket found, error only on unexpected issues
	}

	slog.Debug("Kerberos ticket check: OK (initialized and not expired)")
	return nil
}

// Gokrb5Client returns the underlying gokrb5 client instance if initialized and valid.
func (k *KerberosClient) Gokrb5Client() *gokrb5client.Client {
	k.mu.Lock() // Lock needed to safely access k.client
	defer k.mu.Unlock()
	// Check isInitialized and expiry *while holding the lock*
	if k.isInitialized && k.client != nil && !k.ticketExpiry.IsZero() && time.Now().Before(k.ticketExpiry) {
		return k.client
	}
	return nil
}

// GetStatus returns the current status information of the Kerberos client.
func (k *KerberosClient) GetStatus() map[string]interface{} {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Ensure ccacheName is up-to-date (though unlikely to change unless env var does)
	k.ccacheName = determineEffectiveCacheName()
	isCurrentlyValid := k.isInitialized && k.client != nil && !k.ticketExpiry.IsZero() && time.Now().Before(k.ticketExpiry)

	status := map[string]interface{}{
		"initialized":           isCurrentlyValid,
		"principal":             "N/A",
		"realm":                 "N/A",
		"tgt_expiry":            "N/A",
		"tgt_time_left":         "N/A",
		"source":                "ccache",
		"effective_ccache_path": k.ccacheName,
	}

	if k.isInitialized && k.client != nil && k.client.Credentials != nil {
		status["principal"] = strings.Join(k.client.Credentials.CName().NameString, "/")
		status["realm"] = k.client.Credentials.Realm()
		if !k.ticketExpiry.IsZero() {
			status["tgt_expiry"] = k.ticketExpiry.Format(time.RFC3339)
			timeLeft := time.Until(k.ticketExpiry)
			if timeLeft > 0 {
				status["tgt_time_left"] = timeLeft.Round(time.Second).String()
			} else {
				status["tgt_time_left"] = "Expired"
				// Don't set initialized=false here, let the main check handle it
			}
		} else {
			status["tgt_expiry"] = "Unknown (lookup failed)"
		}
	}

	// Update initialized based on the final check
	status["initialized"] = isCurrentlyValid
	if !isCurrentlyValid {
		status["tgt_time_left"] = "Not Initialized / Expired"
	}

	return status
}

// Close releases resources associated with the Kerberos client.
func (k *KerberosClient) Close() {
	slog.Info("Closing Kerberos client (user context)...")
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.client != nil {
		k.client.Destroy()
		k.client = nil
		slog.Debug("Kerberos client session destroyed.")
	}
	k.isInitialized = false
	k.ticketExpiry = time.Time{}
	slog.Info("Kerberos client closed.")
}

// --- Helper Functions ---

// determineEffectiveCacheName determines the ccache path based only on
// environment variables and default patterns. It IGNORES any path set in config.
func determineEffectiveCacheName() string {
	cachePath := os.Getenv("KRB5CCNAME")
	source := "environment (KRB5CCNAME)"

	if cachePath == "" {
		uidStr := strconv.Itoa(os.Getuid())
		// Common default patterns
		defaultPatterns := []string{
			fmt.Sprintf("/tmp/krb5cc_%s", uidStr),          // Default on many Linux systems
			fmt.Sprintf("/var/run/user/%s/krb5cc", uidStr), // Systemd user session default
		}
		// Check which default exists
		for _, pattern := range defaultPatterns {
			potentialPath := "FILE:" + pattern
			// Simple check if the file itself exists for FILE type
			if _, err := os.Stat(pattern); err == nil {
				cachePath = potentialPath
				source = "default pattern (" + pattern + ")"
				break
			}
		}
		// Fallback if no default found
		if cachePath == "" {
			cachePath = "FILE:/tmp/krb5cc_" + uidStr // Fallback to original default if others don't exist
			source = "fallback default pattern"
		}
	}

	// Expand %{uid} if present (though less likely if default is used)
	if strings.Contains(cachePath, "%{uid}") {
		cachePath = strings.ReplaceAll(cachePath, "%{uid}", strconv.Itoa(os.Getuid()))
	}
	if strings.Contains(cachePath, "%{USERID}") {
		cachePath = strings.ReplaceAll(cachePath, "%{USERID}", strconv.Itoa(os.Getuid()))
	}

	// Ensure ccache type prefix exists
	hasPrefix := false
	knownPrefixes := []string{"FILE:", "DIR:", "API:", "KEYRING:", "KCM:", "MSLSA:"}
	upperCachePath := strings.ToUpper(cachePath)
	for _, prefix := range knownPrefixes {
		if strings.HasPrefix(upperCachePath, prefix) {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		originalPath := cachePath
		cachePath = "FILE:" + cachePath // Default to FILE:
		slog.Debug("Prepended 'FILE:' prefix to ccache name", "original", originalPath, "new", cachePath)
	}

	slog.Debug("Effective ccache name determined", "source", source, "path", cachePath)
	return cachePath
}

func getDefaultKrb5ConfPath() string {
	// Check environment variable first
	if path := os.Getenv("KRB5_CONFIG"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	if os.PathSeparator == '\\' { // Basic Windows check
		programData := os.Getenv("PROGRAMDATA")
		if programData != "" {
			// Check common locations within ProgramData
			locations := []string{
				programData + "\\Kerberos\\krb5.conf",
				programData + "\\Kerberos\\krb5.ini",
				programData + "\\MIT\\Kerberos\\krb5.ini",
				programData + "\\MIT\\Kerberos\\krb5.conf",
			}
			for _, path := range locations {
				if _, err := os.Stat(path); err == nil {
					return path
				}
			}
		}
		// Fallback guesses for Windows outside ProgramData (less standard)
		if _, err := os.Stat("C:\\Windows\\krb5.ini"); err == nil {
			return "C:\\Windows\\krb5.ini"
		}
		return "" // No standard default known easily or found
	}
	// Linux/macOS default
	return "/etc/krb5.conf"
}
