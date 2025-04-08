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

	appconfig "github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

type KerberosClient struct {
	config        *appconfig.KerberosConfig
	client        *gokrb5client.Client
	mu            sync.Mutex
	ticketExpiry  time.Time
	isInitialized bool
	ccacheName    string
}

// NewKerberosClient creates a Kerberos client configured to use the user's ccache.
func NewKerberosClient(cfg *appconfig.KerberosConfig) (*KerberosClient, error) {
	slog.Info("Initializing Kerberos client context (user ccache mode)")

	k := &KerberosClient{
		config: cfg,
	}

	k.ccacheName = determineEffectiveCacheName(cfg.CachePath)

	// Attempt initial load, log outcome appropriately
	loadErr := k.initializeFromCCache()
	if loadErr != nil {
		// Log unexpected errors during load attempt
		slog.Error("Unexpected error during initial Kerberos client setup from ccache",
			"ccache", k.ccacheName, "error", loadErr)
	} else if !k.isInitialized {
		slog.Info("Kerberos client configured, but no valid credentials found in ccache initially.", "ccache", k.ccacheName)
	} else {
		slog.Info("Kerberos client successfully initialized with credentials from ccache.", "ccache", k.ccacheName)
	}

	slog.Info("Kerberos client initialization sequence complete.")
	return k, nil // Return k even if initial load fails, allows retries
}

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

	k.ccacheName = determineEffectiveCacheName(k.config.CachePath)
	effectiveCacheName := k.ccacheName

	slog.Info("Attempting Kerberos init/refresh using credential cache", "name", effectiveCacheName)

	cc, err := credentials.LoadCCache(effectiveCacheName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Info("Credential cache not found.", "path", effectiveCacheName)
			return nil // Not an error, just no ticket to load
		}
		// Log other load errors but don't mark as initialized
		slog.Error("Failed to load user ccache", "path", effectiveCacheName, "error", err)
		return fmt.Errorf("unexpected error loading ccache '%s': %w", effectiveCacheName, err)
	}

	// Try creating client without explicit config first
	cl, err := gokrb5client.NewFromCCache(cc, nil, gokrb5client.DisablePAFXFAST(true))
	if err != nil {
		slog.Error("Failed to create client from loaded ccache (auto config detection)", "ccache", effectiveCacheName, "error", err)

		// Retry with explicitly loaded system config
		systemConf, confErr := krb5config.Load(getDefaultKrb5ConfPath())
		if confErr == nil && systemConf != nil {
			clRetry, retryErr := gokrb5client.NewFromCCache(cc, systemConf, gokrb5client.DisablePAFXFAST(true))
			if retryErr == nil {
				slog.Info("Successfully created client from ccache using explicitly loaded system krb5.conf")
				cl = clRetry
				err = nil // Success after retry
			} else {
				slog.Error("Retry with explicit system krb5.conf also failed", "error", retryErr)
			}
		} else if confErr != nil && !errors.Is(confErr, os.ErrNotExist) {
			slog.Warn("Failed to load system krb5.conf during retry", "error", confErr)
		}

		if err != nil {
			return fmt.Errorf("failed create client from ccache: %w", err) // Return the original or retry error
		}
	}

	// Check if the loaded credentials are valid
	if cl.Credentials == nil || cl.Credentials.Expired() {
		errMsg := "no valid credentials found in loaded ccache or credentials expired"
		slog.Warn(errMsg, "ccache", effectiveCacheName)
		cl.Destroy() // Clean up the client instance
		return nil   // Not an error, just invalid ticket state
	}

	// Success - valid credentials loaded
	k.client = cl
	k.isInitialized = true
	// Estimate expiry - replace with actual TGT expiry if gokrb5 exposes it easily in the future
	k.ticketExpiry = time.Now().Add(8 * time.Hour)
	slog.Debug("Using standard 8-hour ticket lifetime estimate", "expiry", k.ticketExpiry.Format(time.RFC3339))

	slog.Info("Kerberos context initialized successfully from ccache",
		"principal", strings.Join(k.client.Credentials.CName().NameString, "/"),
		"realm", k.client.Credentials.Realm(),
		"estimated_tgt_expiry", k.ticketExpiry.Format(time.RFC3339))

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

		err := k.initializeFromCCache() // This will update internal state (isInitialized, ticketExpiry)
		if err != nil {
			// Log unexpected errors during the reload attempt
			slog.Error("Failed to refresh Kerberos client from ccache", "ccache", ccName, "error", err)
			return fmt.Errorf("ccache reload attempt failed unexpectedly: %w", err)
		}
		// Check the state *after* the attempt
		k.mu.Lock()
		reloadedInit := k.isInitialized
		k.mu.Unlock()
		if reloadedInit {
			slog.Info("Kerberos client state refreshed successfully from ccache.")
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
	// Use IsInitialized which handles locking and checks expiry
	if !k.IsInitialized() {
		return nil
	}
	// Re-lock briefly just to get the client pointer
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.client
}

// GetStatus returns the current status information of the Kerberos client.
func (k *KerberosClient) GetStatus() map[string]interface{} {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Ensure ccacheName is up-to-date if config changed
	k.ccacheName = determineEffectiveCacheName(k.config.CachePath)
	isCurrentlyValid := k.isInitialized && k.client != nil && !k.ticketExpiry.IsZero() && time.Now().Before(k.ticketExpiry)

	status := map[string]interface{}{
		"initialized":           isCurrentlyValid, // Reflects current validity
		"principal":             "N/A",
		"realm":                 "N/A",
		"tgt_expiry":            "N/A",
		"tgt_time_left":         "N/A",
		"source":                "ccache",
		"effective_ccache_path": k.ccacheName,
	}

	if k.isInitialized && k.client != nil && k.client.Credentials != nil {
		// Populate details even if expired, but initialized reflects validity
		status["principal"] = strings.Join(k.client.Credentials.CName().NameString, "/")
		status["realm"] = k.client.Credentials.Realm()
		if !k.ticketExpiry.IsZero() {
			status["tgt_expiry"] = k.ticketExpiry.Format(time.RFC3339)
			timeLeft := time.Until(k.ticketExpiry)
			if timeLeft > 0 {
				status["tgt_time_left"] = timeLeft.Round(time.Second).String()
			} else {
				status["tgt_time_left"] = "Expired"
				status["initialized"] = false // Explicitly mark as not initialized if expired
			}
		} else {
			status["tgt_expiry"] = "Unknown (estimate failed)"
			status["initialized"] = false // Can't be valid if expiry is unknown
		}
	} else {
		// If not initialized or client is nil
		status["tgt_time_left"] = "Not Initialized / No Ticket"
		status["initialized"] = false
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

func determineEffectiveCacheName(configCachePath string) string {
	cachePath := os.Getenv("KRB5CCNAME")
	source := "environment (KRB5CCNAME)"

	if cachePath == "" && configCachePath != "" && !strings.Contains(configCachePath, "%{null}") {
		cachePath = configCachePath
		source = "config (kerberos.cachePath)"
	}

	if cachePath == "" {
		uidStr := strconv.Itoa(os.Getuid())
		cachePath = fmt.Sprintf("FILE:/tmp/krb5cc_%s", uidStr)
		source = "default pattern"
	}

	// Expand placeholders like %{uid}
	if strings.Contains(cachePath, "%{uid}") {
		cachePath = strings.ReplaceAll(cachePath, "%{uid}", strconv.Itoa(os.Getuid()))
	}
	if strings.Contains(cachePath, "%{USERID}") { // Some systems might use USERID
		cachePath = strings.ReplaceAll(cachePath, "%{USERID}", strconv.Itoa(os.Getuid()))
	}

	// Ensure ccache type prefix exists (default to FILE:)
	hasPrefix := false
	knownPrefixes := []string{"FILE:", "DIR:", "API:", "KEYRING:", "KCM:", "MSLSA:"} // Add MSLSA for Windows
	upperCachePath := strings.ToUpper(cachePath)
	for _, prefix := range knownPrefixes {
		if strings.HasPrefix(upperCachePath, prefix) {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		originalPath := cachePath
		cachePath = "FILE:" + cachePath
		slog.Debug("Prepended 'FILE:' prefix to ccache name", "original", originalPath, "new", cachePath)
	}

	slog.Debug("Effective ccache name determined", "source", source, "path", cachePath)
	return cachePath
}

func getDefaultKrb5ConfPath() string {
	// TODO: Add better cross-platform logic if needed
	if os.PathSeparator == '\\' {
		// Basic Windows guess - might need registry checks for robust solution
		programData := os.Getenv("PROGRAMDATA")
		if programData != "" {
			return programData + "\\Kerberos\\krb5.conf" // Common location
		}
		return "C:\\ProgramData\\Kerberos\\krb5.conf" // Fallback guess
	}
	return "/etc/krb5.conf" // Linux/macOS default
}
