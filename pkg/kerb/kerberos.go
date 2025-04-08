package kerb

import (
	"errors"
	"fmt"
	"log/slog" // Only for deprecated function signature
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

	err := k.initializeFromCCache()
	if err != nil {
		slog.Warn("Initial Kerberos client setup from ccache failed",
			"ccache", k.ccacheName,
			"error", err,
			"advice", "This is normal if user hasn't run kinit. Will retry on demand.")
	} else {
		slog.Info("Kerberos client successfully initialized from existing ccache.")
	}

	slog.Info("Kerberos client initialized. Ready to use user credentials when available.")
	return k, nil
}

func (k *KerberosClient) initializeFromCCache() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.client != nil {
		k.client.Destroy()
		k.client = nil
		k.isInitialized = false
		k.ticketExpiry = time.Time{}
		slog.Debug("Destroyed previous Kerberos client instance before reloading ccache")
	}

	k.ccacheName = determineEffectiveCacheName(k.config.CachePath)
	effectiveCacheName := k.ccacheName

	slog.Info("Attempting Kerberos init/refresh using credential cache", "name", effectiveCacheName)

	cc, err := credentials.LoadCCache(effectiveCacheName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Info("Credential cache not found.", "path", effectiveCacheName)
			k.isInitialized = false
			return nil // Not an error, just no ticket
		}
		k.isInitialized = false
		slog.Error("Failed to load user ccache", "path", effectiveCacheName, "error", err)
		return fmt.Errorf("unexpected error loading ccache '%s': %w", effectiveCacheName, err)
	}

	// Try creating client without explicit config first
	cl, err := gokrb5client.NewFromCCache(cc, nil, gokrb5client.DisablePAFXFAST(true))
	if err != nil {
		k.isInitialized = false
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
			return fmt.Errorf("failed create client from ccache: %w", err)
		}
	}

	if cl.Credentials == nil || cl.Credentials.Expired() {
		k.isInitialized = false
		cl.Destroy()
		errMsg := "no valid credentials found in loaded ccache or credentials expired"
		slog.Warn(errMsg, "ccache", effectiveCacheName)
		return nil // Not an error, just invalid ticket
	}

	k.client = cl
	k.isInitialized = true

	// Set expiry time as a standard duration from now
	// Can't directly access TGT details from credentials in this gokrb5 version
	k.ticketExpiry = time.Now().Add(8 * time.Hour)
	slog.Debug("Using standard 8-hour ticket lifetime estimate", "expiry", k.ticketExpiry.Format(time.RFC3339))

	slog.Info("Kerberos context initialized from ccache",
		"principal", strings.Join(k.client.Credentials.CName().NameString, "/"),
		"realm", k.client.Credentials.Realm(),
		"tgt_expiry", k.ticketExpiry.Format(time.RFC3339))

	return nil
}

// IsInitialized returns true if the client has successfully loaded a valid ccache.
func (k *KerberosClient) IsInitialized() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.isInitialized && k.client != nil && !k.ticketExpiry.IsZero() && time.Now().Before(k.ticketExpiry)
}

// CheckAndRefreshClient checks the ticket status and attempts to refresh by reloading the ccache.
// Returns an error only on unexpected issues.
func (k *KerberosClient) CheckAndRefreshClient() error {
	k.mu.Lock()
	isInit := k.isInitialized
	expiry := k.ticketExpiry
	ccName := k.ccacheName
	k.mu.Unlock()

	needsRefresh := !isInit || expiry.IsZero() || time.Now().Add(5*time.Minute).After(expiry)

	if needsRefresh {
		slog.Info("Kerberos ticket check: requires refresh/initialization attempt.",
			"ccache", ccName,
			"reason_needs_init", !isInit,
			"reason_expiry_near_or_zero", expiry.IsZero() || time.Now().Add(5*time.Minute).After(expiry))

		err := k.initializeFromCCache()
		if err != nil {
			slog.Error("Failed to refresh Kerberos client from ccache", "ccache", ccName, "error", err)
			return fmt.Errorf("ccache reload attempt failed unexpectedly: %w", err)
		}
		slog.Info("Kerberos client state refreshed/re-checked from ccache.")
		return nil
	}

	slog.Debug("Kerberos ticket check: OK (initialized and not expired)")
	return nil
}

// Gokrb5Client returns the underlying gokrb5 client instance if initialized.
func (k *KerberosClient) Gokrb5Client() *gokrb5client.Client {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.isInitialized || k.client == nil {
		return nil
	}
	return k.client
}

// GetStatus returns the current status information of the Kerberos client.
func (k *KerberosClient) GetStatus() map[string]interface{} {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.ccacheName = determineEffectiveCacheName(k.config.CachePath)

	status := map[string]interface{}{
		"initialized":           k.isInitialized,
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
			}
		} else {
			status["tgt_expiry"] = "Unknown (estimate failed)"
		}
	} else if !k.isInitialized {
		status["tgt_time_left"] = "Not Initialized / No Ticket"
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

	if strings.Contains(cachePath, "%{uid}") {
		cachePath = strings.ReplaceAll(cachePath, "%{uid}", strconv.Itoa(os.Getuid()))
	}
	if strings.Contains(cachePath, "%{USERID}") {
		cachePath = strings.ReplaceAll(cachePath, "%{USERID}", strconv.Itoa(os.Getuid()))
	}

	hasPrefix := false
	knownPrefixes := []string{"FILE:", "DIR:", "API:", "KEYRING:", "KCM:"}
	for _, prefix := range knownPrefixes {
		if strings.HasPrefix(strings.ToUpper(cachePath), prefix) {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		cachePath = "FILE:" + cachePath
		slog.Debug("Prepended 'FILE:' prefix to ccache name", "path", cachePath)
	}

	slog.Debug("Effective ccache name determined", "source", source, "path", cachePath)
	return cachePath
}

func getDefaultKrb5ConfPath() string {
	// TODO: Add Windows support if needed
	return "/etc/krb5.conf"
}
