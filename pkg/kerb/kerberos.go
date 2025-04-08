package kerb

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	gokrb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"

	appconfig "github.com/yolkispalkis/kernelgatekeeper/pkg/config"
)

type KerberosClient struct {
	config        *appconfig.KerberosConfig
	krb5Config    *krb5config.Config
	client        *gokrb5client.Client
	mu            sync.Mutex
	ticketExpiry  time.Time
	isInitialized bool
}

func NewKerberosClient(cfg *appconfig.KerberosConfig) (*KerberosClient, error) {
	slog.Info("Initializing Kerberos client for user", "realm", cfg.Realm)

	effectiveCacheName := determineEffectiveCacheName(cfg.CachePath)
	slog.Debug("Determined effective ccache name pattern", "pattern", effectiveCacheName)

	krbConf, err := loadMinimalKrb5Config(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed load krb5 config: %w", err)
	}

	k := &KerberosClient{
		config:     cfg,
		krb5Config: krbConf,
	}

	if err := k.initializeFromCCache(effectiveCacheName); err != nil {
		slog.Warn("Initial Kerberos client setup from ccache failed", "error", err, "advice", "Ensure 'kinit' has been run or ccache is valid.")
		// Note: We continue even if initial load fails, CheckAndRefreshClient will try again later.
	} else {
		slog.Info("Kerberos client successfully initialized from ccache.")
	}

	// Note: Automatic renewal is usually handled by system tools (kinit -R, sssd) when using ccache.
	slog.Warn("Automatic ticket renewal is handled by system tools (e.g., kinit, sssd) when using user credential cache (ccache).")

	return k, nil
}

func determineEffectiveCacheName(configCachePath string) string {
	cachePath := os.Getenv("KRB5CCNAME")
	source := "environment (KRB5CCNAME)"

	if cachePath == "" && configCachePath != "" && !strings.Contains(configCachePath, "%{null}") {
		cachePath = configCachePath
		source = "config (kerberos.cache_path)"
	}

	if cachePath == "" {
		uidStr := strconv.Itoa(os.Getuid())
		// Default ccache name pattern used by many systems
		cachePath = fmt.Sprintf("FILE:/tmp/krb5cc_%s", uidStr)
		source = "default pattern"
	}

	// Replace %{uid} / %{USERID} if present (common in krb5.conf defaults)
	if strings.Contains(cachePath, "%{uid}") {
		cachePath = strings.ReplaceAll(cachePath, "%{uid}", strconv.Itoa(os.Getuid()))
	}
	if strings.Contains(cachePath, "%{USERID}") {
		cachePath = strings.ReplaceAll(cachePath, "%{USERID}", strconv.Itoa(os.Getuid()))
	}

	// Ensure FILE: prefix if not already present and it's not another type
	hasPrefix := false
	for _, prefix := range []string{"FILE:", "DIR:", "API:", "KEYRING:", "KCM:"} {
		if strings.HasPrefix(cachePath, prefix) {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		// Assume FILE: if no other known prefix is present
		cachePath = "FILE:" + cachePath
		slog.Debug("Prepended 'FILE:' prefix to ccache name", "original", strings.TrimPrefix(cachePath, "FILE:"), "final", cachePath)
	}

	slog.Debug("Effective ccache name determined", "source", source, "path", cachePath)
	return cachePath
}

func loadMinimalKrb5Config(cfg *appconfig.KerberosConfig) (*krb5config.Config, error) {
	// Explicitly try loading the standard system path first
	systemConfigPath := "/etc/krb5.conf"
	c, err := krb5config.Load(systemConfigPath)
	// Also check if the loaded config is minimally useful (e.g., has a default realm)
	if err == nil && c != nil && c.LibDefaults.DefaultRealm != "" {
		slog.Info("Loaded system Kerberos configuration for client context", "path", systemConfigPath)
		if cfg.Realm != "" && c.LibDefaults.DefaultRealm != cfg.Realm {
			slog.Debug("Overriding default_realm from system config", "system", c.LibDefaults.DefaultRealm, "app", cfg.Realm)
			c.LibDefaults.DefaultRealm = cfg.Realm
		}
		return c, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		// Log error if it's not "file not found"
		slog.Warn("Error loading system krb5.conf", "path", systemConfigPath, "error", err)
	} else if errors.Is(err, os.ErrNotExist) {
		// Log specifically if the explicit path doesn't exist
		slog.Info("System krb5.conf not found at explicit path", "path", systemConfigPath)
	} else if err == nil && (c == nil || c.LibDefaults.DefaultRealm == "") {
		// Log if load succeeded but config seems empty/useless
		slog.Info("System krb5.conf loaded but appears empty or lacks default_realm", "path", systemConfigPath)
	}

	// Fallback to minimal config generation
	slog.Info("No valid system krb5.conf found or load failed, creating minimal config for client.")
	confStr := "[libdefaults]\n"
	realmSet := false
	if cfg.Realm != "" {
		confStr += fmt.Sprintf("  default_realm = %s\n", cfg.Realm)
		realmSet = true
	} else {
		// Try to guess realm from username@REALM
		currentUser, userErr := user.Current()
		if userErr == nil && strings.Contains(currentUser.Username, "@") {
			parts := strings.SplitN(currentUser.Username, "@", 2)
			if len(parts) == 2 {
				realmGuess := strings.ToUpper(parts[1])
				confStr += fmt.Sprintf("  default_realm = %s\n", realmGuess)
				slog.Debug("Guessed default realm from username", "realm", realmGuess)
				realmSet = true
			}
		}
	}

	if !realmSet {
		return nil, errors.New("kerberos realm is not configured and could not be guessed")
	}

	confStr += "  dns_lookup_kdc = true\n"
	confStr += "  dns_lookup_realm = false\n" // Usually false for performance/security
	confStr += "  rdns = false\n"             // Usually false for security

	slog.Debug("Using minimal generated krb5 config string", "config", confStr)
	newConf, configErr := krb5config.NewFromString(confStr)
	if configErr != nil {
		return nil, fmt.Errorf("failed to parse minimal config string: %w", configErr)
	}
	return newConf, nil
}

func (k *KerberosClient) initializeFromCCache(effectiveCacheName string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Destroy existing client if any
	if k.client != nil {
		k.client.Destroy()
		k.client = nil
		k.isInitialized = false
		k.ticketExpiry = time.Time{}
		slog.Debug("Destroyed previous Kerberos client instance before reloading ccache")
	}

	slog.Info("Attempting Kerberos init using credential cache", "name", effectiveCacheName)

	// === Start FIX: Correct type for cc ===
	var cc *credentials.CCache // <--- FIX: Correct type is *credentials.CCache
	var err error
	const maxRetries = 3
	const retryDelay = 250 * time.Millisecond // Slightly longer delay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Log the exact path being used
		slog.Debug("LoadCCache attempt", "attempt", attempt, "path_quoted", fmt.Sprintf("%q", effectiveCacheName))

		cc, err = credentials.LoadCCache(effectiveCacheName) // Assigns to *credentials.CCache
		if err == nil {
			slog.Debug("LoadCCache successful", "attempt", attempt)
			break // Success!
		}

		// Check if the error is "no such file or directory"
		errMsg := err.Error()

		isNoSuchFileError := strings.Contains(errMsg, "no such file or directory")

		// Retry only for "no such file" and if attempts remain
		if isNoSuchFileError && attempt < maxRetries {
			slog.Warn("LoadCCache failed (no such file), retrying...",
				"attempt", attempt, "error", err)
			time.Sleep(retryDelay * time.Duration(attempt)) // Exponential backoff might be better, but simple delay for now
		} else {
			// Either a different error or max retries reached
			if isNoSuchFileError {
				slog.Error("LoadCCache failed (no such file) after max retries", "path", effectiveCacheName, "error", err)
			} else {
				slog.Error("LoadCCache failed with non-retryable error", "path", effectiveCacheName, "error", err)
			}
			break // Stop retrying
		}
	}
	// === End FIX ===

	// Check final error after potential retries
	if err != nil {
		k.isInitialized = false
		// Error already logged inside the loop
		return fmt.Errorf("failed load user ccache '%s': %w", effectiveCacheName, err)
	}

	// === Start FIX: Pass correct type to NewFromCCache ===
	cl, err := gokrb5client.NewFromCCache(cc, k.krb5Config, gokrb5client.DisablePAFXFAST(true)) // <--- FIX: cc is now *credentials.CCache, which is correct
	// === End FIX ===
	if err != nil {
		k.isInitialized = false
		slog.Error("Failed to create client from ccache", "error", err)
		return fmt.Errorf("failed create client from ccache: %w", err)
	}

	// Check if credentials are valid after creating client
	// We access the underlying Credentials from the client object now
	if cl.Credentials == nil {
		k.isInitialized = false
		cl.Destroy() // Clean up the partially created client
		errMsg := "no valid credentials found in loaded ccache (client.Credentials is nil)"
		slog.Error(errMsg)
		return errors.New(errMsg)
	}

	k.client = cl
	k.isInitialized = true

	// Estimate expiry as before
	estimatedExpiry := time.Now().Add(8 * time.Hour) // Default 8 hours estimate
	k.ticketExpiry = estimatedExpiry

	slog.Info("Kerberos context initialized from ccache",
		"principal", strings.Join(k.client.Credentials.CName().NameString, "/"), // Access Credentials via client
		"realm", k.client.Credentials.Realm(), // Access Credentials via client
		"estimated_expiry", k.ticketExpiry.Format(time.RFC3339))

	return nil
}

func (k *KerberosClient) Gokrb5Client() *gokrb5client.Client {
	k.mu.Lock()
	defer k.mu.Unlock()
	// Ensure client is valid before returning
	if !k.isInitialized || k.client == nil {
		return nil
	}
	return k.client
}

// CreateProxyTransport remains deprecated
func (k *KerberosClient) CreateProxyTransport(baseTransport *http.Transport) (http.RoundTripper, error) {
	slog.Warn("KerberosClient.CreateProxyTransport is deprecated and likely unused.")
	if err := k.CheckAndRefreshClient(); err != nil {
		slog.Warn("Kerberos ticket potentially invalid before creating SPNEGO transport", "error", err)
	}

	k.mu.Lock()
	gokrbCl := k.client
	isInit := k.isInitialized
	k.mu.Unlock()

	if !isInit || gokrbCl == nil {
		return nil, errors.New("kerberos client not initialized or ticket invalid, cannot create SPNEGO transport")
	}

	spnegoTransport := &spnegoRoundTripper{
		base:   baseTransport,
		client: gokrbCl,
	}
	slog.Info("Created SPNEGO HTTP transport wrapper using user credentials")

	return spnegoTransport, nil
}

// spnegoRoundTripper remains deprecated
type spnegoRoundTripper struct {
	base   *http.Transport
	client *gokrb5client.Client
}

// RoundTrip remains deprecated
func (s *spnegoRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqCopy := req.Clone(req.Context())
	err := spnego.SetSPNEGOHeader(s.client, reqCopy, "")
	if err != nil {
		return nil, fmt.Errorf("failed to set SPNEGO header: %w", err)
	}
	resp, err := s.base.RoundTrip(reqCopy)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (k *KerberosClient) CheckAndRefreshClient() error {
	k.mu.Lock()
	isInit := k.isInitialized
	expiry := k.ticketExpiry
	ccName := determineEffectiveCacheName(k.config.CachePath) // Recalculate in case env changed
	k.mu.Unlock()                                             // Unlock before potentially long operation

	needsRefresh := !isInit || expiry.IsZero() || time.Now().Add(5*time.Minute).After(expiry)

	if needsRefresh {
		slog.Info("Kerberos ticket check: attempting refresh by reloading ccache...",
			"ccache", ccName,
			"reason_needs_init", !isInit,
			"reason_expiry_near_or_zero", expiry.IsZero() || time.Now().Add(5*time.Minute).After(expiry))

		err := k.initializeFromCCache(ccName)
		if err != nil {
			k.mu.Lock()
			k.isInitialized = false // Mark as not initialized on failure
			k.mu.Unlock()
			slog.Error("Failed to refresh Kerberos client from ccache", "error", err)
			return fmt.Errorf("ccache reload failed: %w", err)
		}
		slog.Info("Kerberos client state refreshed from ccache.")
		return nil // Refresh successful
	}

	slog.Debug("Kerberos ticket check: OK (based on estimated expiry)")
	return nil
}

func (k *KerberosClient) GetStatus() map[string]interface{} {
	k.mu.Lock()
	defer k.mu.Unlock()

	ccName := determineEffectiveCacheName(k.config.CachePath)

	status := map[string]interface{}{
		"initialized":           k.isInitialized,
		"principal":             "N/A",
		"realm":                 "N/A",
		"tgt_expiry":            "N/A",
		"tgt_time_left":         "N/A",
		"source":                "ccache",
		"effective_ccache_path": ccName,
	}

	// Check client and client.Credentials for validity
	if k.isInitialized && k.client != nil && k.client.Credentials != nil {
		status["principal"] = strings.Join(k.client.Credentials.CName().NameString, "/")
		status["realm"] = k.client.Credentials.Realm()
		if !k.ticketExpiry.IsZero() {
			status["tgt_expiry"] = k.ticketExpiry.Format(time.RFC3339) + " (estimated)"
			timeLeft := time.Until(k.ticketExpiry)
			if timeLeft > 0 {
				status["tgt_time_left"] = timeLeft.Round(time.Second).String() + " (estimated)"
			} else {
				status["tgt_time_left"] = "Expired (estimated)"
			}
		}
	} else if !k.isInitialized {
		status["tgt_time_left"] = "Client not initialized"
	}

	return status
}

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
	k.ticketExpiry = time.Time{} // Clear expiry on close
	slog.Info("Kerberos client closed.")
}
