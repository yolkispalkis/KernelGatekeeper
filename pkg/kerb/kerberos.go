// pkg/kerb/kerberos.go
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

	gokrb5client "github.com/jcmturner/gokrb5/v8/client" // Alias for gokrb5 client type
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types" // Import types for Ticket

	appconfig "github.com/yolki/kernelgatekeeper/pkg/config"
)

type KerberosClient struct {
	config        *appconfig.KerberosConfig
	krb5Config    *krb5config.Config
	client        *gokrb5client.Client // Use the aliased type here
	mu            sync.Mutex
	ticketExpiry  time.Time
	stopCh        chan struct{}
	isInitialized bool
}

// NewKerberosClient initializes a Kerberos client primarily using the user's credential cache (ccache).
// Configuration hints like realm are used, but the actual TGT is expected to be managed externally (e.g., via kinit).
func NewKerberosClient(cfg *appconfig.KerberosConfig) (*KerberosClient, error) {
	slog.Info("Initializing Kerberos client for user", "realm", cfg.Realm)

	effectiveCacheName := determineEffectiveCacheName(cfg.CachePath)
	slog.Debug("Determined effective ccache name pattern", "pattern", effectiveCacheName)

	// Load system krb5.conf if available, otherwise create a minimal one.
	// This provides context like default_realm if not specified or for DNS lookups.
	krbConf, err := loadMinimalKrb5Config(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed load krb5 config: %w", err)
	}

	k := &KerberosClient{
		config:     cfg,
		krb5Config: krbConf,
		stopCh:     make(chan struct{}),
	}

	// Attempt initial setup from the credential cache.
	if err := k.initializeFromCCache(effectiveCacheName); err != nil {
		slog.Warn("Initial Kerberos client setup from ccache failed", "error", err, "advice", "Ensure 'kinit' has been run or ccache is valid.")
		// Continue even if initial load fails; CheckAndRefreshClient might succeed later.
	} else {
		slog.Info("Kerberos client successfully initialized from ccache.")
	}

	// Note: This client relies on external tools (kinit, sssd) to manage the TGT in the ccache.
	// It only reads the cache, it doesn't perform kinit itself.
	slog.Warn("Automatic ticket renewal is handled by system tools (e.g., kinit, sssd) when using user credential cache (ccache).")

	return k, nil
}

// determineEffectiveCacheName figures out the ccache path based on environment, config, or defaults.
func determineEffectiveCacheName(configCachePath string) string {
	cachePath := os.Getenv("KRB5CCNAME")
	source := "environment (KRB5CCNAME)"

	// If KRB5CCNAME is not set, try the path from the application config
	if cachePath == "" && configCachePath != "" && !strings.Contains(configCachePath, "%{null}") {
		cachePath = configCachePath
		source = "config (kerberos.cache_path)"
	}

	// If still no path, use the default pattern /tmp/krb5cc_%{uid}
	if cachePath == "" {
		uidStr := strconv.Itoa(os.Getuid())
		cachePath = fmt.Sprintf("FILE:/tmp/krb5cc_%s", uidStr)
		source = "default pattern"
	}

	// Replace placeholders like %{uid} or %{USERID}
	if strings.Contains(cachePath, "%{uid}") {
		cachePath = strings.ReplaceAll(cachePath, "%{uid}", strconv.Itoa(os.Getuid()))
	}
	if strings.Contains(cachePath, "%{USERID}") {
		cachePath = strings.ReplaceAll(cachePath, "%{USERID}", strconv.Itoa(os.Getuid()))
	}

	// Ensure the path starts with a type prefix (e.g., FILE:) if not already present.
	if !strings.HasPrefix(cachePath, "FILE:") && !strings.HasPrefix(cachePath, "DIR:") && !strings.HasPrefix(cachePath, "API:") && !strings.HasPrefix(cachePath, "KEYRING:") && !strings.HasPrefix(cachePath, "KCM:") {
		cachePath = "FILE:" + cachePath
	}

	slog.Debug("Effective ccache name determined", "source", source, "path", cachePath)
	return cachePath
}

// loadMinimalKrb5Config tries to load the system /etc/krb5.conf.
// If that fails or doesn't exist, it constructs a minimal config string
// based on the application config (or guesses the realm).
func loadMinimalKrb5Config(cfg *appconfig.KerberosConfig) (*krb5config.Config, error) {
	// Try loading the system default krb5.conf first
	c, err := krb5config.Load("") // Passing "" loads default paths like /etc/krb5.conf
	if err == nil && c != nil {
		slog.Info("Loaded system Kerberos configuration for client context")
		// If a realm is specified in our app config, ensure it overrides the system default
		if cfg.Realm != "" && c.LibDefaults.DefaultRealm != cfg.Realm {
			slog.Debug("Overriding default_realm from system config", "system", c.LibDefaults.DefaultRealm, "app", cfg.Realm)
			c.LibDefaults.DefaultRealm = cfg.Realm
		}
		return c, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		// Log if there was an error other than file not found
		slog.Warn("Error loading system krb5.conf", "error", err)
	}

	// If system config failed or didn't exist, create a minimal one
	slog.Info("No system krb5.conf found or load failed, creating minimal config for client.")
	confStr := "[libdefaults]\n"
	realmSet := false
	if cfg.Realm != "" {
		confStr += fmt.Sprintf("  default_realm = %s\n", cfg.Realm)
		realmSet = true
	} else {
		// Try to guess realm from the current username (e.g., user@REALM.COM)
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

	// Add basic defaults for KDC lookup via DNS
	confStr += "  dns_lookup_kdc = true\n"
	confStr += "  dns_lookup_realm = false\n" // Usually false, realm is known
	confStr += "  rdns = false\n"             // Avoid reverse DNS lookups

	slog.Debug("Using minimal generated krb5 config string", "config", confStr)
	newConf, configErr := krb5config.NewFromString(confStr)
	if configErr != nil {
		return nil, fmt.Errorf("failed to parse minimal config string: %w", configErr)
	}
	return newConf, nil
}

// initializeFromCCache attempts to load credentials from the specified ccache path
// and create a gokrb5 client instance. It updates the client's state.
func (k *KerberosClient) initializeFromCCache(effectiveCacheName string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// If a client already exists, destroy it first
	if k.client != nil {
		k.client.Destroy()
		k.client = nil
		k.isInitialized = false
		k.ticketExpiry = time.Time{}
	}

	slog.Info("Attempting Kerberos init using credential cache", "name", effectiveCacheName)

	// Load the credential cache file/resource
	cc, err := credentials.LoadCCache(effectiveCacheName)
	if err != nil {
		k.isInitialized = false // Ensure flag is false on failure
		slog.Error("Failed to load user ccache", "name", effectiveCacheName, "error", err)
		return fmt.Errorf("failed load user ccache '%s': %w", effectiveCacheName, err)
	}

	// Create client FROM the loaded ccache. The client itself will select the appropriate TGT.
	// Set DisablePAFXFAST to potentially improve compatibility with some KDCs.
	// Pass k.krb5Config to provide context like default realm if needed.
	cl, err := gokrb5client.NewFromCCache(cc, k.krb5Config, gokrb5client.DisablePAFXFAST(true))
	if err != nil {
		k.isInitialized = false // Ensure flag is false on failure
		slog.Error("Failed to create client from ccache", "error", err)
		return fmt.Errorf("failed create client from ccache: %w", err)
	}

	// Validate the TGT within the client's credentials
	if cl.Credentials == nil {
		k.isInitialized = false // Ensure flag is false if TGT is bad
		cl.Destroy()            // Clean up the partially created client
		errMsg := "no valid credentials found in loaded ccache"
		slog.Error(errMsg)
		return errors.New(errMsg)
	}

	// Success! Store the client and update state.
	k.client = cl
	k.isInitialized = true

	// Attempt to get the expiry time from the TGT
	// Construct the TGT SPN
	tgtSPN := fmt.Sprintf("krbtgt/%s@%s", cl.Credentials.Domain(), cl.Credentials.Domain())
	// Call GetCachedTicket with the SPN string
	var tgt types.Ticket
	var ok bool
	tgt, ok, err = k.client.GetCachedTicket(tgtSPN) // Corrected call

	if err == nil && ok && tgt.EndTime.After(time.Now()) {
		k.ticketExpiry = tgt.EndTime
		slog.Info("Kerberos context initialized from ccache", "principal", strings.Join(k.client.Credentials.CName().NameString, "/"), "realm", k.client.Credentials.Realm(), "tgt_expiry", k.ticketExpiry.Format(time.RFC3339))
	} else {
		// If unable to get TGT expiry, set a reasonable default (e.g., 8 hours from now) - actual refresh will happen by external tools
		k.ticketExpiry = time.Now().Add(8 * time.Hour)
		logReason := ""
		if err != nil {
			logReason = fmt.Sprintf("error: %v", err)
		} else if !ok {
			logReason = "ticket not found in cache"
		} else if !tgt.EndTime.After(time.Now()) {
			logReason = "cached ticket already expired"
		}
		slog.Warn("Could not determine exact TGT expiry from ccache, using default duration", "principal", strings.Join(k.client.Credentials.CName().NameString, "/"), "realm", k.client.Credentials.Realm(), "assumed_expiry", k.ticketExpiry.Format(time.RFC3339), "reason", logReason)
	}

	return nil
}

// Gokrb5Client returns the underlying gokrb5 client instance.
// This is needed for operations like generating SPNEGO tokens directly.
func (k *KerberosClient) Gokrb5Client() *gokrb5client.Client {
	k.mu.Lock() // Lock needed if client can be mutated concurrently
	defer k.mu.Unlock()
	return k.client
}

// CreateProxyTransport creates an http.RoundTripper that wraps the provided base transport
// and automatically handles SPNEGO authentication using the initialized Kerberos client.
// DEPRECATED: The logic was moved to establishConnectTunnel in the client. This function is no longer used there.
// It's kept here for potential future use or reference.
func (k *KerberosClient) CreateProxyTransport(baseTransport *http.Transport) (http.RoundTripper, error) {
	slog.Warn("KerberosClient.CreateProxyTransport is deprecated and likely unused.")
	// Check if the current ticket is valid before creating the transport
	if err := k.CheckAndRefreshClient(); err != nil {
		slog.Warn("Kerberos ticket potentially invalid before creating SPNEGO transport", "error", err)
		// Don't necessarily fail here, let SPNEGO attempt auth, but log the warning.
	}

	k.mu.Lock()
	gokrbCl := k.client // Get client under lock
	isInit := k.isInitialized
	k.mu.Unlock()

	if !isInit || gokrbCl == nil {
		return nil, errors.New("kerberos client not initialized or ticket invalid, cannot create SPNEGO transport")
	}

	// Create a custom roundtripper that wraps the base transport and adds SPNEGO authentication headers
	spnegoTransport := &spnegoRoundTripper{
		base:   baseTransport,
		client: gokrbCl, // Pass the fetched client
	}
	slog.Info("Created SPNEGO HTTP transport wrapper using user credentials")

	return spnegoTransport, nil
}

// spnegoRoundTripper is a custom http.RoundTripper that adds SPNEGO authentication headers
// DEPRECATED: See CreateProxyTransport deprecation notice.
type spnegoRoundTripper struct {
	base   *http.Transport
	client *gokrb5client.Client // Use aliased type
}

// RoundTrip implements the http.RoundTripper interface
// DEPRECATED: See CreateProxyTransport deprecation notice.
func (s *spnegoRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqCopy := req.Clone(req.Context())

	// Add SPNEGO authorization header
	err := spnego.SetSPNEGOHeader(s.client, reqCopy, "")
	if err != nil {
		return nil, fmt.Errorf("failed to set SPNEGO header: %w", err)
	}

	// Use the base transport to perform the actual request
	resp, err := s.base.RoundTrip(reqCopy)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// CheckAndRefreshClient checks if the Kerberos TGT is valid and close to expiry.
// If needed, it attempts to re-initialize the client by reloading the credential cache.
func (k *KerberosClient) CheckAndRefreshClient() error {
	k.mu.Lock()
	isInit := k.isInitialized
	expiry := k.ticketExpiry
	ccName := determineEffectiveCacheName(k.config.CachePath) // Get current effective ccache path
	k.mu.Unlock()

	// Determine if a refresh is needed: not initialized, expired, or expiring within 5 minutes
	needsRefresh := !isInit || expiry.IsZero() || time.Now().Add(5*time.Minute).After(expiry)

	if needsRefresh {
		slog.Info("Kerberos ticket invalid or expiring soon, attempting refresh by reloading ccache...", "ccache", ccName)

		// Attempt to reload the ccache and re-initialize the client
		err := k.initializeFromCCache(ccName)
		if err != nil {
			// Log the error but don't necessarily prevent operation if a previous ticket existed
			slog.Error("Failed to refresh Kerberos client from ccache", "error", err)
			return fmt.Errorf("ccache reload failed: %w", err) // Return error as refresh failed
		}
		slog.Info("Kerberos client state refreshed from ccache.")
		return nil // Refresh successful
	}

	slog.Debug("Kerberos ticket check: OK (valid and not expiring soon)")
	return nil // Ticket is okay
}

// GetStatus returns the current status of the Kerberos client.
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
		"source":                "ccache", // This client always uses ccache
		"effective_ccache_path": ccName,
	}

	// If initialized and client/credentials exist, populate details
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
		}
	}
	return status
}

// Close destroys the Kerberos client session.
func (k *KerberosClient) Close() {
	slog.Info("Closing Kerberos client (user context)...")
	k.mu.Lock()
	defer k.mu.Unlock()

	// Destroy the underlying gokrb5 client session if it exists
	if k.client != nil {
		k.client.Destroy()
		k.client = nil
		slog.Debug("Kerberos client session destroyed.")
	}
	k.isInitialized = false // Mark as not initialized
	slog.Info("Kerberos client closed.")
}
