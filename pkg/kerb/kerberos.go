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
	} else {
		slog.Info("Kerberos client successfully initialized from ccache.")
	}

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
		cachePath = fmt.Sprintf("FILE:/tmp/krb5cc_%s", uidStr)
		source = "default pattern"
	}

	if strings.Contains(cachePath, "%{uid}") {
		cachePath = strings.ReplaceAll(cachePath, "%{uid}", strconv.Itoa(os.Getuid()))
	}
	if strings.Contains(cachePath, "%{USERID}") {
		cachePath = strings.ReplaceAll(cachePath, "%{USERID}", strconv.Itoa(os.Getuid()))
	}

	if !strings.HasPrefix(cachePath, "FILE:") && !strings.HasPrefix(cachePath, "DIR:") && !strings.HasPrefix(cachePath, "API:") && !strings.HasPrefix(cachePath, "KEYRING:") && !strings.HasPrefix(cachePath, "KCM:") {
		cachePath = "FILE:" + cachePath
	}

	slog.Debug("Effective ccache name determined", "source", source, "path", cachePath)
	return cachePath
}

func loadMinimalKrb5Config(cfg *appconfig.KerberosConfig) (*krb5config.Config, error) {
	c, err := krb5config.Load("")
	if err == nil && c != nil {
		slog.Info("Loaded system Kerberos configuration for client context")
		if cfg.Realm != "" && c.LibDefaults.DefaultRealm != cfg.Realm {
			slog.Debug("Overriding default_realm from system config", "system", c.LibDefaults.DefaultRealm, "app", cfg.Realm)
			c.LibDefaults.DefaultRealm = cfg.Realm
		}
		return c, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("Error loading system krb5.conf", "error", err)
	}

	slog.Info("No system krb5.conf found or load failed, creating minimal config for client.")
	confStr := "[libdefaults]\n"
	realmSet := false
	if cfg.Realm != "" {
		confStr += fmt.Sprintf("  default_realm = %s\n", cfg.Realm)
		realmSet = true
	} else {
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
	confStr += "  dns_lookup_realm = false\n"
	confStr += "  rdns = false\n"

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

	if k.client != nil {
		k.client.Destroy()
		k.client = nil
		k.isInitialized = false
		k.ticketExpiry = time.Time{}
	}

	slog.Info("Attempting Kerberos init using credential cache", "name", effectiveCacheName)

	cc, err := credentials.LoadCCache(effectiveCacheName)
	if err != nil {
		k.isInitialized = false
		slog.Error("Failed to load user ccache", "name", effectiveCacheName, "error", err)
		return fmt.Errorf("failed load user ccache '%s': %w", effectiveCacheName, err)
	}

	cl, err := gokrb5client.NewFromCCache(cc, k.krb5Config, gokrb5client.DisablePAFXFAST(true))
	if err != nil {
		k.isInitialized = false
		slog.Error("Failed to create client from ccache", "error", err)
		return fmt.Errorf("failed create client from ccache: %w", err)
	}

	if cl.Credentials == nil {
		k.isInitialized = false
		cl.Destroy()
		errMsg := "no valid credentials found in loaded ccache"
		slog.Error(errMsg)
		return errors.New(errMsg)
	}

	k.client = cl
	k.isInitialized = true

	// Cannot reliably get TGT expiry from client object after loading from ccache.
	// Set a reasonable default or use a heuristic. Rely on CheckAndRefreshClient.
	k.ticketExpiry = time.Now().Add(8 * time.Hour) // Default 8 hours estimate
	slog.Info("Kerberos context initialized from ccache",
		"principal", strings.Join(k.client.Credentials.CName().NameString, "/"),
		"realm", k.client.Credentials.Realm(),
		"estimated_expiry", k.ticketExpiry.Format(time.RFC3339))

	return nil
}

func (k *KerberosClient) Gokrb5Client() *gokrb5client.Client {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.client
}

// CreateProxyTransport is deprecated
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

// spnegoRoundTripper is deprecated
type spnegoRoundTripper struct {
	base   *http.Transport
	client *gokrb5client.Client
}

// RoundTrip is deprecated
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
	ccName := determineEffectiveCacheName(k.config.CachePath)
	k.mu.Unlock()

	needsRefresh := !isInit || expiry.IsZero() || time.Now().Add(5*time.Minute).After(expiry)

	if needsRefresh {
		slog.Info("Kerberos ticket check: attempting refresh by reloading ccache...", "ccache", ccName, "reason_needs_init", !isInit, "reason_expiry_near", !expiry.IsZero() && time.Now().Add(5*time.Minute).After(expiry))

		err := k.initializeFromCCache(ccName)
		if err != nil {
			slog.Error("Failed to refresh Kerberos client from ccache", "error", err)
			return fmt.Errorf("ccache reload failed: %w", err)
		}
		slog.Info("Kerberos client state refreshed from ccache.")
		return nil
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
		"tgt_expiry":            "N/A (estimated)",
		"tgt_time_left":         "N/A (estimated)",
		"source":                "ccache",
		"effective_ccache_path": ccName,
	}

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
	slog.Info("Kerberos client closed.")
}
