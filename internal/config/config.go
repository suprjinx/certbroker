// Package config loads and validates YAML configuration. Secrets are referenced
// by path or env var name, never inlined; role names are opaque strings.
package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level broker configuration.
type Config struct {
	Server    Server    `yaml:"server"`
	OpenBao   OpenBao   `yaml:"openbao"`
	Trust     Trust     `yaml:"trust"`
	RoleMap   RoleMap   `yaml:"role_map"`
	Policy    Policy    `yaml:"policy"`
	Inventory Inventory `yaml:"inventory"`
	Challenge Challenge `yaml:"challenge"`
	Limits    Limits    `yaml:"limits"`
	Audit     Audit     `yaml:"audit"`
}

// Server configures the in-app TLS/mTLS listener; TLS terminates here so client
// certs survive the L4 passthrough.
type Server struct {
	ListenAddr   string   `yaml:"listen_addr"`   // e.g. ":8443"
	TLSCertFile  string   `yaml:"tls_cert_file"` // server leaf cert (PEM)
	TLSKeyFile   string   `yaml:"tls_key_file"`  // server key (PEM)
	ReadTimeout  Duration `yaml:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout"`
	// ReadHeaderTimeout bounds the handshake plus headers — the Slowloris guard.
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	// IdleTimeout reaps quiet keep-alives before they exhaust file descriptors.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// MaxRequestBytes bounds enrollment request bodies (0 = handler default).
	MaxRequestBytes int64 `yaml:"max_request_bytes"`
	// MaxHeaderBytes bounds request headers (0 = Go default, 1MB).
	MaxHeaderBytes int `yaml:"max_header_bytes"`
	// ShutdownTimeout bounds graceful shutdown before in-flight requests are cut.
	ShutdownTimeout Duration `yaml:"shutdown_timeout"`
	// HealthAddr serves health/metrics on a separate non-mTLS listener.
	HealthAddr string `yaml:"health_addr"` // e.g. ":9090"
}

// Limits bounds the unauthenticated work enrollment can force (signatures are
// verified before authorization). Negative disables a limiter; zero = default.
type Limits struct {
	// PerClientRate/Burst bound one source IP (requests/second, bucket depth).
	PerClientRate  float64 `yaml:"per_client_rate"`
	PerClientBurst float64 `yaml:"per_client_burst"`
	// GlobalRate/Burst catch distributed floods staying under the per-client cap.
	GlobalRate  float64 `yaml:"global_rate"`
	GlobalBurst float64 `yaml:"global_burst"`
	// MaxConcurrent bounds requests inside the handler simultaneously.
	MaxConcurrent int `yaml:"max_concurrent"`
	// AcquireTimeout is the wait for a concurrency slot before shedding with 503.
	AcquireTimeout Duration `yaml:"acquire_timeout"`
	// MaxTrackedClients stops the bucket table itself becoming a memory DoS.
	MaxTrackedClients int `yaml:"max_tracked_clients"`
	// UpstreamTimeout bounds a single OpenBao call made while serving a request.
	UpstreamTimeout Duration `yaml:"upstream_timeout"`
}

// OpenBao configures the upstream connection; auth is AppRole.
type OpenBao struct {
	Address    string `yaml:"address"`      // https://openbao.internal:8200
	Mount      string `yaml:"mount"`        // PKI mount path, e.g. "pki_int"
	CACertFile string `yaml:"ca_cert_file"` // PEM trust anchor for the OpenBao API TLS (optional)
	MaxRetries int    `yaml:"max_retries"`

	AppRole AppRole `yaml:"approle"`
}

// AppRole holds auth material; the SecretID comes from a file or env var.
type AppRole struct {
	MountPath string `yaml:"mount_path"` // auth mount, default "approle"
	RoleID    string `yaml:"role_id"`
	// SecretIDFile reads the SecretID from a file, preferred over the env var
	// (env leaks via /proc, ps, crash dumps). Wins when both are set.
	SecretIDFile string `yaml:"secret_id_file"`
	// SecretIDEnv names the env var holding the SecretID.
	SecretIDEnv    string   `yaml:"secret_id_env"`
	RenewThreshold Duration `yaml:"renew_threshold"`
}

// Trust holds the client trust anchors. Bootstrap and device stay distinct:
// a bootstrap credential must not double as a renewal credential.
type Trust struct {
	BootstrapCAFile string `yaml:"bootstrap_ca_file"` // PEM bundle: accepted for /simpleenroll
	DeviceCAFile    string `yaml:"device_ca_file"`    // PEM bundle: accepted for /simplereenroll
}

// RoleMap maps a device identity to an externally-defined OpenBao role name.
type RoleMap struct {
	// Default role used when no rule matches (empty = deny).
	Default string `yaml:"default"`
	// Rules are evaluated in order, first match wins; see authz.Rule for keys.
	Rules []RoleRule `yaml:"rules"`
}

// RoleRule maps a match expression to an OpenBao role name.
type RoleRule struct {
	Match string `yaml:"match"` // opaque selector, interpreted by policy engine
	Role  string `yaml:"role"`  // external OpenBao PKI role name
}

// Policy is what an authenticated identity may request, enforced before calling
// OpenBao and again by the role itself.
type Policy struct {
	AllowedKeyTypes []string `yaml:"allowed_key_types"` // e.g. ["rsa-2048","ec-p256"]
	MaxValidity     Duration `yaml:"max_validity"`
	RequireCPP      bool     `yaml:"require_challenge_password"`
	// MinRSABits/MaxRSABits bound CSR RSA moduli; the ceiling caps PoP cost.
	MinRSABits int `yaml:"min_rsa_bits"`
	MaxRSABits int `yaml:"max_rsa_bits"`
	// ServerKeyGenKeyType/Bits select the /serverkeygen key. OpenBao refuses
	// pki/issue on a key_type=any role without them, so they default to rsa/2048.
	ServerKeyGenKeyType string `yaml:"serverkeygen_key_type"`
	ServerKeyGenKeyBits int    `yaml:"serverkeygen_key_bits"`
	// SANConstraint: "identity", "allowlist", or "csr" (dev only).
	SANConstraint string `yaml:"san_constraint"`
}

// Inventory configures the device-authorization backend. To add one (REST, DB),
// implement authz.Inventory and give it a case in cmd/certbroker.buildInventory.
type Inventory struct {
	// Backend selects the implementation: "none" (default, permits every device)
	// or "file". Anything else is rejected at startup.
	Backend string `yaml:"backend"`
	// Path is the "file" backend's YAML allowlist; required for that backend.
	Path string `yaml:"path"`
}

// Challenge configures challenge-password (challengePassword) validation.
type Challenge struct {
	Backend string `yaml:"backend"` // "none" | "static"
	// StaticSecretEnv names the env var holding the "static" backend's secret.
	StaticSecretEnv string `yaml:"static_secret_env"`
}

// Audit configures the issuance decision audit log.
type Audit struct {
	Path string `yaml:"path"` // append-only audit sink; empty = stdout
}

// Duration is a time.Duration that unmarshals from a YAML duration string
// ("15s", "5m", "720h") or a bare integer number of seconds.
type Duration time.Duration

// Std returns the standard library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.Unmarshaler. An int node still decodes into a
// string, so integer-seconds is tried after ParseDuration fails, not before.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		if parsed, perr := time.ParseDuration(s); perr == nil {
			*d = Duration(parsed)
			return nil
		}
		var secs int64
		if ierr := value.Decode(&secs); ierr == nil {
			*d = Duration(time.Duration(secs) * time.Second)
			return nil
		}
		return fmt.Errorf("invalid duration %q: expected a duration string (e.g. \"15s\") or integer seconds", s)
	}

	var secs int64
	if err := value.Decode(&secs); err != nil {
		return fmt.Errorf("duration must be a string or integer seconds: %w", err)
	}
	*d = Duration(time.Duration(secs) * time.Second)
	return nil
}

// Load reads and validates config, merging YAML onto the built-in defaults so a
// sparse file need only set what differs.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := Default()
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // reject unknown keys — typo protection
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Default returns a config with safe defaults filled in.
func Default() *Config {
	return &Config{
		Server: Server{
			ListenAddr:        ":8443",
			ReadTimeout:       Duration(15 * time.Second),
			WriteTimeout:      Duration(30 * time.Second),
			ReadHeaderTimeout: Duration(10 * time.Second),
			IdleTimeout:       Duration(60 * time.Second),
			MaxHeaderBytes:    16 * 1024,
			ShutdownTimeout:   Duration(10 * time.Second),
			HealthAddr:        ":9090",
		},
		OpenBao: OpenBao{
			Mount:      "pki_int",
			MaxRetries: 3,
			AppRole: AppRole{
				MountPath:      "approle",
				SecretIDEnv:    "OPENBAO_APPROLE_SECRET_ID",
				RenewThreshold: Duration(5 * time.Minute),
			},
		},
		Policy: Policy{
			AllowedKeyTypes:     []string{"rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"},
			MaxValidity:         Duration(90 * 24 * time.Hour),
			RequireCPP:          false,
			SANConstraint:       "identity",
			MinRSABits:          2048,
			MaxRSABits:          8192,
			ServerKeyGenKeyType: "rsa",
			ServerKeyGenKeyBits: 2048,
		},
		Inventory: Inventory{Backend: "none"},
		Challenge: Challenge{Backend: "none"},
		Limits: Limits{
			PerClientRate:     1,
			PerClientBurst:    5,
			GlobalRate:        50,
			GlobalBurst:       100,
			MaxConcurrent:     32,
			AcquireTimeout:    Duration(5 * time.Second),
			MaxTrackedClients: 65536,
			UpstreamTimeout:   Duration(20 * time.Second),
		},
	}
}

// Validate checks that required fields are present and coherent.
func (c *Config) Validate() error {
	if c.OpenBao.Address == "" {
		return fmt.Errorf("openbao.address is required")
	}
	if c.OpenBao.Mount == "" {
		return fmt.Errorf("openbao.mount is required")
	}
	if c.OpenBao.AppRole.RoleID == "" {
		return fmt.Errorf("openbao.approle.role_id is required")
	}
	switch ar := c.OpenBao.AppRole; {
	case ar.SecretIDFile != "":
		// Presence is left to ResolveSecretID, for one clear error.
	case ar.SecretIDEnv == "":
		return fmt.Errorf("one of openbao.approle.secret_id_file or openbao.approle.secret_id_env is required")
	default:
		if _, ok := os.LookupEnv(ar.SecretIDEnv); !ok {
			return fmt.Errorf("secret id env %q is not set", ar.SecretIDEnv)
		}
	}
	if c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "" {
		return fmt.Errorf("server.tls_cert_file and server.tls_key_file are required")
	}
	if c.Trust.BootstrapCAFile == "" && c.Trust.DeviceCAFile == "" {
		return fmt.Errorf("at least one of trust.bootstrap_ca_file or trust.device_ca_file is required")
	}
	if c.RoleMap.Default == "" && len(c.RoleMap.Rules) == 0 {
		return fmt.Errorf("role_map must define a default role or at least one rule")
	}
	// A required challenge with no backend denies everything: fail at startup.
	if c.Policy.RequireCPP {
		switch c.Challenge.Backend {
		case "", "none":
			return fmt.Errorf("policy.require_challenge_password is set but challenge.backend is %q; "+
				"configure a challenge backend or the broker will deny every enrollment",
				c.Challenge.Backend)
		}
	}
	if c.Policy.MinRSABits > 0 && c.Policy.MaxRSABits > 0 && c.Policy.MinRSABits > c.Policy.MaxRSABits {
		return fmt.Errorf("policy.min_rsa_bits (%d) exceeds policy.max_rsa_bits (%d)",
			c.Policy.MinRSABits, c.Policy.MaxRSABits)
	}
	// 0 means "default" downstream, but reads as "unlimited" here — reject it
	// rather than silently surprise the operator either way.
	if c.Limits.PerClientRate == 0 {
		return fmt.Errorf("limits.per_client_rate: 0 is ambiguous; omit the key for the default or set a negative value to disable")
	}
	if c.Limits.GlobalRate == 0 {
		return fmt.Errorf("limits.global_rate: 0 is ambiguous; omit the key for the default or set a negative value to disable")
	}
	return nil
}

// ResolveSecretID reads the SecretID, file taking precedence over env.
func (c *Config) ResolveSecretID() (string, error) {
	if path := c.OpenBao.AppRole.SecretIDFile; path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read secret id file: %w", err)
		}
		// Mounted secrets almost always carry a trailing newline; it would 400.
		v := strings.TrimSpace(string(raw))
		if v == "" {
			return "", fmt.Errorf("secret id file %q is empty", path)
		}
		return v, nil
	}

	v, ok := os.LookupEnv(c.OpenBao.AppRole.SecretIDEnv)
	if !ok || v == "" {
		return "", fmt.Errorf("secret id env %q is empty", c.OpenBao.AppRole.SecretIDEnv)
	}
	return v, nil
}

// ServerTLSCertificate loads the server's TLS certificate and key.
func (c *Config) ServerTLSCertificate() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(c.Server.TLSCertFile, c.Server.TLSKeyFile)
}

// OpenBaoCACert reads the API CA bundle; nil means use the system roots.
func (c *Config) OpenBaoCACert() ([]byte, error) {
	if c.OpenBao.CACertFile == "" {
		return nil, nil
	}
	return os.ReadFile(c.OpenBao.CACertFile)
}

// TrustPools loads the trust anchors. Either may be nil if unconfigured; the
// handler rejects operations needing a missing anchor.
func (c *Config) TrustPools() (bootstrap, device *x509.CertPool, err error) {
	if c.Trust.BootstrapCAFile != "" {
		bootstrap, err = poolFromFile(c.Trust.BootstrapCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("bootstrap CA: %w", err)
		}
	}
	if c.Trust.DeviceCAFile != "" {
		device, err = poolFromFile(c.Trust.DeviceCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("device CA: %w", err)
		}
	}
	return bootstrap, device, nil
}

func poolFromFile(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}
