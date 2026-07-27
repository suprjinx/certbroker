// Package config loads and validates broker configuration from a YAML file.
// Secrets are never stored in that file: they are referenced by the path of a
// mounted file or the name of an environment variable.
//
// The broker treats OpenBao as externally managed: it never creates or
// modifies PKI roles. It assumes the configured mount is an intermediate
// authorized to issue leaf certificates, and references role names as
// opaque strings supplied here.
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

// Server configures the in-app TLS/mTLS listener. TLS is terminated here even
// when behind an L4 passthrough proxy, so client certs reach the app.
type Server struct {
	ListenAddr   string   `yaml:"listen_addr"`   // e.g. ":8443"
	TLSCertFile  string   `yaml:"tls_cert_file"` // server leaf cert (PEM)
	TLSKeyFile   string   `yaml:"tls_key_file"`  // server key (PEM)
	ReadTimeout  Duration `yaml:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout"`
	// ReadHeaderTimeout bounds the TLS handshake plus request headers. This is
	// the Slowloris guard: without it a connection can hold a slot open by
	// dribbling header bytes forever.
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	// IdleTimeout closes kept-alive connections that go quiet, so idle peers
	// cannot accumulate and exhaust file descriptors.
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

// Limits configures the denial-of-service controls in front of the enrollment
// handlers. Enrollment verifies attacker-supplied signatures before any
// authorization is possible, so this bounds unauthenticated work.
//
// A negative rate or burst disables that limiter; zero takes the default.
type Limits struct {
	// PerClientRate/Burst bound one source IP (requests/second, bucket depth).
	PerClientRate  float64 `yaml:"per_client_rate"`
	PerClientBurst float64 `yaml:"per_client_burst"`
	// GlobalRate/Burst bound the listener as a whole, catching distributed
	// floods that stay under the per-client limit.
	GlobalRate  float64 `yaml:"global_rate"`
	GlobalBurst float64 `yaml:"global_burst"`
	// MaxConcurrent bounds requests inside the handler simultaneously.
	MaxConcurrent int `yaml:"max_concurrent"`
	// AcquireTimeout is how long a request waits for a concurrency slot before
	// being shed with 503.
	AcquireTimeout Duration `yaml:"acquire_timeout"`
	// MaxTrackedClients bounds the per-client bucket table so that tracking
	// cannot itself be turned into memory exhaustion.
	MaxTrackedClients int `yaml:"max_tracked_clients"`
	// UpstreamTimeout bounds a single OpenBao call made while serving a request.
	UpstreamTimeout Duration `yaml:"upstream_timeout"`
}

// OpenBao configures the upstream OpenBao/Vault connection. The broker
// authenticates via AppRole; the SecretID is referenced, never inlined here.
type OpenBao struct {
	Address    string `yaml:"address"`      // https://openbao.internal:8200
	Mount      string `yaml:"mount"`        // PKI mount path, e.g. "pki_int"
	CACertFile string `yaml:"ca_cert_file"` // PEM trust anchor for the OpenBao API TLS (optional)
	MaxRetries int    `yaml:"max_retries"`

	AppRole AppRole `yaml:"approle"`
}

// AppRole holds AppRole auth material. The SecretID is never written in the
// config file itself; it comes from a file or an environment variable.
type AppRole struct {
	MountPath string `yaml:"mount_path"` // auth mount, default "approle"
	RoleID    string `yaml:"role_id"`
	// SecretIDFile reads the SecretID from a file. Preferred over the env var:
	// a mounted secret can be rotated in place and does not appear in /proc,
	// process listings, or crash dumps. Takes precedence when both are set.
	SecretIDFile string `yaml:"secret_id_file"`
	// SecretIDEnv names the env var holding the SecretID.
	SecretIDEnv    string   `yaml:"secret_id_env"`
	RenewThreshold Duration `yaml:"renew_threshold"`
}

// Trust holds the trust anchors used to authenticate enrolling clients.
// Bootstrap and device anchors are kept distinct: first enrollment is gated by
// the bootstrap CA, re-enrollment by the CA that signed already-issued devices.
type Trust struct {
	BootstrapCAFile string `yaml:"bootstrap_ca_file"` // PEM bundle: accepted for /simpleenroll
	DeviceCAFile    string `yaml:"device_ca_file"`    // PEM bundle: accepted for /simplereenroll
}

// RoleMap maps an authenticated device identity to an externally-defined
// OpenBao PKI role name. Role names are opaque to the broker.
type RoleMap struct {
	// Default role used when no rule matches (empty = deny).
	Default string `yaml:"default"`
	// Rules are evaluated in order; first match wins. Match keys are
	// identity attributes (e.g. cert OU, SAN domain suffix) resolved by the
	// authz layer.
	Rules []RoleRule `yaml:"rules"`
}

// RoleRule maps a match expression to an OpenBao role name.
type RoleRule struct {
	Match string `yaml:"match"` // opaque selector, interpreted by policy engine
	Role  string `yaml:"role"`  // external OpenBao PKI role name
}

// Policy holds CSR constraint policy: what an authenticated identity is
// permitted to request. Enforced before calling OpenBao (defense in depth
// alongside the OpenBao role's own constraints).
type Policy struct {
	AllowedKeyTypes []string `yaml:"allowed_key_types"` // e.g. ["rsa-2048","ec-p256"]
	MaxValidity     Duration `yaml:"max_validity"`
	RequireCPP      bool     `yaml:"require_challenge_password"`
	// MinRSABits/MaxRSABits bound CSR RSA moduli. The ceiling also caps the cost
	// of the proof-of-possession check, which runs before authorization.
	MinRSABits int `yaml:"min_rsa_bits"`
	MaxRSABits int `yaml:"max_rsa_bits"`
	// SANConstraint controls whether requested SANs must be derivable from the
	// authenticated identity ("identity") or matched against allowlists ("allowlist").
	SANConstraint string `yaml:"san_constraint"`
}

// Inventory configures the pluggable device-authorization backend. Backend is
// chosen later; "file" is the reference implementation.
type Inventory struct {
	Backend string `yaml:"backend"` // "file" | "rest" | "db" | "none"
	// File-backend options.
	Path string `yaml:"path"`
}

// Challenge configures challenge-password (challengePassword) validation.
type Challenge struct {
	Backend string `yaml:"backend"` // "none" | "static"
	// StaticSecretEnv names the env var holding the shared secret for the
	// "static" backend.
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

// UnmarshalYAML implements yaml.Unmarshaler.
//
// A bare scalar decodes into a string even when it is an integer node, so the
// integer-seconds form has to be tried after ParseDuration fails rather than
// after the string decode fails — otherwise "30" would be a hard error.
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

// Load reads, parses, and validates config from path. YAML values are merged
// onto the built-in defaults, so a sparse file only needs to set what differs.
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
			AllowedKeyTypes: []string{"rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"},
			MaxValidity:     Duration(90 * 24 * time.Hour),
			RequireCPP:      false,
			SANConstraint:   "identity",
			MinRSABits:      2048,
			MaxRSABits:      8192,
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
		// Presence is checked at startup rather than here so a not-yet-mounted
		// secret produces one clear error from ResolveSecretID.
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
	if c.Policy.MinRSABits > 0 && c.Policy.MaxRSABits > 0 && c.Policy.MinRSABits > c.Policy.MaxRSABits {
		return fmt.Errorf("policy.min_rsa_bits (%d) exceeds policy.max_rsa_bits (%d)",
			c.Policy.MinRSABits, c.Policy.MaxRSABits)
	}
	// In the limits package 0 means "use the built-in default" and a negative
	// means "disable". An explicit 0 in the file therefore reads as "unlimited"
	// but silently applies the default; reject it rather than surprise the
	// operator in either direction.
	if c.Limits.PerClientRate == 0 {
		return fmt.Errorf("limits.per_client_rate: 0 is ambiguous; omit the key for the default or set a negative value to disable")
	}
	if c.Limits.GlobalRate == 0 {
		return fmt.Errorf("limits.global_rate: 0 is ambiguous; omit the key for the default or set a negative value to disable")
	}
	return nil
}

// ResolveSecretID reads the AppRole SecretID from its configured source, with
// the file taking precedence over the environment variable.
func (c *Config) ResolveSecretID() (string, error) {
	if path := c.OpenBao.AppRole.SecretIDFile; path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read secret id file: %w", err)
		}
		// Trailing newlines are near-universal in mounted secrets and shell
		// redirection; a stray one would fail the login with an opaque 400.
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

// OpenBaoCACert reads the OpenBao API CA bundle, or returns nil when none is
// configured (system roots are then used).
func (c *Config) OpenBaoCACert() ([]byte, error) {
	if c.OpenBao.CACertFile == "" {
		return nil, nil
	}
	return os.ReadFile(c.OpenBao.CACertFile)
}

// TrustPools loads the bootstrap and device trust anchors. Either may be nil if
// its file is unconfigured; the handler rejects operations that need a missing
// anchor.
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
