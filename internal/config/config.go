// Package config loads and validates broker configuration from a file
// (YAML) with environment-variable overrides for secrets.
//
// The broker treats OpenBao as externally managed: it never creates or
// modifies PKI roles. It assumes the configured mount is an intermediate
// authorized to issue leaf certificates, and references role names as
// opaque strings supplied here.
package config

import (
	"fmt"
	"os"
	"time"
)

// Config is the top-level broker configuration.
type Config struct {
	Server    Server    `yaml:"server"`
	OpenBao   OpenBao   `yaml:"openbao"`
	Trust     Trust     `yaml:"trust"`
	RoleMap   RoleMap   `yaml:"role_map"`
	Policy    Policy    `yaml:"policy"`
	Inventory Inventory `yaml:"inventory"`
	Audit     Audit     `yaml:"audit"`
}

// Server configures the in-app TLS/mTLS listener. TLS is terminated here even
// when behind an L4 passthrough proxy, so client certs reach the app.
type Server struct {
	ListenAddr   string        `yaml:"listen_addr"`   // e.g. ":8443"
	TLSCertFile  string        `yaml:"tls_cert_file"` // server leaf cert
	TLSKeyFile   string        `yaml:"tls_key_file"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	// HealthAddr serves health/metrics on a separate non-mTLS listener.
	HealthAddr string `yaml:"health_addr"` // e.g. ":9090"
}

// OpenBao configures the upstream OpenBao/Vault connection. The broker
// authenticates via AppRole; the SecretID is supplied via env, never the file.
type OpenBao struct {
	Address   string `yaml:"address"`     // https://openbao.internal:8200
	Mount     string `yaml:"mount"`       // PKI mount path, e.g. "pki_int"
	CACertPEM string `yaml:"ca_cert_pem"` // trust anchor for the OpenBao API TLS

	AppRole AppRole `yaml:"approle"`
}

// AppRole holds AppRole auth material. SecretID must come from the environment.
type AppRole struct {
	MountPath      string        `yaml:"mount_path"` // auth mount, default "approle"
	RoleID         string        `yaml:"role_id"`
	SecretIDEnv    string        `yaml:"secret_id_env"` // env var name holding the SecretID
	RenewThreshold time.Duration `yaml:"renew_threshold"`
}

// Trust holds the trust anchors used to authenticate enrolling clients.
// Bootstrap and device anchors are kept distinct: first enrollment is gated by
// the bootstrap CA, re-enrollment by the CA that signed already-issued devices.
type Trust struct {
	BootstrapCABundle string `yaml:"bootstrap_ca_bundle"` // PEM: accepted for /simpleenroll
	DeviceCABundle    string `yaml:"device_ca_bundle"`    // PEM: accepted for /simplereenroll
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
	AllowedKeyTypes []string      `yaml:"allowed_key_types"` // e.g. ["rsa-2048","ec-p256"]
	MaxValidity     time.Duration `yaml:"max_validity"`
	RequireCPP      bool          `yaml:"require_challenge_password"`
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

// Audit configures the issuance decision audit log.
type Audit struct {
	Path string `yaml:"path"` // append-only audit sink; empty = stdout
}

// Load reads and validates config from path, applying env overrides.
func Load(path string) (*Config, error) {
	// TODO(phase0): YAML unmarshal (add sigs.k8s.io/yaml or gopkg.in/yaml.v3).
	// Kept dependency-free for the initial compiling skeleton.
	_ = path
	c := Default()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Default returns a config with safe defaults filled in.
func Default() *Config {
	return &Config{
		Server: Server{
			ListenAddr:   ":8443",
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			HealthAddr:   ":9090",
		},
		OpenBao: OpenBao{
			Mount: "pki_int",
			AppRole: AppRole{
				MountPath:      "approle",
				SecretIDEnv:    "OPENBAO_APPROLE_SECRET_ID",
				RenewThreshold: 5 * time.Minute,
			},
		},
		Policy: Policy{
			AllowedKeyTypes: []string{"rsa-2048", "rsa-3072", "ec-p256", "ec-p384"},
			MaxValidity:     90 * 24 * time.Hour,
			RequireCPP:      false,
			SANConstraint:   "identity",
		},
		Inventory: Inventory{Backend: "none"},
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
	if env := c.OpenBao.AppRole.SecretIDEnv; env == "" {
		return fmt.Errorf("openbao.approle.secret_id_env is required")
	} else if _, ok := os.LookupEnv(env); !ok {
		return fmt.Errorf("secret id env %q is not set", env)
	}
	if c.Trust.BootstrapCABundle == "" && c.Trust.DeviceCABundle == "" {
		return fmt.Errorf("at least one of trust.bootstrap_ca_bundle or trust.device_ca_bundle is required")
	}
	if c.RoleMap.Default == "" && len(c.RoleMap.Rules) == 0 {
		return fmt.Errorf("role_map must define a default role or at least one rule")
	}
	return nil
}
