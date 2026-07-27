package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalConfig is the smallest file that passes Validate. Tests append or
// override sections onto it.
const minimalConfig = `
server:
  tls_cert_file: /tmp/cert.pem
  tls_key_file: /tmp/key.pem
openbao:
  address: https://openbao.internal:8200
  approle:
    role_id: test-role-id
trust:
  bootstrap_ca_file: /tmp/bootstrap-ca.pem
role_map:
  default: device-role
`

// writeConfig writes body to a temp file and sets the AppRole SecretID env var
// that Validate requires.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	t.Setenv("OPENBAO_APPROLE_SECRET_ID", "test-secret-id")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.ListenAddr != ":8443" {
		t.Errorf("listen_addr = %q, want :8443", cfg.Server.ListenAddr)
	}
	if got := cfg.Server.ReadHeaderTimeout.Std(); got != 10*time.Second {
		t.Errorf("read_header_timeout = %v, want 10s", got)
	}
	if got := cfg.Server.IdleTimeout.Std(); got != 60*time.Second {
		t.Errorf("idle_timeout = %v, want 60s", got)
	}
	if cfg.Server.MaxHeaderBytes != 16*1024 {
		t.Errorf("max_header_bytes = %d, want 16384", cfg.Server.MaxHeaderBytes)
	}
	if cfg.Limits.PerClientRate != 1 || cfg.Limits.PerClientBurst != 5 {
		t.Errorf("per-client limits = %v/%v, want 1/5", cfg.Limits.PerClientRate, cfg.Limits.PerClientBurst)
	}
	if cfg.Limits.MaxConcurrent != 32 {
		t.Errorf("max_concurrent = %d, want 32", cfg.Limits.MaxConcurrent)
	}
	if cfg.Policy.MinRSABits != 2048 || cfg.Policy.MaxRSABits != 8192 {
		t.Errorf("RSA bounds = %d/%d, want 2048/8192", cfg.Policy.MinRSABits, cfg.Policy.MaxRSABits)
	}
	if got := cfg.Limits.UpstreamTimeout.Std(); got != 20*time.Second {
		t.Errorf("upstream_timeout = %v, want 20s", got)
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig+`
limits:
  per_client_rate: 10
  per_client_burst: 20
  max_concurrent: 8
  acquire_timeout: 2s
  upstream_timeout: 45s
policy:
  max_rsa_bits: 4096
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Limits.PerClientRate != 10 || cfg.Limits.PerClientBurst != 20 {
		t.Errorf("per-client limits = %v/%v", cfg.Limits.PerClientRate, cfg.Limits.PerClientBurst)
	}
	if cfg.Limits.MaxConcurrent != 8 {
		t.Errorf("max_concurrent = %d", cfg.Limits.MaxConcurrent)
	}
	if got := cfg.Limits.AcquireTimeout.Std(); got != 2*time.Second {
		t.Errorf("acquire_timeout = %v", got)
	}
	if cfg.Policy.MaxRSABits != 4096 {
		t.Errorf("max_rsa_bits = %d", cfg.Policy.MaxRSABits)
	}
	// Unset keys in an overridden section keep their defaults.
	if cfg.Policy.MinRSABits != 2048 {
		t.Errorf("min_rsa_bits = %d, want the default 2048", cfg.Policy.MinRSABits)
	}
	if cfg.Limits.GlobalRate != 50 {
		t.Errorf("global_rate = %v, want the default 50", cfg.Limits.GlobalRate)
	}
}

func TestNegativeRateDisablesLimiter(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig+`
limits:
  per_client_rate: -1
  per_client_burst: -1
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Limits.PerClientRate != -1 {
		t.Errorf("per_client_rate = %v, want -1", cfg.Limits.PerClientRate)
	}
}

func TestValidationRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown key",
			body: minimalConfig + "\nlimits:\n  per_clietn_rate: 5\n",
			want: "field per_clietn_rate not found",
		},
		{
			name: "rsa bounds inverted",
			body: minimalConfig + "\npolicy:\n  min_rsa_bits: 8192\n  max_rsa_bits: 2048\n",
			want: "exceeds policy.max_rsa_bits",
		},
		{
			name: "ambiguous zero per-client rate",
			body: minimalConfig + "\nlimits:\n  per_client_rate: 0\n",
			want: "limits.per_client_rate: 0 is ambiguous",
		},
		{
			name: "ambiguous zero global rate",
			body: minimalConfig + "\nlimits:\n  global_rate: 0\n",
			want: "limits.global_rate: 0 is ambiguous",
		},
		{
			name: "no role mapping",
			body: strings.Replace(minimalConfig, "role_map:\n  default: device-role\n", "", 1),
			want: "role_map must define",
		},
		{
			name: "no trust anchor",
			body: strings.Replace(minimalConfig, "trust:\n  bootstrap_ca_file: /tmp/bootstrap-ca.pem\n", "", 1),
			want: "trust.bootstrap_ca_file",
		},
		{
			name: "bad duration",
			body: minimalConfig + "\nlimits:\n  acquire_timeout: not-a-duration\n",
			want: "invalid duration",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestMissingSecretIDEnvIsRejected(t *testing.T) {
	path := writeConfig(t, minimalConfig)
	os.Unsetenv("OPENBAO_APPROLE_SECRET_ID")

	if _, err := Load(path); err == nil {
		t.Fatal("expected a missing-secret-id error")
	} else if !strings.Contains(err.Error(), "is not set") {
		t.Fatalf("error = %v", err)
	}
}

func TestDurationAcceptsBareSeconds(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig+"\nlimits:\n  acquire_timeout: 30\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Limits.AcquireTimeout.Std(); got != 30*time.Second {
		t.Errorf("acquire_timeout = %v, want 30s", got)
	}
}
