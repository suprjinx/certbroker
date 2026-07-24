package authz

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func certFor(cn string, dns []string) *x509.Certificate {
	return &x509.Certificate{
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		SerialNumber: big.NewInt(0x1234),
		Raw:          []byte("raw:" + cn),
	}
}

func certWithOU(cn string, ou []string) *x509.Certificate {
	return &x509.Certificate{
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: ou},
		SerialNumber: big.NewInt(0x99),
		Raw:          []byte("raw:" + cn),
	}
}

func csrFor(cn string, dns []string) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dns,
	}
}

func basePipeline(inv Inventory, ch ChallengeValidator, requireCh bool, mode string) *Pipeline {
	return &Pipeline{
		Inventory:        inv,
		Challenge:        ch,
		Roles:            NewRuleSelector(nil, "default-role"),
		Constraints:      NewStandardConstraints(mode, time.Hour),
		RequireChallenge: requireCh,
	}
}

func mustAllow(t *testing.T, p *Pipeline, req Request) Decision {
	t.Helper()
	d, err := p.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allow {
		t.Fatalf("expected Allow, got deny: %q", d.Reason)
	}
	return d
}

func mustDeny(t *testing.T, p *Pipeline, req Request) {
	t.Helper()
	d, err := p.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allow {
		t.Fatalf("expected Deny, got allow (role=%q)", d.Role)
	}
}

func TestNoInventoryCSRMode(t *testing.T) {
	p := basePipeline(NoInventory{}, nil, false, SANModeCSR)
	d := mustAllow(t, p, Request{
		Operation: OpSimpleEnroll,
		CSR:       csrFor("device01.example.com", []string{"device01.example.com"}),
	})
	if d.Role != "default-role" {
		t.Errorf("role = %q", d.Role)
	}
	if d.Constraints.CommonName != "device01.example.com" {
		t.Errorf("CN = %q", d.Constraints.CommonName)
	}
	if d.Constraints.TTL != time.Hour {
		t.Errorf("TTL = %v", d.Constraints.TTL)
	}
}

func TestReenrollRequiresClientCert(t *testing.T) {
	p := basePipeline(NoInventory{}, nil, false, SANModeIdentity)
	mustDeny(t, p, Request{
		Operation: OpSimpleReenroll,
		CSR:       csrFor("device01.example.com", nil),
	})
}

func TestIdentityContinuity(t *testing.T) {
	p := basePipeline(NoInventory{}, nil, false, SANModeIdentity)
	cert := certFor("device01.example.com", []string{"device01.example.com"})

	// Re-key with the same identity: allowed.
	d := mustAllow(t, p, Request{
		Operation:  OpSimpleReenroll,
		ClientCert: cert,
		CSR:        csrFor("device01.example.com", []string{"device01.example.com"}),
	})
	if d.Constraints.CommonName != "device01.example.com" {
		t.Errorf("CN = %q", d.Constraints.CommonName)
	}

	// Attempt to broaden identity to a new SAN: denied.
	mustDeny(t, p, Request{
		Operation:  OpSimpleReenroll,
		ClientCert: cert,
		CSR:        csrFor("device01.example.com", []string{"evil.example.com"}),
	})
}

func writeInventory(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileInventoryDenyAndAllow(t *testing.T) {
	inv, err := NewFileInventory(writeInventory(t, `
devices:
  - cn: "device01.example.com"
    allowed_dns: ["device01.example.com"]
    role: "sensor-role"
`))
	if err != nil {
		t.Fatal(err)
	}
	p := basePipeline(inv, nil, false, SANModeAllowlist)

	// Unknown device -> deny.
	mustDeny(t, p, Request{
		Operation: OpSimpleEnroll,
		CSR:       csrFor("device99.example.com", nil),
	})

	// Known device -> allow, with the record's role override.
	d := mustAllow(t, p, Request{
		Operation: OpSimpleEnroll,
		CSR:       csrFor("device01.example.com", []string{"device01.example.com"}),
	})
	if d.Role != "sensor-role" {
		t.Errorf("role = %q, want sensor-role (record override)", d.Role)
	}
}

func TestAllowlistExceedDenied(t *testing.T) {
	inv, err := NewFileInventory(writeInventory(t, `
devices:
  - cn: "*.iot.example.com"
    allowed_dns: ["*.iot.example.com"]
`))
	if err != nil {
		t.Fatal(err)
	}
	p := basePipeline(inv, nil, false, SANModeAllowlist)

	// Within the allowlist.
	mustAllow(t, p, Request{
		Operation: OpSimpleEnroll,
		CSR:       csrFor("sensor7.iot.example.com", []string{"sensor7.iot.example.com"}),
	})

	// Requests a name outside the allowlist.
	mustDeny(t, p, Request{
		Operation: OpSimpleEnroll,
		CSR:       csrFor("sensor7.iot.example.com", []string{"sensor7.corp.example.com"}),
	})
}

func TestChallengeRequiredMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	store.Add("device01.example.com", "one-time-pw", time.Minute)

	p := basePipeline(NoInventory{}, store, true, SANModeCSR)
	req := Request{
		Operation:         OpSimpleEnroll,
		CSR:               csrFor("device01.example.com", nil),
		ChallengePassword: "one-time-pw",
	}

	// First use succeeds.
	mustAllow(t, p, req)
	// Second use fails (consumed).
	mustDeny(t, p, req)

	// Wrong code fails.
	store.Add("device01.example.com", "correct", time.Minute)
	bad := req
	bad.ChallengePassword = "wrong"
	mustDeny(t, p, bad)
}

func TestChallengeRequiredNoValidator(t *testing.T) {
	p := basePipeline(NoInventory{}, nil, true, SANModeCSR)
	mustDeny(t, p, Request{
		Operation:         OpSimpleEnroll,
		CSR:               csrFor("device01.example.com", nil),
		ChallengePassword: "anything",
	})
}

func TestStaticSecret(t *testing.T) {
	ss, err := NewStaticSecret("fleet-secret")
	if err != nil {
		t.Fatal(err)
	}
	p := basePipeline(NoInventory{}, ss, true, SANModeCSR)

	mustAllow(t, p, Request{
		Operation:         OpSimpleEnroll,
		CSR:               csrFor("device01.example.com", nil),
		ChallengePassword: "fleet-secret",
	})
	mustDeny(t, p, Request{
		Operation:         OpSimpleEnroll,
		CSR:               csrFor("device01.example.com", nil),
		ChallengePassword: "wrong",
	})
}

func TestWrongChallengeDeniedEvenWhenNotRequired(t *testing.T) {
	ss, _ := NewStaticSecret("fleet-secret")
	p := basePipeline(NoInventory{}, ss, false, SANModeCSR)
	// Not required, but a wrong secret was supplied -> hard fail.
	mustDeny(t, p, Request{
		Operation:         OpSimpleEnroll,
		CSR:               csrFor("device01.example.com", nil),
		ChallengePassword: "wrong",
	})
}

func TestRoleRuleSelection(t *testing.T) {
	p := basePipeline(NoInventory{}, nil, false, SANModeCSR)
	p.Roles = NewRuleSelector([]Rule{
		{Match: "ou:sensors", Role: "sensor-role"},
		{Match: "cn:*.admin.example.com", Role: "admin-role"},
	}, "default-role")

	// OU rule matches.
	d := mustAllow(t, p, Request{
		Operation:  OpSimpleReenroll,
		ClientCert: certWithOU("device01", []string{"sensors"}),
		CSR:        csrFor("device01", nil),
	})
	if d.Role != "sensor-role" {
		t.Errorf("role = %q, want sensor-role", d.Role)
	}

	// No rule matches -> default.
	d2 := mustAllow(t, p, Request{
		Operation: OpSimpleEnroll,
		CSR:       csrFor("random.example.com", nil),
	})
	if d2.Role != "default-role" {
		t.Errorf("role = %q, want default-role", d2.Role)
	}
}

func TestNoRoleDenied(t *testing.T) {
	p := basePipeline(NoInventory{}, nil, false, SANModeCSR)
	p.Roles = NewRuleSelector(nil, "") // no default, no rules
	mustDeny(t, p, Request{
		Operation: OpSimpleEnroll,
		CSR:       csrFor("device01.example.com", nil),
	})
}
