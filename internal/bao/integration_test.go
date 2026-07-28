//go:build integration

package bao_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gr-oss/certbroker/internal/bao"
	"github.com/gr-oss/certbroker/internal/baotest"
)

// Item 5a: exercise the OpenBao client against a real server, covering the
// paths httptest fakes cannot vouch for — actual AppRole login, actual PKI
// response shapes, and actual server-side rejection of out-of-policy requests.

func newClient(t *testing.T, srv *baotest.Server) *bao.Client {
	t.Helper()
	c, err := bao.New(bao.Config{
		Address:        srv.Addr,
		PKIMount:       srv.Mount,
		AppRoleMount:   "approle",
		RoleID:         srv.RoleID,
		SecretID:       srv.SecretID,
		RenewThreshold: 5 * time.Minute,
		MaxRetries:     2,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("bao.New: %v", err)
	}
	return c
}

func makeCSRPEM(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dns,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestIntegrationLogin(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
}

func TestIntegrationBadCredentialsFail(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c, err := bao.New(bao.Config{
		Address:      srv.Addr,
		PKIMount:     srv.Mount,
		AppRoleMount: "approle",
		RoleID:       srv.RoleID,
		SecretID:     "00000000-0000-0000-0000-000000000000",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(context.Background()); err == nil {
		t.Fatal("expected login with a bogus SecretID to fail")
	}
}

func TestIntegrationCAChain(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	chain, err := c.CAChain(context.Background())
	if err != nil {
		t.Fatalf("CAChain: %v", err)
	}
	blk, _ := pem.Decode(chain)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("chain is not a CERTIFICATE PEM: %q", string(chain))
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
}

func TestIntegrationSign(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	csrPEM := makeCSRPEM(t, "device01.example.com", "device01.example.com")
	bundle, err := c.Sign(context.Background(), srv.Role, csrPEM, bao.SignOptions{
		CommonName: "device01.example.com",
		AltNames:   []string{"device01.example.com"},
		TTL:        "24h",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	blk, _ := pem.Decode([]byte(bundle.Certificate))
	if blk == nil {
		t.Fatal("no certificate in bundle")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if cert.Subject.CommonName != "device01.example.com" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if bundle.SerialNumber == "" {
		t.Error("empty serial number")
	}
	// Sign must never return private key material — the device holds its key.
	if bundle.PrivateKey != "" {
		t.Error("Sign returned a private key")
	}
	if got := time.Until(cert.NotAfter); got > 25*time.Hour {
		t.Errorf("validity %v exceeds the requested 24h", got)
	}
}

// TestIntegrationSignHonorsRequestedNames is the defense-in-depth check: the
// broker constrains what it asks for, and what comes back must match — not the
// wider set the CSR itself requested.
func TestIntegrationSignHonorsRequestedNames(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	// CSR asks for two names; the broker authorizes only one.
	csrPEM := makeCSRPEM(t, "device01.example.com", "device01.example.com", "sneaky.example.com")
	bundle, err := c.Sign(context.Background(), srv.Role, csrPEM, bao.SignOptions{
		CommonName: "device01.example.com",
		AltNames:   []string{"device01.example.com"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	blk, _ := pem.Decode([]byte(bundle.Certificate))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range cert.DNSNames {
		if name == "sneaky.example.com" {
			t.Fatalf("issued cert carries a SAN the broker did not authorize: %v", cert.DNSNames)
		}
	}
}

// TestIntegrationOutOfPolicyDomainRejected proves the second enforcement layer
// is real: even if the broker asked, OpenBao's role refuses.
func TestIntegrationOutOfPolicyDomainRejected(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	csrPEM := makeCSRPEM(t, "device01.notallowed.test")
	_, err := c.Sign(context.Background(), srv.Role, csrPEM, bao.SignOptions{
		CommonName: "device01.notallowed.test",
	})
	if err == nil {
		t.Fatal("expected OpenBao to reject a domain outside allowed_domains")
	}
	var apiErr *bao.APIError
	if !asAPIError(err, &apiErr) {
		t.Fatalf("expected an APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 400 {
		t.Errorf("status = %d, want 400", apiErr.StatusCode)
	}
}

// TestIntegrationTTLCappedByRole confirms the role's max_ttl bounds the broker's
// request rather than the broker's request winning.
func TestIntegrationTTLCappedByRole(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	csrPEM := makeCSRPEM(t, "device01.example.com")
	// Role max_ttl is 2160h (90d); ask for a year.
	bundle, err := c.Sign(context.Background(), srv.Role, csrPEM, bao.SignOptions{
		CommonName: "device01.example.com",
		TTL:        "8760h",
	})
	if err != nil {
		// Some versions reject rather than truncate; either is a valid cap.
		if !strings.Contains(err.Error(), "ttl") && !strings.Contains(err.Error(), "TTL") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	blk, _ := pem.Decode([]byte(bundle.Certificate))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(cert.NotAfter); got > 2161*time.Hour {
		t.Errorf("validity %v exceeds the role's 2160h max_ttl", got)
	}
}

func TestIntegrationIssue(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	// key_type/key_bits are required because the role's key_type is "any";
	// without them OpenBao refuses pki/issue outright.
	bundle, err := c.Issue(context.Background(), srv.Role, "device02.example.com", bao.SignOptions{
		TTL:     "24h",
		KeyType: "rsa",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if bundle.PrivateKey == "" {
		t.Fatal("Issue returned no private key")
	}
	if blk, _ := pem.Decode([]byte(bundle.PrivateKey)); blk == nil {
		t.Fatal("private key is not PEM")
	}
	blk, _ := pem.Decode([]byte(bundle.Certificate))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "device02.example.com" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
}

func TestIntegrationUnknownRoleRejected(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	csrPEM := makeCSRPEM(t, "device01.example.com")
	// The AppRole policy only grants sign on the provisioned role, so an
	// unknown role name is a permission denial rather than a 404.
	if _, err := c.Sign(context.Background(), "no-such-role", csrPEM, bao.SignOptions{}); err == nil {
		t.Fatal("expected signing under an unknown role to fail")
	}
}

// TestIntegrationConcurrentSign exercises the token mutex under load: many
// goroutines share one client and must not corrupt token state or double-login.
func TestIntegrationConcurrentSign(t *testing.T) {
	srv := baotest.Provision(t, "example.com")
	c := newClient(t, srv)

	const n = 8
	errs := make(chan error, n)
	for i := range n {
		go func(i int) {
			csrPEM := makeCSRPEM(t, "device01.example.com")
			_, err := c.Sign(context.Background(), srv.Role, csrPEM, bao.SignOptions{
				CommonName: "device01.example.com",
			})
			errs <- err
		}(i)
	}
	for range n {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Sign: %v", err)
		}
	}
}

// asAPIError is errors.As specialized to *bao.APIError, kept local so the test
// does not depend on the errors package shape.
func asAPIError(err error, target **bao.APIError) bool {
	for err != nil {
		if e, ok := err.(*bao.APIError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
