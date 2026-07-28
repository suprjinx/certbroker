package est

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
)

func TestVerifyIssuedAcceptsMatchingCert(t *testing.T) {
	_, der, _, _ := genLeafWithSANs(t, "device01.example.com", []string{"device01.example.com"})
	cert := parseDER(t, der)

	err := verifyIssued(cert, authz.CertConstraints{
		CommonName: "device01.example.com",
		DNSNames:   []string{"device01.example.com"},
		TTL:        720 * time.Hour,
	})
	if err != nil {
		t.Fatalf("verifyIssued: %v", err)
	}
}

// TestVerifyIssuedCatchesSANInjection is why this check exists: use_csr_sans at
// its default merges the CSR's SANs in, widening the issued identity.
func TestVerifyIssuedCatchesSANInjection(t *testing.T) {
	_, der, _, _ := genLeafWithSANs(t, "device01.example.com",
		[]string{"device01.example.com", "sneaky.example.com"})
	cert := parseDER(t, der)

	err := verifyIssued(cert, authz.CertConstraints{
		CommonName: "device01.example.com",
		DNSNames:   []string{"device01.example.com"},
	})
	if err == nil {
		t.Fatal("expected the unauthorized SAN to be caught")
	}
	if !strings.Contains(err.Error(), "sneaky.example.com") {
		t.Fatalf("error should name the offending SAN: %v", err)
	}
}

// TestVerifyIssuedCatchesCNSubstitution covers use_csr_common_name: the role
// honors the CSR's CN instead of the one the broker authorized.
func TestVerifyIssuedCatchesCNSubstitution(t *testing.T) {
	_, der, _, _ := genLeafWithSANs(t, "attacker.example.com", nil)
	cert := parseDER(t, der)

	err := verifyIssued(cert, authz.CertConstraints{CommonName: "device01.example.com"})
	if err == nil {
		t.Fatal("expected the substituted CN to be caught")
	}
	if !strings.Contains(err.Error(), "attacker.example.com") {
		t.Fatalf("error should name the issued CN: %v", err)
	}
}

func TestVerifyIssuedAllowsCNMirroredIntoSANs(t *testing.T) {
	// OpenBao copies the CN into the SANs unless exclude_cn_from_sans is set;
	// that must not read as an unauthorized name.
	_, der, _, _ := genLeafWithSANs(t, "device01.example.com", []string{"device01.example.com"})
	cert := parseDER(t, der)

	if err := verifyIssued(cert, authz.CertConstraints{CommonName: "device01.example.com"}); err != nil {
		t.Fatalf("CN mirrored into SANs should be accepted: %v", err)
	}
}

func TestVerifyIssuedIsCaseInsensitiveForDNS(t *testing.T) {
	// DNS names are case-insensitive; a case-flipped name is the same name and
	// must not be treated as unauthorized (nor as a bypass).
	_, der, _, _ := genLeafWithSANs(t, "Device01.Example.COM", []string{"Device01.Example.COM"})
	cert := parseDER(t, der)

	err := verifyIssued(cert, authz.CertConstraints{
		CommonName: "device01.example.com",
		DNSNames:   []string{"device01.example.com"},
	})
	if err != nil {
		t.Fatalf("case difference should be accepted: %v", err)
	}
}

func TestVerifyIssuedRejectsUnauthorizedSANWhenNoneAllowed(t *testing.T) {
	_, der, _, _ := genLeafWithSANs(t, "device01.example.com", []string{"other.example.com"})
	cert := parseDER(t, der)

	err := verifyIssued(cert, authz.CertConstraints{CommonName: "device01.example.com"})
	if err == nil {
		t.Fatal("expected rejection of a SAN that is neither the CN nor authorized")
	}
}

func TestVerifyIssuedRejectsExcessiveTTL(t *testing.T) {
	_, der, _, _ := genLeafWithSANs(t, "device01.example.com", nil) // 24h lifetime
	cert := parseDER(t, der)

	err := verifyIssued(cert, authz.CertConstraints{
		CommonName: "device01.example.com",
		TTL:        time.Hour,
	})
	if err == nil {
		t.Fatal("expected a lifetime exceeding the authorized TTL to be caught")
	}
	if !strings.Contains(err.Error(), "lifetime") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyIssuedUnconstrainedFieldsAreNotChecked(t *testing.T) {
	// Empty constraints mean policy deferred to the OpenBao role; there is
	// nothing to enforce and the check must not invent a failure.
	_, der, _, _ := genLeafWithSANs(t, "whatever.example.com", []string{"whatever.example.com"})
	cert := parseDER(t, der)

	if err := verifyIssued(cert, authz.CertConstraints{}); err != nil {
		t.Fatalf("unconstrained issuance should pass: %v", err)
	}
}

func TestVerifyIssuedRejectsUnauthorizedURIAndIP(t *testing.T) {
	u, _ := url.Parse("spiffe://example.com/ns/default/sa/admin")
	_, der, _, _ := genLeafWithURIs(t, "device01.example.com", []*url.URL{u})
	cert := parseDER(t, der)

	err := verifyIssued(cert, authz.CertConstraints{CommonName: "device01.example.com"})
	if err == nil {
		t.Fatal("expected an unauthorized URI SAN to be caught")
	}
	if !strings.Contains(err.Error(), "URI") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRogueRoleIsBlockedEndToEnd drives the handler against a misconfigured
// role and asserts the client gets nothing, not an over-broad certificate.
func TestRogueRoleIsBlockedEndToEnd(t *testing.T) {
	fe := newFakeEnroller(t)
	fe.rogueDNS = []string{"sneaky.example.com"} // role echoes the CSR's SANs

	h, err := NewHandler(quietOpts(Options{
		Enroller:   fe,
		Authorizer: constrainedAuthorizer{cn: "device01.example.com"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	csr := makeCSR(t, "device01.example.com", "device01.example.com", "sneaky.example.com")
	resp := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/simpleenroll", csr)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 — an over-broad certificate must not be released", resp.StatusCode)
	}
}

// constrainedAuthorizer authorizes exactly one name, ignoring the CSR.
type constrainedAuthorizer struct{ cn string }

func (a constrainedAuthorizer) Authorize(_ context.Context, _ authz.Request) (authz.Decision, error) {
	return authz.Decision{
		Allow: true,
		Role:  "test-role",
		Constraints: authz.CertConstraints{
			CommonName: a.cn,
			DNSNames:   []string{a.cn},
		},
		Reason: "test",
	}, nil
}

func parseDER(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// genLeafWithURIs mints a self-signed cert carrying URI SANs.
func genLeafWithURIs(t *testing.T, cn string, uris []*url.URL) (string, []byte, string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		URIs:         uris,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, der, keyPEM, keyDER
}
