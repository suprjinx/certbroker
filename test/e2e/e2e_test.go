//go:build integration

// Package e2e drives the assembled broker the way a device would: real TLS,
// real mTLS, the real pipeline, a real OpenBao. See docs/runbook.md §9.
package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
	"github.com/gr-oss/certbroker/internal/bao"
	"github.com/gr-oss/certbroker/internal/baotest"
	"github.com/gr-oss/certbroker/internal/est"
)

// --- harness ---

type harness struct {
	srv    *httptest.Server
	bao    *baotest.Server
	boot   *testCA // bootstrap CA: gates initial enrollment
	device *x509.CertPool
}

// testCA is a minimal in-test CA for minting bootstrap credentials.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue mints a leaf signed by the CA.
func (ca *testCA) issue(t *testing.T, cn string, eku x509.ExtKeyUsage, dns []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// newHarness provisions OpenBao and stands up the broker over TLS.
func newHarness(t *testing.T, inventoryYAML string, role string) *harness {
	t.Helper()

	baoSrv := baotest.Provision(t, "example.com")
	if role == "" {
		role = baoSrv.Role
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	client, err := bao.New(bao.Config{
		Address:      baoSrv.Addr,
		PKIMount:     baoSrv.Mount,
		AppRoleMount: "approle",
		RoleID:       baoSrv.RoleID,
		SecretID:     baoSrv.SecretID,
		MaxRetries:   2,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Devices renew against the CA that issued them: OpenBao's mount.
	devicePool := x509.NewCertPool()
	if !devicePool.AppendCertsFromPEM(baoSrv.CACertPEM) {
		t.Fatal("could not load the OpenBao CA as the device trust anchor")
	}
	bootstrapCA := newTestCA(t, "e2e bootstrap CA")

	invPath := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(invPath, []byte(inventoryYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := authz.NewFileInventory(invPath)
	if err != nil {
		t.Fatal(err)
	}

	pipeline := &authz.Pipeline{
		Inventory:   inv,
		Challenge:   authz.NoChallenge{},
		Roles:       authz.NewRuleSelector(nil, role),
		Constraints: authz.NewStandardConstraints(authz.SANModeIdentity, 720*time.Hour),
	}

	handler, err := est.NewHandler(est.Options{
		BootstrapRoots:      bootstrapCA.pool,
		DeviceRoots:         devicePool,
		Enroller:            client,
		Authorizer:          pipeline,
		AllowedKeyTypes:     []string{"rsa-2048", "ec-p256", "ec-p384"},
		ServerKeyGenKeyType: "rsa",
		ServerKeyGenKeyBits: 2048,
		Logger:              logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Signed by the bootstrap CA only so the client trusts it; unrelated to enrollment.
	serverCert := bootstrapCA.issue(t, "localhost", x509.ExtKeyUsageServerAuth,
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = est.TLSConfig(serverCert)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &harness{srv: srv, bao: baoSrv, boot: bootstrapCA, device: devicePool}
}

// client builds an HTTPS client presenting cert (or none) and trusting the broker.
func (h *harness) client(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: h.boot.pool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}
}

func (h *harness) url(op string) string {
	return h.srv.URL + "/.well-known/est/" + op
}

// enroll POSTs a CSR and returns the HTTP status plus the issued certificates.
func (h *harness) enroll(t *testing.T, c *http.Client, op string, csrDER []byte) (int, []*x509.Certificate) {
	t.Helper()
	body := base64.StdEncoding.EncodeToString(csrDER)
	req, err := http.NewRequest(http.MethodPost, h.url(op), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Content-Transfer-Encoding", "base64")

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(string(raw)))
	if err != nil {
		t.Fatalf("decode response base64: %v", err)
	}
	return resp.StatusCode, certsFromPKCS7(t, der)
}

// --- helpers ---

// makeCSR builds a CSR with the given subject and SANs.
func makeCSR(t *testing.T, cn string, dns ...string) ([]byte, *ecdsa.PrivateKey) {
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
	return der, key
}

// certsFromPKCS7 decodes a degenerate PKCS#7, mirroring internal/pkcs7.
func certsFromPKCS7(t *testing.T, der []byte) []*x509.Certificate {
	t.Helper()

	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatalf("parse ContentInfo: %v", err)
	}

	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"tag:0,optional"`
		SignerInfos      asn1.RawValue
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("parse SignedData: %v", err)
	}

	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		t.Fatalf("parse certificates: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("no certificates in the PKCS#7 response")
	}
	return certs
}

// tlsCertFrom pairs an issued certificate with the key that requested it.
func tlsCertFrom(cert *x509.Certificate, key *ecdsa.PrivateKey) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

const inventoryOneDevice = `
devices:
  - cn: device01.example.com
    allowed_dns:
      - device01.example.com
`

// --- tests ---

// TestEnrollThenReenroll walks the full device lifecycle across both anchors.
func TestEnrollThenReenroll(t *testing.T) {
	h := newHarness(t, inventoryOneDevice, "")

	// --- initial enrollment, authenticated by a bootstrap certificate ---
	bootstrapCert := h.boot.issue(t, "device01.example.com", x509.ExtKeyUsageClientAuth,
		[]string{"device01.example.com"}, nil)

	csr, key := makeCSR(t, "device01.example.com", "device01.example.com")
	status, certs := h.enroll(t, h.client(&bootstrapCert), "simpleenroll", csr)
	if status != http.StatusOK {
		t.Fatalf("simpleenroll status = %d, want 200", status)
	}

	issued := certs[0]
	if issued.Subject.CommonName != "device01.example.com" {
		t.Errorf("issued CN = %q", issued.Subject.CommonName)
	}
	if len(issued.DNSNames) != 1 || issued.DNSNames[0] != "device01.example.com" {
		t.Errorf("issued SANs = %v, want exactly [device01.example.com]", issued.DNSNames)
	}
	// It must chain to the device anchor, or renewal could never work.
	if _, err := issued.Verify(x509.VerifyOptions{
		Roots:     h.device,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("issued cert does not chain to the device trust anchor: %v", err)
	}

	// --- renewal, authenticated by the certificate just issued ---
	renewCSR, _ := makeCSR(t, "device01.example.com", "device01.example.com")
	status, renewed := h.enroll(t, h.client(tlsCertFrom(issued, key)), "simplereenroll", renewCSR)
	if status != http.StatusOK {
		t.Fatalf("simplereenroll status = %d, want 200", status)
	}
	if renewed[0].Subject.CommonName != "device01.example.com" {
		t.Errorf("renewed CN = %q", renewed[0].Subject.CommonName)
	}
	if renewed[0].SerialNumber.Cmp(issued.SerialNumber) == 0 {
		t.Error("renewal returned the same serial; expected a fresh certificate")
	}
}

// TestBootstrapCertCannotRenew: a bootstrap credential must not renew.
func TestBootstrapCertCannotRenew(t *testing.T) {
	h := newHarness(t, inventoryOneDevice, "")
	bootstrapCert := h.boot.issue(t, "device01.example.com", x509.ExtKeyUsageClientAuth,
		[]string{"device01.example.com"}, nil)

	csr, _ := makeCSR(t, "device01.example.com", "device01.example.com")
	status, _ := h.enroll(t, h.client(&bootstrapCert), "simplereenroll", csr)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a bootstrap cert must not authorize renewal", status)
	}
}

func TestReenrollWithoutClientCertRejected(t *testing.T) {
	h := newHarness(t, inventoryOneDevice, "")
	csr, _ := makeCSR(t, "device01.example.com", "device01.example.com")

	status, _ := h.enroll(t, h.client(nil), "simplereenroll", csr)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
}

func TestDeviceNotInInventoryRejected(t *testing.T) {
	h := newHarness(t, inventoryOneDevice, "")
	cert := h.boot.issue(t, "rogue.example.com", x509.ExtKeyUsageClientAuth,
		[]string{"rogue.example.com"}, nil)

	csr, _ := makeCSR(t, "rogue.example.com", "rogue.example.com")
	status, _ := h.enroll(t, h.client(&cert), "simpleenroll", csr)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
}

// TestSANEscalationRejected: a name beyond the authenticated identity is
// refused by policy, before OpenBao is called.
func TestSANEscalationRejected(t *testing.T) {
	h := newHarness(t, inventoryOneDevice, "")
	cert := h.boot.issue(t, "device01.example.com", x509.ExtKeyUsageClientAuth,
		[]string{"device01.example.com"}, nil)

	csr, _ := makeCSR(t, "device01.example.com", "device01.example.com", "admin.example.com")
	status, _ := h.enroll(t, h.client(&cert), "simpleenroll", csr)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — SAN escalation must be refused", status)
	}
}

// TestPermissiveRoleCannotSubstituteCN proves the post-issuance check on real
// OpenBao: policy pins the CN to device01, use_csr_common_name overrides it.
func TestPermissiveRoleCannotSubstituteCN(t *testing.T) {
	inventory := `
devices:
  - cn: device01.example.com
    allowed_dns:
      - device01.example.com
      - extra.example.com
`
	h := newHarness(t, inventory, "")

	// A role left at OpenBao's permissive defaults.
	h.bao.WriteRole("permissive-role", map[string]any{
		"use_csr_common_name": true,
		"use_csr_sans":        true,
	})
	h2 := newHarnessOnRole(t, h, inventory, "permissive-role")

	// Identity covers both names; the authorized CN is still device01.
	cert := h2.boot.issue(t, "device01.example.com", x509.ExtKeyUsageClientAuth,
		[]string{"device01.example.com", "extra.example.com"}, nil)

	// The CSR asks to be issued as extra.example.com.
	csr, _ := makeCSR(t, "extra.example.com")

	status, certs := h2.enroll(t, h2.client(&cert), "simpleenroll", csr)
	if status == http.StatusOK {
		cn := ""
		if len(certs) > 0 {
			cn = certs[0].Subject.CommonName
		}
		t.Fatalf("broker released a certificate with CN %q from a permissive role; "+
			"the post-issuance constraint check should have withheld it", cn)
	}
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", status)
	}
}

// TestStrictRoleIssuesTheAuthorizedName is the control: the same request against
// a correct role yields the authorized name, not the requested one.
func TestStrictRoleIssuesTheAuthorizedName(t *testing.T) {
	inventory := `
devices:
  - cn: device01.example.com
    allowed_dns:
      - device01.example.com
      - extra.example.com
`
	h := newHarness(t, inventory, "")
	cert := h.boot.issue(t, "device01.example.com", x509.ExtKeyUsageClientAuth,
		[]string{"device01.example.com", "extra.example.com"}, nil)

	csr, _ := makeCSR(t, "extra.example.com")
	status, certs := h.enroll(t, h.client(&cert), "simpleenroll", csr)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got := certs[0].Subject.CommonName; got != "device01.example.com" {
		t.Fatalf("issued CN = %q, want the authorized identity CN device01.example.com", got)
	}
}

// newHarnessOnRole rebuilds the broker against the same OpenBao, a new role.
func newHarnessOnRole(t *testing.T, base *harness, inventoryYAML, role string) *harness {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	client, err := bao.New(bao.Config{
		Address:      base.bao.Addr,
		PKIMount:     base.bao.Mount,
		AppRoleMount: "approle",
		RoleID:       base.bao.RoleID,
		SecretID:     base.bao.SecretID,
		MaxRetries:   2,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	invPath := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(invPath, []byte(inventoryYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := authz.NewFileInventory(invPath)
	if err != nil {
		t.Fatal(err)
	}

	handler, err := est.NewHandler(est.Options{
		BootstrapRoots: base.boot.pool,
		DeviceRoots:    base.device,
		Enroller:       client,
		Authorizer: &authz.Pipeline{
			Inventory:   inv,
			Challenge:   authz.NoChallenge{},
			Roles:       authz.NewRuleSelector(nil, role),
			Constraints: authz.NewStandardConstraints(authz.SANModeIdentity, 720*time.Hour),
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	serverCert := base.boot.issue(t, "localhost", x509.ExtKeyUsageServerAuth,
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = est.TLSConfig(serverCert)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &harness{srv: srv, bao: base.bao, boot: base.boot, device: base.device}
}

// TestCACerts checks the chain the broker publishes actually matches OpenBao's.
func TestCACerts(t *testing.T) {
	h := newHarness(t, inventoryOneDevice, "")

	resp, err := h.client(nil).Get(h.url("cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	raw, _ := io.ReadAll(resp.Body)
	der, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(string(raw)))
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	certs := certsFromPKCS7(t, der)

	blk, _ := pem.Decode(h.bao.CACertPEM)
	expected, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certs[0].Equal(expected) {
		t.Errorf("/cacerts served %q, want %q",
			certs[0].Subject.CommonName, expected.Subject.CommonName)
	}
}

// TestServerKeyGen covers the broker-generated-key path, where the role's
// key_type=any requirement surfaced.
func TestServerKeyGen(t *testing.T) {
	h := newHarness(t, inventoryOneDevice, "")
	cert := h.boot.issue(t, "device01.example.com", x509.ExtKeyUsageClientAuth,
		[]string{"device01.example.com"}, nil)

	csr, _ := makeCSR(t, "device01.example.com", "device01.example.com")
	body := base64.StdEncoding.EncodeToString(csr)
	req, err := http.NewRequest(http.MethodPost, h.url("serverkeygen"), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Content-Transfer-Encoding", "base64")

	resp, err := h.client(&cert).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "multipart/mixed") {
		t.Errorf("content-type = %q, want multipart/mixed", ct)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "application/pkcs8") {
		t.Error("response is missing the PKCS#8 private key part")
	}
}
