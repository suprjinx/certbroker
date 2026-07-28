package est

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
	"github.com/gr-oss/certbroker/internal/bao"
)

// --- fakes ---

type fakeEnroller struct {
	caChainPEM []byte
	leafPEM    string
	leafDER    []byte
	keyPEM     string
	keyDER     []byte

	lastRole string
	lastOpts bao.SignOptions

	// t enables parameter-honoring issuance (see issueFor).
	t *testing.T
	// lastLeafDER is the DER of the most recently minted certificate.
	lastLeafDER []byte
	// rogueCN / rogueDNS make the fake role echo the CSR's own names back.
	rogueCN  string
	rogueDNS []string
}

// issueFor honors the requested parameters as a correct OpenBao role does; the
// rogue fields instead simulate permissive use_csr_* defaults.
func (f *fakeEnroller) issueFor(t *testing.T, opts bao.SignOptions) string {
	t.Helper()
	cn, dns := opts.CommonName, opts.AltNames
	if f.rogueCN != "" || len(f.rogueDNS) > 0 {
		if f.rogueCN != "" {
			cn = f.rogueCN
		}
		dns = append(append([]string{}, opts.AltNames...), f.rogueDNS...)
	} else if len(dns) == 0 && cn != "" {
		dns = []string{cn}
	}
	pemStr, der, _, _ := genLeafWithSANs(t, cn, dns)
	f.lastLeafDER = der
	return pemStr
}

func (f *fakeEnroller) Sign(_ context.Context, role, _ string, opts bao.SignOptions) (*bao.CertBundle, error) {
	f.lastRole = role
	f.lastOpts = opts
	if f.t != nil && opts.CommonName != "" {
		return &bao.CertBundle{Certificate: f.issueFor(f.t, opts)}, nil
	}
	return &bao.CertBundle{Certificate: f.leafPEM}, nil
}

func (f *fakeEnroller) Issue(_ context.Context, role, _ string, opts bao.SignOptions) (*bao.CertBundle, error) {
	f.lastRole = role
	f.lastOpts = opts
	if f.t != nil && opts.CommonName != "" {
		return &bao.CertBundle{Certificate: f.issueFor(f.t, opts), PrivateKey: f.keyPEM}, nil
	}
	return &bao.CertBundle{Certificate: f.leafPEM, PrivateKey: f.keyPEM}, nil
}

func (f *fakeEnroller) CAChain(context.Context) ([]byte, error) {
	return f.caChainPEM, nil
}

func newFakeEnroller(t *testing.T) *fakeEnroller {
	t.Helper()
	certPEM, certDER, keyPEM, keyDER := genLeaf(t, "device-issued.example.com")
	return &fakeEnroller{
		caChainPEM: []byte(certPEM), // reuse as a stand-in CA chain
		leafPEM:    certPEM,
		leafDER:    certDER,
		keyPEM:     keyPEM,
		keyDER:     keyDER,
		t:          t,
	}
}

// genLeaf makes a self-signed cert + PKCS#8 key and returns PEM + DER for each.
func genLeaf(t *testing.T, cn string) (certPEM string, certDER []byte, keyPEM string, keyDER []byte) {
	return genLeafWithSANs(t, cn, nil)
}

// genLeafWithSANs is genLeaf with explicit dNSName SANs.
func genLeafWithSANs(t *testing.T, cn string, dns []string) (certPEM string, certDER []byte, keyPEM string, keyDER []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
}

// --- test PKI for mTLS ---

type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	pool   *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &testPKI{caCert: caCert, caKey: key, pool: pool}
}

func (p *testPKI) issue(t *testing.T, cn string, eku x509.ExtKeyUsage, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// --- helpers ---

func newTestHandler(t *testing.T, fe Enroller, az authz.Authorizer, pki *testPKI, csrAttrs []byte) http.Handler {
	t.Helper()
	opts := Options{Enroller: fe, Authorizer: az, CSRAttrs: csrAttrs}
	if pki != nil {
		opts.BootstrapRoots = pki.pool
		opts.DeviceRoots = pki.pool
	}
	h, err := NewHandler(opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func postCSR(t *testing.T, client *http.Client, url string, csrDER []byte) *http.Response {
	t.Helper()
	body := base64.StdEncoding.EncodeToString(csrDER)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", ctPKCS10)
	req.Header.Set("Content-Transfer-Encoding", "base64")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decodeBase64Body(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dec, err := base64.StdEncoding.DecodeString(string(stripASCIIWhitespace(raw)))
	if err != nil {
		t.Fatalf("decode body base64: %v", err)
	}
	return dec
}

// --- tests ---

func TestCACerts(t *testing.T) {
	fe := newFakeEnroller(t)
	srv := httptest.NewServer(newTestHandler(t, fe, authz.AllowAllEcho{Role: "server"}, nil, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "pkcs7-mime") {
		t.Errorf("content-type = %q", ct)
	}
	p7 := decodeBase64Body(t, resp)
	if !bytes.Contains(p7, fe.leafDER) {
		t.Error("pkcs7 does not contain the CA cert DER")
	}
}

func TestSimpleEnrollHappy(t *testing.T) {
	fe := newFakeEnroller(t)
	srv := httptest.NewServer(newTestHandler(t, fe, authz.AllowAllEcho{Role: "server-role"}, nil, nil))
	defer srv.Close()

	csr := makeCSR(t, "device01.example.com", "device01.example.com")
	resp := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/simpleenroll", csr)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	p7 := decodeBase64Body(t, resp)
	if !bytes.Contains(p7, fe.lastLeafDER) {
		t.Error("pkcs7 does not contain the issued leaf DER")
	}
	if fe.lastRole != "server-role" {
		t.Errorf("role = %q, want server-role", fe.lastRole)
	}
	// AllowAllEcho should have echoed the CSR CN into the constraints.
	if fe.lastOpts.CommonName != "device01.example.com" {
		t.Errorf("signed CN = %q", fe.lastOpts.CommonName)
	}
}

func TestSimpleEnrollBadSignature(t *testing.T) {
	fe := newFakeEnroller(t)
	srv := httptest.NewServer(newTestHandler(t, fe, authz.AllowAllEcho{Role: "r"}, nil, nil))
	defer srv.Close()

	csr := makeCSR(t, "device01.example.com")
	csr[len(csr)-1] ^= 0xFF // break PoP
	resp := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/simpleenroll", csr)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSimpleEnrollDenied(t *testing.T) {
	fe := newFakeEnroller(t)
	srv := httptest.NewServer(newTestHandler(t, fe, authz.DenyAll{}, nil, nil))
	defer srv.Close()

	csr := makeCSR(t, "device01.example.com")
	resp := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/simpleenroll", csr)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestCSRAttrs(t *testing.T) {
	fe := newFakeEnroller(t)

	// Unset -> 204.
	srv := httptest.NewServer(newTestHandler(t, fe, authz.DenyAll{}, nil, nil))
	resp, _ := http.Get(srv.URL + "/.well-known/est/csrattrs")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("unset csrattrs status = %d, want 204", resp.StatusCode)
	}
	srv.Close()

	// Set -> 200 with base64 body.
	attrs := []byte{0x30, 0x00} // empty SEQUENCE, a valid minimal advertisement
	srv2 := httptest.NewServer(newTestHandler(t, fe, authz.DenyAll{}, nil, attrs))
	defer srv2.Close()
	resp2, _ := http.Get(srv2.URL + "/.well-known/est/csrattrs")
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("set csrattrs status = %d, want 200", resp2.StatusCode)
	}
	if got := decodeBase64Body(t, resp2); !bytes.Equal(got, attrs) {
		t.Errorf("csrattrs body = %x, want %x", got, attrs)
	}
}

func TestReenrollRequiresClientCert(t *testing.T) {
	fe := newFakeEnroller(t)
	pki := newTestPKI(t)
	serverCert := pki.issue(t, "localhost", x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1)})

	srv := httptest.NewUnstartedServer(newTestHandler(t, fe, authz.AllowAllEcho{Role: "renew"}, pki, nil))
	srv.TLS = TLSConfig(serverCert)
	srv.StartTLS()
	defer srv.Close()

	csr := makeCSR(t, "device01.example.com")

	// No client cert -> 403.
	resp := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/simplereenroll", csr)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no-cert status = %d, want 403", resp.StatusCode)
	}

	// Valid device cert -> 200.
	deviceCert := pki.issue(t, "device01.example.com", x509.ExtKeyUsageClientAuth, nil)
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{deviceCert}
	resp2 := postCSR(t, client, srv.URL+"/.well-known/est/simplereenroll", csr)
	if resp2.StatusCode != 200 {
		t.Fatalf("with-cert status = %d, want 200", resp2.StatusCode)
	}
	p7 := decodeBase64Body(t, resp2)
	if !bytes.Contains(p7, fe.lastLeafDER) {
		t.Error("reenroll pkcs7 missing leaf DER")
	}
}

func TestServerKeyGen(t *testing.T) {
	fe := newFakeEnroller(t)
	pki := newTestPKI(t)
	serverCert := pki.issue(t, "localhost", x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1)})

	srv := httptest.NewUnstartedServer(newTestHandler(t, fe, authz.AllowAllEcho{Role: "skg"}, pki, nil))
	srv.TLS = TLSConfig(serverCert)
	srv.StartTLS()
	defer srv.Close()

	deviceCert := pki.issue(t, "device01.example.com", x509.ExtKeyUsageClientAuth, nil)
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{deviceCert}

	csr := makeCSR(t, "device01.example.com")
	resp := postCSR(t, client, srv.URL+"/.well-known/est/serverkeygen", csr)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	mt, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("content-type = %q (%v)", resp.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(resp.Body, params["boundary"])
	var sawKey, sawCert bool
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(part)
		dec, _ := base64.StdEncoding.DecodeString(string(stripASCIIWhitespace(body)))
		switch {
		case strings.Contains(part.Header.Get("Content-Type"), "pkcs8"):
			sawKey = true
			if !bytes.Contains(dec, fe.keyDER) {
				t.Error("pkcs8 part missing key DER")
			}
		case strings.Contains(part.Header.Get("Content-Type"), "pkcs7"):
			sawCert = true
			if !bytes.Contains(dec, fe.lastLeafDER) {
				t.Error("pkcs7 part missing cert DER")
			}
		}
	}
	if !sawKey || !sawCert {
		t.Errorf("multipart missing parts: key=%v cert=%v", sawKey, sawCert)
	}
}

func TestUnknownOperation(t *testing.T) {
	fe := newFakeEnroller(t)
	srv := httptest.NewServer(newTestHandler(t, fe, authz.DenyAll{}, nil, nil))
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/.well-known/est/bogus")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
