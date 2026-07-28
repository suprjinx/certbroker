package est

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
	"github.com/gr-oss/certbroker/internal/bao"
)

// blockingEnroller is an OpenBao that stopped responding: every call waits on
// its context, so the handler's deadline is what ends it.
type blockingEnroller struct{}

func (blockingEnroller) Sign(ctx context.Context, _, _ string, _ bao.SignOptions) (*bao.CertBundle, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingEnroller) Issue(ctx context.Context, _, _ string, _ bao.SignOptions) (*bao.CertBundle, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingEnroller) CAChain(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func quietOpts(opts Options) Options {
	opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return opts
}

func TestRequestSizeLimit(t *testing.T) {
	fe := newFakeEnroller(t)
	h, err := NewHandler(quietOpts(Options{
		Enroller:        fe,
		Authorizer:      authz.AllowAllEcho{Role: "r"},
		MaxRequestBytes: 1024,
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	oversized := strings.Repeat("A", 4096)
	resp, err := http.Post(srv.URL+"/.well-known/est/simpleenroll", ctPKCS10, strings.NewReader(oversized))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

// TestRequestSizeLimitIsCheckedBeforeParsing: the payload is not a valid CSR, so
// a 400 would mean the parser ran on an oversized body.
func TestRequestSizeLimitIsCheckedBeforeParsing(t *testing.T) {
	fe := newFakeEnroller(t)
	h, err := NewHandler(quietOpts(Options{
		Enroller:        fe,
		Authorizer:      authz.AllowAllEcho{Role: "r"},
		MaxRequestBytes: 512,
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/.well-known/est/simpleenroll", ctPKCS10,
		strings.NewReader(strings.Repeat("\x30", 2048)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestEmptyBodyRejected(t *testing.T) {
	fe := newFakeEnroller(t)
	srv := httptest.NewServer(newTestHandler(t, fe, authz.AllowAllEcho{Role: "r"}, nil, nil))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/.well-known/est/simpleenroll", ctPKCS10, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestUpstreamTimeout: a wedged OpenBao must not pin the request goroutine.
func TestUpstreamTimeout(t *testing.T) {
	h, err := NewHandler(quietOpts(Options{
		Enroller:        blockingEnroller{},
		Authorizer:      authz.AllowAllEcho{Role: "r"},
		UpstreamTimeout: 50 * time.Millisecond,
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	csr := makeCSR(t, "device01.example.com")
	start := time.Now()
	resp := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/simpleenroll", csr)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("request took %v; the upstream deadline did not fire", elapsed)
	}
}

func TestCACertsUpstreamTimeout(t *testing.T) {
	h, err := NewHandler(quietOpts(Options{
		Enroller:        blockingEnroller{},
		Authorizer:      authz.AllowAllEcho{Role: "r"},
		UpstreamTimeout: 50 * time.Millisecond,
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

// TestEnrollRejectsUndersizedRSAKey exercises the RSA floor end to end.
func TestEnrollRejectsUndersizedRSAKey(t *testing.T) {
	fe := newFakeEnroller(t)
	h, err := NewHandler(quietOpts(Options{
		Enroller:   fe,
		Authorizer: authz.AllowAllEcho{Role: "r"},
		MinRSABits: 2048,
		MaxRSABits: 8192,
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "weak.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}

	resp := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/simpleenroll", der)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "too small") {
		t.Fatalf("body = %q, want a key-size rejection", body)
	}
}

// TestServerKeyGenEnforcesKeyTypePolicy covers the key-type allowlist on
// /serverkeygen, which previously ignored policy entirely.
func TestServerKeyGenEnforcesKeyTypePolicy(t *testing.T) {
	fe := newFakeEnroller(t)
	pki := newTestPKI(t)
	h, err := NewHandler(quietOpts(Options{
		Enroller:        fe,
		Authorizer:      authz.AllowAllEcho{Role: "r"},
		BootstrapRoots:  pki.pool,
		DeviceRoots:     pki.pool,
		AllowedKeyTypes: []string{"rsa-2048"}, // EC is not permitted
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	csr := makeCSR(t, "device01.example.com")
	resp := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/serverkeygen", csr)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// TestBase64AndRawDERBothAccepted guards readCSR's CTE handling, which shares a
// code path with the size limit.
func TestBase64AndRawDERBothAccepted(t *testing.T) {
	fe := newFakeEnroller(t)
	srv := httptest.NewServer(newTestHandler(t, fe, authz.AllowAllEcho{Role: "r"}, nil, nil))
	defer srv.Close()

	csr := makeCSR(t, "device01.example.com")

	// Raw DER, no Content-Transfer-Encoding.
	resp, err := http.Post(srv.URL+"/.well-known/est/simpleenroll", ctPKCS10, strings.NewReader(string(csr)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw DER: status = %d, want 200", resp.StatusCode)
	}

	// Base64 with the header set.
	resp2 := postCSR(t, srv.Client(), srv.URL+"/.well-known/est/simpleenroll", csr)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("base64: status = %d, want 200", resp2.StatusCode)
	}
}
