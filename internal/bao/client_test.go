package bao

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBao is a minimal in-memory OpenBao stand-in for tests.
type fakeBao struct {
	logins       atomic.Int32
	renews       atomic.Int32
	signs        atomic.Int32
	leaseSeconds int
	renewable    bool
	// failSignTimes causes the first N /sign calls to return 503.
	failSignTimes atomic.Int32
}

func (f *fakeBao) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		f.logins.Add(1)
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] == "" || body["secret_id"] == "" {
			writeErr(w, 400, "missing approle creds")
			return
		}
		writeJSON(w, 200, map[string]any{
			"auth": map[string]any{
				"client_token":   "tok-" + fmt.Sprint(f.logins.Load()),
				"lease_duration": f.leaseSeconds,
				"renewable":      f.renewable,
			},
		})
	})

	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		f.renews.Add(1)
		if r.Header.Get("X-Vault-Token") == "" {
			writeErr(w, 403, "missing token")
			return
		}
		writeJSON(w, 200, map[string]any{
			"auth": map[string]any{
				"lease_duration": f.leaseSeconds,
				"renewable":      f.renewable,
			},
		})
	})

	mux.HandleFunc("/v1/pki_int/sign/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			writeErr(w, 403, "missing token")
			return
		}
		if f.failSignTimes.Load() > 0 {
			f.failSignTimes.Add(-1)
			writeErr(w, 503, "temporarily unavailable")
			return
		}
		f.signs.Add(1)
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["csr"] == "" {
			writeErr(w, 400, "missing csr")
			return
		}
		writeJSON(w, 200, map[string]any{
			"data": map[string]any{
				"certificate":   "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
				"issuing_ca":    "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
				"ca_chain":      []string{"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"},
				"serial_number": "12:34:56",
			},
		})
	})

	mux.HandleFunc("/v1/pki_int/issue/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"data": map[string]any{
				"certificate":   "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
				"issuing_ca":    "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
				"private_key":   "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
				"serial_number": "ab:cd",
			},
		})
	})

	mux.HandleFunc("/v1/pki_int/ca_chain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		io.WriteString(w, "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n")
	})

	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"errors": []string{msg}})
}

func newTestClient(t *testing.T, f *fakeBao) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c, err := New(Config{
		Address:        srv.URL,
		PKIMount:       "pki_int",
		AppRoleMount:   "approle",
		RoleID:         "rid",
		SecretID:       "sid",
		RenewThreshold: 5 * time.Minute,
		MaxRetries:     3,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Point the client at the httptest server's plain-HTTP transport.
	c.hc = srv.Client()
	return c, srv
}

func TestLoginAndReuse(t *testing.T) {
	f := &fakeBao{leaseSeconds: 3600, renewable: true}
	c, _ := newTestClient(t, f)
	ctx := context.Background()

	// Two signs should trigger exactly one login and reuse the token.
	if _, err := c.Sign(ctx, "server", "CSR", SignOptions{}); err != nil {
		t.Fatalf("sign 1: %v", err)
	}
	if _, err := c.Sign(ctx, "server", "CSR", SignOptions{}); err != nil {
		t.Fatalf("sign 2: %v", err)
	}
	if got := f.logins.Load(); got != 1 {
		t.Errorf("logins = %d, want 1", got)
	}
	if got := f.signs.Load(); got != 2 {
		t.Errorf("signs = %d, want 2", got)
	}
}

func TestRenewWhenNearExpiry(t *testing.T) {
	// Short lease so the token is always within the renew threshold.
	f := &fakeBao{leaseSeconds: 60, renewable: true}
	c, _ := newTestClient(t, f)
	ctx := context.Background()

	if _, err := c.Sign(ctx, "server", "CSR", SignOptions{}); err != nil {
		t.Fatalf("sign 1: %v", err)
	}
	if _, err := c.Sign(ctx, "server", "CSR", SignOptions{}); err != nil {
		t.Fatalf("sign 2: %v", err)
	}
	// One login to bootstrap; the second call should renew, not re-login.
	if got := f.logins.Load(); got != 1 {
		t.Errorf("logins = %d, want 1", got)
	}
	if got := f.renews.Load(); got < 1 {
		t.Errorf("renews = %d, want >= 1", got)
	}
}

func TestReLoginWhenNotRenewable(t *testing.T) {
	// Non-renewable short lease forces a fresh login each request.
	f := &fakeBao{leaseSeconds: 60, renewable: false}
	c, _ := newTestClient(t, f)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := c.Sign(ctx, "server", "CSR", SignOptions{}); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}
	if got := f.logins.Load(); got != 3 {
		t.Errorf("logins = %d, want 3 (re-login each call)", got)
	}
	if got := f.renews.Load(); got != 0 {
		t.Errorf("renews = %d, want 0 (not renewable)", got)
	}
}

func TestRetryOn503(t *testing.T) {
	f := &fakeBao{leaseSeconds: 3600, renewable: true}
	f.failSignTimes.Store(2) // first two /sign attempts 503, third succeeds
	c, _ := newTestClient(t, f)

	b, err := c.Sign(context.Background(), "server", "CSR", SignOptions{})
	if err != nil {
		t.Fatalf("sign should succeed after retries: %v", err)
	}
	if b.SerialNumber != "12:34:56" {
		t.Errorf("serial = %q", b.SerialNumber)
	}
}

func TestSignParsing(t *testing.T) {
	f := &fakeBao{leaseSeconds: 3600, renewable: true}
	c, _ := newTestClient(t, f)

	b, err := c.Sign(context.Background(), "server", "CSR", SignOptions{
		CommonName: "device01.example.com",
		AltNames:   []string{"a.example.com", "b.example.com"},
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if b.Certificate == "" || b.IssuingCA == "" {
		t.Errorf("missing cert/issuer in bundle: %+v", b)
	}
	if b.PrivateKey != "" {
		t.Errorf("Sign must not return a private key, got one")
	}
	if len(b.CAChain) != 1 {
		t.Errorf("ca_chain len = %d, want 1", len(b.CAChain))
	}
}

func TestIssueReturnsKey(t *testing.T) {
	f := &fakeBao{leaseSeconds: 3600, renewable: true}
	c, _ := newTestClient(t, f)

	b, err := c.Issue(context.Background(), "server", "device01.example.com", SignOptions{})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if b.PrivateKey == "" {
		t.Errorf("Issue must return a private key")
	}
}

func TestCAChain(t *testing.T) {
	f := &fakeBao{leaseSeconds: 3600, renewable: true}
	c, _ := newTestClient(t, f)

	pem, err := c.CAChain(context.Background())
	if err != nil {
		t.Fatalf("ca_chain: %v", err)
	}
	if len(pem) == 0 {
		t.Error("empty CA chain")
	}
}

func TestClientErrorNotRetried(t *testing.T) {
	f := &fakeBao{leaseSeconds: 3600, renewable: true}
	c, _ := newTestClient(t, f)

	// Empty CSR is rejected client-side before any HTTP call.
	if _, err := c.Sign(context.Background(), "server", "", SignOptions{}); err == nil {
		t.Fatal("expected error for empty CSR")
	}
}
