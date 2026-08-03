package est

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gr-oss/certbroker/internal/authz"
)

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
