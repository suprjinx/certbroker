// Package baotest provisions an isolated PKI mount and AppRole on a live
// OpenBao server for integration tests.
//
// Tests using it are guarded by the `integration` build tag and skip unless
// CERTBROKER_TEST_OPENBAO_ADDR is set, so the default `go test ./...` stays
// hermetic. Point it at the dev stack:
//
//	make dev-up
//	CERTBROKER_TEST_OPENBAO_ADDR=http://localhost:8200 \
//	CERTBROKER_TEST_OPENBAO_TOKEN=dev-root-token \
//	  go test -tags=integration -count=1 ./...
//
// Each call to Provision creates a uniquely-named mount and AppRole and tears
// them down via t.Cleanup, so parallel and repeated runs do not collide.
package baotest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// Env vars naming the target server. Both must be set for integration tests to
// run; the token must be able to mount secrets engines and write policies.
const (
	EnvAddr  = "CERTBROKER_TEST_OPENBAO_ADDR"
	EnvToken = "CERTBROKER_TEST_OPENBAO_TOKEN"
)

// Server is a provisioned OpenBao environment for one test.
type Server struct {
	Addr string // e.g. http://localhost:8200

	Mount string // PKI mount path, unique per test
	Role  string // PKI issuing role name

	AppRole  string // AppRole name, unique per test
	RoleID   string
	SecretID string

	// CACertPEM is the mount's CA certificate — the anchor that issued certs
	// chain to, i.e. the device trust anchor for re-enrollment.
	CACertPEM []byte

	token  string
	client *http.Client
	t      *testing.T
}

// Provision creates an isolated PKI mount, issuing role, and least-privilege
// AppRole, and registers cleanup. It skips the test when the env vars are unset.
//
// allowedDomains is passed through to the PKI role; issuance of anything
// outside it fails at OpenBao regardless of what the broker authorizes.
func Provision(t *testing.T, allowedDomains string) *Server {
	t.Helper()

	addr := os.Getenv(EnvAddr)
	token := os.Getenv(EnvToken)
	if addr == "" || token == "" {
		t.Skipf("integration test needs %s and %s", EnvAddr, EnvToken)
	}

	suffix := randomSuffix(t)
	s := &Server{
		Addr:    addr,
		Mount:   "pki_test_" + suffix,
		Role:    "test-role",
		AppRole: "certbroker_test_" + suffix,
		token:   token,
		client:  &http.Client{Timeout: 15 * time.Second},
		t:       t,
	}

	s.mountPKI()
	s.generateCA()
	s.writeRole(allowedDomains)
	s.enableAppRole()
	s.writePolicy()
	s.writeAppRole()
	s.RoleID = s.readRoleID()
	s.SecretID = s.issueSecretID()
	s.CACertPEM = s.readCACert()

	t.Cleanup(s.teardown)
	return s
}

// PolicyName is the ACL policy created for this server's AppRole.
func (s *Server) PolicyName() string { return s.AppRole }

func (s *Server) mountPKI() {
	s.t.Helper()
	s.post("v1/sys/mounts/"+s.Mount, map[string]any{
		"type":   "pki",
		"config": map[string]any{"max_lease_ttl": "87600h"},
	}, nil)
}

func (s *Server) generateCA() {
	s.t.Helper()
	s.post("v1/"+s.Mount+"/root/generate/internal", map[string]any{
		"common_name": "certbroker integration test CA",
		"ttl":         "87600h",
	}, nil)
}

func (s *Server) writeRole(allowedDomains string) {
	s.t.Helper()
	s.writeRoleWith(s.Role, map[string]any{
		"allowed_domains": allowedDomains,
		// Not the OpenBao defaults, and security-critical: left true, the CSR's
		// own CN and SANs merge into the issued certificate alongside the
		// broker's constrained parameters, defeating the constraint policy.
		"use_csr_common_name": false,
		"use_csr_sans":        false,
	})
}

// WriteRole creates an additional PKI role with the given overrides layered
// over the defaults. Tests use it to provision a deliberately permissive role.
func (s *Server) WriteRole(name string, overrides map[string]any) {
	s.t.Helper()
	s.writeRoleWith(name, overrides)
}

func (s *Server) writeRoleWith(name string, overrides map[string]any) {
	s.t.Helper()
	body := map[string]any{
		"allowed_domains":     "example.com",
		"allow_subdomains":    true,
		"allow_bare_domains":  false,
		"allow_localhost":     false,
		"allow_ip_sans":       false,
		"use_csr_common_name": false,
		"use_csr_sans":        false,
		"server_flag":         true,
		"client_flag":         true,
		"key_type":            "any",
		"max_ttl":             "2160h",
		"ttl":                 "720h",
	}
	for k, v := range overrides {
		body[k] = v
	}
	s.post("v1/"+s.Mount+"/roles/"+name, body, nil)
}

func (s *Server) enableAppRole() {
	s.t.Helper()
	// Already-enabled is the normal case on a shared dev server; the mount is
	// global rather than per-test, so a failure here is not fatal.
	var out map[string]any
	if err := s.request(http.MethodGet, "v1/sys/auth", nil, &out); err == nil {
		if _, ok := out["approle/"]; ok {
			return
		}
	}
	_ = s.try(http.MethodPost, "v1/sys/auth/approle", map[string]any{"type": "approle"}, nil)
}

func (s *Server) writePolicy() {
	s.t.Helper()
	// The capability set the broker needs: sign, issue, and read the chain for
	// /cacerts and the readiness probe.
	//
	// Wildcarded over role names so a test can provision extra roles; the
	// least-privilege form naming a single role is in
	// deploy/provision-openbao.sh, which is what a deployment should copy.
	policy := fmt.Sprintf(`
path "%[1]s/sign/*"   { capabilities = ["create", "update"] }
path "%[1]s/issue/*"  { capabilities = ["create", "update"] }
path "%[1]s/ca_chain" { capabilities = ["read"] }
`, s.Mount)

	s.post("v1/sys/policies/acl/"+s.PolicyName(), map[string]any{"policy": policy}, nil)
}

func (s *Server) writeAppRole() {
	s.t.Helper()
	s.post("v1/auth/approle/role/"+s.AppRole, map[string]any{
		"token_policies":     s.PolicyName(),
		"token_ttl":          "20m",
		"token_max_ttl":      "1h",
		"secret_id_ttl":      0,
		"secret_id_num_uses": 0,
	}, nil)
}

func (s *Server) readRoleID() string {
	s.t.Helper()
	var out struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	s.request2(http.MethodGet, "v1/auth/approle/role/"+s.AppRole+"/role-id", nil, &out)
	if out.Data.RoleID == "" {
		s.t.Fatal("baotest: empty role_id")
	}
	return out.Data.RoleID
}

func (s *Server) issueSecretID() string {
	s.t.Helper()
	var out struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	s.post("v1/auth/approle/role/"+s.AppRole+"/secret-id", map[string]any{}, &out)
	if out.Data.SecretID == "" {
		s.t.Fatal("baotest: empty secret_id")
	}
	return out.Data.SecretID
}

func (s *Server) readCACert() []byte {
	s.t.Helper()
	var out struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	s.request2(http.MethodGet, "v1/"+s.Mount+"/cert/ca", nil, &out)
	if out.Data.Certificate == "" {
		s.t.Fatal("baotest: empty CA certificate")
	}
	return []byte(out.Data.Certificate)
}

// IssueSecretID mints an additional SecretID, for tests that need a second one.
func (s *Server) IssueSecretID() string { return s.issueSecretID() }

func (s *Server) teardown() {
	// Best effort: a leaked test mount on a dev server is noise, not a failure.
	_ = s.try(http.MethodDelete, "v1/sys/mounts/"+s.Mount, nil, nil)
	_ = s.try(http.MethodDelete, "v1/auth/approle/role/"+s.AppRole, nil, nil)
	_ = s.try(http.MethodDelete, "v1/sys/policies/acl/"+s.PolicyName(), nil, nil)
}

// --- HTTP plumbing ---

func (s *Server) post(path string, body any, out any) {
	s.t.Helper()
	s.request2(http.MethodPost, path, body, out)
}

// request2 is request with a fatal on error.
func (s *Server) request2(method, path string, body, out any) {
	s.t.Helper()
	if err := s.request(method, path, body, out); err != nil {
		s.t.Fatalf("baotest: %v", err)
	}
}

func (s *Server) try(method, path string, body, out any) error {
	return s.request(method, path, body, out)
}

func (s *Server) request(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", path, err)
		}
		rdr = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, s.Addr+"/"+path, rdr)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("X-Vault-Token", s.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s -> %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(raw))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return nil
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("baotest: random: %v", err)
	}
	return hex.EncodeToString(b[:])
}
