// Package authz defines the authorization seam between the enrollment
// protocols (EST, later SCEP) and the policy engine that decides whether a
// device may receive the certificate it is asking for.
//
// The protocol handlers never call OpenBao with attributes taken straight from
// a CSR. Instead they build a Request, ask an Authorizer for a Decision, and
// pass the Decision's role + constrained parameters to the issuer. This is the
// single chokepoint where "is this device permitted to have this cert?" is
// answered. The real pipeline (mTLS identity mapping, challenge-password
// validation, inventory lookup, CSR constraint policy) is built in Phase 3;
// this file provides the contract and two trivial placeholders.
package authz

import (
	"context"
	"crypto/x509"
	"net/url"
	"time"
)

// Operation identifies the enrollment operation being authorized.
type Operation string

const (
	OpSimpleEnroll   Operation = "simpleenroll"
	OpSimpleReenroll Operation = "simplereenroll"
	OpServerKeyGen   Operation = "serverkeygen"
)

// Request is everything the authorizer needs to make a decision. Fields are
// populated by the protocol handler from the authenticated transport and the
// parsed CSR.
type Request struct {
	Operation Operation
	// ClientCert is the verified mTLS client certificate, or nil if the client
	// presented none. For re-enroll it is the existing device certificate
	// (already verified against the device trust anchor by the handler).
	ClientCert *x509.Certificate
	// CSR is the parsed, signature-verified certificate request.
	CSR *x509.CertificateRequest
	// ChallengePassword is the PKCS#9 challengePassword from the CSR, if present.
	ChallengePassword string
	// Label is the optional EST URI label (/.well-known/est/{label}/...), which
	// a future policy may use to select a role or tenant.
	Label string
	// RemoteAddr is the client's network address, for audit/rate context.
	RemoteAddr string
}

// CertConstraints are the parameters the broker will actually request from
// OpenBao, derived and bounded by policy rather than copied blindly from the
// CSR. Empty slice/zero fields mean "do not send this parameter" (the OpenBao
// role's own configuration then applies).
type CertConstraints struct {
	CommonName        string
	DNSNames          []string
	IPs               []string
	URIs              []string
	TTL               time.Duration
	ExcludeCNFromSANs bool
}

// Decision is the authorizer's answer. When Allow is false the handler must not
// issue; Reason is logged for audit and may be surfaced generically to clients.
type Decision struct {
	Allow       bool
	Role        string // external OpenBao PKI role name to issue under
	Constraints CertConstraints
	Reason      string
}

// Deny is a convenience constructor for a rejection.
func Deny(reason string) Decision { return Decision{Allow: false, Reason: reason} }

// Authorizer decides whether a request may be fulfilled and under what
// constraints. Implementations must be safe for concurrent use and must fail
// closed (return Allow=false, or a non-nil error) on any uncertainty.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, error)
}

// DenyAll rejects everything. It is the safe default so an unconfigured broker
// never issues.
type DenyAll struct{}

func (DenyAll) Authorize(context.Context, Request) (Decision, error) {
	return Deny("no authorizer configured"), nil
}

// AllowAllEcho authorizes every request and echoes the CSR's own subject/SANs
// back as the constraints, issuing under a fixed role.
//
// SECURITY: this performs NO authorization and MUST NOT be used in production.
// It exists only for local development and handler tests until the Phase 3
// policy pipeline replaces it. Guard its selection behind an explicit,
// loudly-logged dev flag in the wiring layer.
type AllowAllEcho struct {
	Role string
}

func (a AllowAllEcho) Authorize(_ context.Context, req Request) (Decision, error) {
	c := CertConstraints{}
	if req.CSR != nil {
		c.CommonName = req.CSR.Subject.CommonName
		c.DNSNames = req.CSR.DNSNames
		c.URIs = urisToStrings(req.CSR.URIs)
		c.IPs = ipsToStrings(req.CSR)
	}
	return Decision{
		Allow:       true,
		Role:        a.Role,
		Constraints: c,
		Reason:      "allow-all-echo (dev only)",
	}, nil
}

func urisToStrings(us []*url.URL) []string {
	if len(us) == 0 {
		return nil
	}
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.String())
	}
	return out
}

func ipsToStrings(csr *x509.CertificateRequest) []string {
	if len(csr.IPAddresses) == 0 {
		return nil
	}
	out := make([]string, 0, len(csr.IPAddresses))
	for _, ip := range csr.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}
