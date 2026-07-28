// Package authz is the single chokepoint answering "may this device have this
// cert?". Handlers pass a Request, never CSR attributes, to the issuer.
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

// Request is everything the authorizer needs, populated by the protocol handler
// from the authenticated transport and the parsed CSR.
type Request struct {
	Operation Operation
	// ClientCert is the verified mTLS client certificate, or nil if none was
	// presented. Set only after the handler verifies it against a trust anchor.
	ClientCert *x509.Certificate
	// CSR is the parsed, signature-verified certificate request.
	CSR *x509.CertificateRequest
	// ChallengePassword is the PKCS#9 challengePassword from the CSR, if present.
	ChallengePassword string
	// Label is the optional EST URI label (/.well-known/est/{label}/...).
	Label string
	// RemoteAddr is the client's network address, for audit/rate context.
	RemoteAddr string
}

// CertConstraints are what the broker actually requests from OpenBao, bounded by
// policy rather than copied from the CSR. Zero fields = omit, role decides.
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
// constraints. Must be concurrency-safe and fail closed on any uncertainty.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, error)
}

// DenyAll rejects everything. It is the safe default so an unconfigured broker
// never issues.
type DenyAll struct{}

func (DenyAll) Authorize(context.Context, Request) (Decision, error) {
	return Deny("no authorizer configured"), nil
}

// AllowAllEcho authorizes everything, echoing the CSR's own subject/SANs back.
// SECURITY: no authorization whatsoever — dev and tests only.
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
