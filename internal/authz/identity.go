package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Identity is the resolved view of who is making a request and what they are
// asking for. It separates the *authenticated* identity (from a verified mTLS
// client certificate, when present) from the *requested* identity (the subject
// and SANs in the CSR). Policy decisions compare the two.
type Identity struct {
	// Authenticated is true when a verified client certificate was presented
	// (always true for re-enrollment; optional for initial enrollment).
	Authenticated bool

	// Authenticated-certificate attributes (empty when Authenticated is false).
	CommonName  string   // cert subject CN
	OrgUnits    []string // cert subject OU values
	Orgs        []string // cert subject O values
	DNSNames    []string // cert SAN dNSNames
	Serial      string   // cert serial number, lowercase hex
	Fingerprint string   // sha256 of the cert DER, lowercase hex

	// EST URI label (/.well-known/est/{label}/...), if any.
	Label string

	// Requested-from-CSR attributes (what the device wants issued).
	RequestedCN   string
	RequestedDNS  []string
	RequestedIPs  []string
	RequestedURIs []string
}

// resolveIdentity builds an Identity from a request's client certificate and CSR.
func resolveIdentity(req Request) Identity {
	id := Identity{Label: req.Label}

	if c := req.ClientCert; c != nil {
		id.Authenticated = true
		id.CommonName = c.Subject.CommonName
		id.OrgUnits = c.Subject.OrganizationalUnit
		id.Orgs = c.Subject.Organization
		id.DNSNames = c.DNSNames
		id.Serial = strings.ToLower(c.SerialNumber.Text(16))
		fp := sha256.Sum256(c.Raw)
		id.Fingerprint = hex.EncodeToString(fp[:])
	}

	if csr := req.CSR; csr != nil {
		id.RequestedCN = csr.Subject.CommonName
		id.RequestedDNS = csr.DNSNames
		id.RequestedURIs = urisToStrings(csr.URIs)
		id.RequestedIPs = ipsToStrings(csr)
	}
	return id
}
