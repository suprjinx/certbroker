package est

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
)

// ttlSlack absorbs the backdating OpenBao applies to NotBefore (30s by default)
// plus clock skew, so a correctly-issued certificate is not flagged.
const ttlSlack = time.Hour

// verifyIssued checks that the certificate OpenBao returned stays within the
// constraints the authorizer approved.
//
// This is not paranoia about OpenBao; it closes a real gap. OpenBao's PKI roles
// default to use_csr_sans=true and use_csr_common_name=true, which make the
// CSR's own subject and SANs *merge with* the parameters the broker sends
// rather than being replaced by them. Under such a role a device authorized for
// one name can obtain any additional name the role's allowed_domains permits,
// simply by putting it in the CSR — silently defeating the constraint policy.
//
// Roles are externally managed and opaque to the broker (it cannot read or fix
// them), so the broker verifies the result instead. A violation means the role
// is misconfigured: it must be reported loudly, and the certificate must not be
// handed to the client.
//
// Constraints left empty mean policy chose not to bound that field and the
// role's own configuration applies; those fields are not checked.
func verifyIssued(cert *x509.Certificate, c authz.CertConstraints) error {
	if cert == nil {
		return fmt.Errorf("no certificate to verify")
	}

	// Compared case-insensitively, like the SANs: a CN carrying a hostname is a
	// DNS name, and a CA that normalizes its case has not issued a different
	// name. Exact comparison here would reject correct certificates.
	if c.CommonName != "" && !equalFoldASCII(cert.Subject.CommonName, c.CommonName) {
		return fmt.Errorf("issued CN %q does not match the authorized CN %q",
			cert.Subject.CommonName, c.CommonName)
	}

	// The CN is legitimately mirrored into the SANs unless the broker asked for
	// it to be excluded, so it joins the permitted set.
	permittedDNS := c.DNSNames
	if c.CommonName != "" && !c.ExcludeCNFromSANs {
		permittedDNS = append(append([]string{}, c.DNSNames...), c.CommonName)
	}
	if len(permittedDNS) > 0 {
		for _, name := range cert.DNSNames {
			if !containsFold(permittedDNS, name) {
				return fmt.Errorf("issued cert carries unauthorized DNS SAN %q (authorized: %v)",
					name, permittedDNS)
			}
		}
	} else if len(cert.DNSNames) > 0 && c.CommonName != "" {
		// Policy pinned a CN and authorized no SANs, yet SANs came back.
		return fmt.Errorf("issued cert carries DNS SANs %v but none were authorized", cert.DNSNames)
	}

	if len(c.IPs) > 0 {
		for _, ip := range cert.IPAddresses {
			if !containsIP(c.IPs, ip) {
				return fmt.Errorf("issued cert carries unauthorized IP SAN %q", ip)
			}
		}
	} else if len(cert.IPAddresses) > 0 {
		return fmt.Errorf("issued cert carries IP SANs %v but none were authorized", cert.IPAddresses)
	}

	if len(c.URIs) > 0 {
		for _, u := range cert.URIs {
			if !containsFold(c.URIs, u.String()) {
				return fmt.Errorf("issued cert carries unauthorized URI SAN %q", u)
			}
		}
	} else if len(cert.URIs) > 0 {
		return fmt.Errorf("issued cert carries URI SANs %v but none were authorized", cert.URIs)
	}

	if c.TTL > 0 {
		if lifetime := cert.NotAfter.Sub(cert.NotBefore); lifetime > c.TTL+ttlSlack {
			return fmt.Errorf("issued cert lifetime %v exceeds the authorized TTL %v", lifetime, c.TTL)
		}
	}

	return nil
}

// containsFold reports whether want is in list, case-insensitively. DNS names
// are case-insensitive, and a case-flipped name would otherwise slip through.
func containsFold(list []string, want string) bool {
	for _, v := range list {
		if equalFoldASCII(v, want) {
			return true
		}
	}
	return false
}

// equalFoldASCII is strings.EqualFold restricted to ASCII, which is all DNS
// names and URI schemes need and avoids Unicode case-folding surprises.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func containsIP(list []string, want net.IP) bool {
	for _, v := range list {
		if parsed := net.ParseIP(v); parsed != nil && parsed.Equal(want) {
			return true
		}
	}
	return false
}
