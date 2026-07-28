package est

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
)

// ttlSlack absorbs OpenBao's NotBefore backdating plus clock skew.
const ttlSlack = time.Hour

// verifyIssued checks the issued cert against what was approved, catching roles
// whose use_csr_* defaults re-add the CSR's names. Empty = unchecked.
func verifyIssued(cert *x509.Certificate, c authz.CertConstraints) error {
	if cert == nil {
		return fmt.Errorf("no certificate to verify")
	}

	// Case-insensitive like the SANs: a CN carrying a hostname is a DNS name, and
	// a CA that normalizes its case has not issued a different name.
	if c.CommonName != "" && !equalFoldASCII(cert.Subject.CommonName, c.CommonName) {
		return fmt.Errorf("issued CN %q does not match the authorized CN %q",
			cert.Subject.CommonName, c.CommonName)
	}

	// OpenBao mirrors the CN into the SANs unless told not to, so it is permitted.
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

// containsFold reports whether want is in list, case-insensitively, so a
// case-flipped name does not slip through.
func containsFold(list []string, want string) bool {
	for _, v := range list {
		if equalFoldASCII(v, want) {
			return true
		}
	}
	return false
}

// equalFoldASCII is strings.EqualFold restricted to ASCII — enough for DNS
// names and URI schemes, without Unicode case-folding surprises.
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
