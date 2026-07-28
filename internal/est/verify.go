package est

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
)

// ttlSlack absorbs OpenBao's NotBefore backdating plus clock skew.
const ttlSlack = time.Hour

// verifyIssued checks the issued cert against what was approved. Names are
// all-or-nothing (see namesConstrained); the TTL cap applies regardless.
func verifyIssued(cert *x509.Certificate, c authz.CertConstraints) error {
	if cert == nil {
		return errors.New("no certificate to verify")
	}

	if namesConstrained(c) {
		if err := verifyNames(cert, c); err != nil {
			return err
		}
	}

	if c.TTL > 0 {
		if lifetime := cert.NotAfter.Sub(cert.NotBefore); lifetime > c.TTL+ttlSlack {
			return fmt.Errorf("issued cert lifetime %v exceeds the authorized TTL %v", lifetime, c.TTL)
		}
	}
	return nil
}

// namesConstrained reports whether the decision bounded the subject at all.
func namesConstrained(c authz.CertConstraints) bool {
	return c.CommonName != "" || len(c.DNSNames) > 0 || len(c.IPs) > 0 || len(c.URIs) > 0
}

func verifyNames(cert *x509.Certificate, c authz.CertConstraints) error {
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
	for _, name := range cert.DNSNames {
		if !containsFold(permittedDNS, name) {
			return fmt.Errorf("issued cert carries unauthorized DNS SAN %q (authorized: %v)",
				name, permittedDNS)
		}
	}
	for _, ip := range cert.IPAddresses {
		if !containsIP(c.IPs, ip) {
			return fmt.Errorf("issued cert carries unauthorized IP SAN %q (authorized: %v)", ip, c.IPs)
		}
	}
	for _, u := range cert.URIs {
		if !containsFold(c.URIs, u.String()) {
			return fmt.Errorf("issued cert carries unauthorized URI SAN %q (authorized: %v)", u, c.URIs)
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
