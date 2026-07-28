package authz

import (
	"fmt"
	"time"
)

// SAN constraint modes.
const (
	// SANModeIdentity derives names from the authenticated identity, falling back
	// to the inventory allowlist for unauthenticated bootstrap. The safe default.
	SANModeIdentity = "identity"
	// SANModeAllowlist permits only names matched by the inventory record's
	// AllowedDNSNames, regardless of authentication.
	SANModeAllowlist = "allowlist"
	// SANModeCSR trusts the CSR's requested names as-is (still TTL-capped).
	// Least safe; intended for controlled/dev environments.
	SANModeCSR = "csr"
)

// ConstraintBuilder turns an identity + inventory record into the bounded
// parameters requested from OpenBao. An error denies the request.
type ConstraintBuilder interface {
	Build(id Identity, rec Record) (CertConstraints, error)
}

// StandardConstraints implements ConstraintBuilder for the supported SAN modes,
// applying a maximum validity cap in all modes.
type StandardConstraints struct {
	Mode        string
	MaxValidity time.Duration
}

// NewStandardConstraints builds a StandardConstraints, defaulting the mode to
// SANModeIdentity.
func NewStandardConstraints(mode string, maxValidity time.Duration) *StandardConstraints {
	if mode == "" {
		mode = SANModeIdentity
	}
	return &StandardConstraints{Mode: mode, MaxValidity: maxValidity}
}

// Build implements ConstraintBuilder.
func (b *StandardConstraints) Build(id Identity, rec Record) (CertConstraints, error) {
	c, err := b.build(id, rec)
	if err != nil {
		return CertConstraints{}, err
	}
	// Reachable from a CSR with neither CN nor SANs, whose emptiness satisfies
	// every check vacuously — leaving the subject entirely to the role.
	if c.CommonName == "" && len(c.DNSNames) == 0 && len(c.IPs) == 0 && len(c.URIs) == 0 {
		return CertConstraints{}, fmt.Errorf("request names no subject")
	}
	return c, nil
}

func (b *StandardConstraints) build(id Identity, rec Record) (CertConstraints, error) {
	c := CertConstraints{TTL: b.MaxValidity}

	switch b.Mode {
	case SANModeCSR:
		c.CommonName = id.RequestedCN
		c.DNSNames = id.RequestedDNS
		c.IPs = id.RequestedIPs
		c.URIs = id.RequestedURIs
		return c, nil

	case SANModeAllowlist:
		return b.allowlist(id, rec)

	case SANModeIdentity:
		if id.Authenticated {
			return b.fromAuthenticatedIdentity(id)
		}
		// Unauthenticated bootstrap: fall back to the inventory allowlist.
		return b.allowlist(id, rec)

	default:
		return CertConstraints{}, fmt.Errorf("unknown SAN constraint mode %q", b.Mode)
	}
}

// fromAuthenticatedIdentity pins issued names to the authenticated cert: a
// device may re-key but not rename itself. This is identity continuity.
func (b *StandardConstraints) fromAuthenticatedIdentity(id Identity) (CertConstraints, error) {
	permitted := append([]string{id.CommonName}, id.DNSNames...)

	if id.RequestedCN != "" && !allAllowed([]string{id.RequestedCN}, permitted) {
		return CertConstraints{}, fmt.Errorf("requested CN %q is not part of the authenticated identity", id.RequestedCN)
	}
	if !allAllowed(id.RequestedDNS, permitted) {
		return CertConstraints{}, fmt.Errorf("requested SANs exceed the authenticated identity")
	}
	// IP/URI SANs are not part of the authenticated identity here; refuse them
	// in identity mode rather than silently dropping.
	if len(id.RequestedIPs) > 0 || len(id.RequestedURIs) > 0 {
		return CertConstraints{}, fmt.Errorf("IP/URI SANs are not permitted in identity mode")
	}

	c := CertConstraints{TTL: b.MaxValidity, CommonName: id.CommonName}
	if len(id.RequestedDNS) > 0 {
		c.DNSNames = id.RequestedDNS // device may narrow to a subset
	} else {
		c.DNSNames = id.DNSNames
	}
	return c, nil
}

// allowlist permits only names matched by the inventory record's allowlist.
func (b *StandardConstraints) allowlist(id Identity, rec Record) (CertConstraints, error) {
	if len(rec.AllowedDNSNames) == 0 {
		return CertConstraints{}, fmt.Errorf("no allowed names for this device")
	}
	if id.RequestedCN != "" && !allAllowed([]string{id.RequestedCN}, rec.AllowedDNSNames) {
		return CertConstraints{}, fmt.Errorf("requested CN %q is not allowed for this device", id.RequestedCN)
	}
	if !allAllowed(id.RequestedDNS, rec.AllowedDNSNames) {
		return CertConstraints{}, fmt.Errorf("requested SANs are not allowed for this device")
	}
	if len(id.RequestedIPs) > 0 || len(id.RequestedURIs) > 0 {
		return CertConstraints{}, fmt.Errorf("IP/URI SANs are not permitted in allowlist mode")
	}
	return CertConstraints{
		TTL:        b.MaxValidity,
		CommonName: id.RequestedCN,
		DNSNames:   id.RequestedDNS,
	}, nil
}
