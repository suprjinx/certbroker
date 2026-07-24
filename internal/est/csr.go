package est

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// oidChallengePassword is the PKCS#9 challengePassword attribute (1.2.840.113549.1.9.7).
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// ParseCSR decodes a DER PKCS#10 request and verifies its self-signature, which
// is the proof-of-possession that the requester holds the private key. Go's
// x509.ParseCertificateRequest does NOT check the signature, so we do it here.
func ParseCSR(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR proof-of-possession failed: %w", err)
	}
	return csr, nil
}

// KeyType returns a normalized token describing the CSR's public key, e.g.
// "rsa-2048", "ec-p256", "ed25519". Unknown types yield an error.
func KeyType(csr *x509.CertificateRequest) (string, error) {
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", pub.N.BitLen()), nil
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return "ec-p256", nil
		case elliptic.P384():
			return "ec-p384", nil
		case elliptic.P521():
			return "ec-p521", nil
		default:
			return "", fmt.Errorf("unsupported EC curve %q", pub.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		return "ed25519", nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}

// ValidateKeyType checks the CSR's key against an allowlist of normalized
// tokens. An empty allowlist permits any recognized key type (the Phase 3
// policy engine tightens this per identity). Unrecognized key types are always
// rejected.
func ValidateKeyType(csr *x509.CertificateRequest, allowed []string) error {
	kt, err := KeyType(csr)
	if err != nil {
		return err
	}
	if len(allowed) == 0 {
		return nil
	}
	for _, a := range allowed {
		if a == kt {
			return nil
		}
	}
	return fmt.Errorf("key type %q is not permitted", kt)
}

// tbsCSR mirrors CertificationRequestInfo enough to reach the attributes.
type tbsCSR struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes []csrAttribute `asn1:"tag:0,optional,set"`
}

// csrAttribute is a PKCS#9 Attribute: an OID plus a SET OF values.
type csrAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// ChallengePassword extracts the PKCS#9 challengePassword attribute from a CSR,
// returning "" when absent. Go's high-level CertificateRequest drops CSR
// attributes, so we re-parse the raw CertificationRequestInfo.
func ChallengePassword(csr *x509.CertificateRequest) (string, error) {
	if len(csr.RawTBSCertificateRequest) == 0 {
		return "", nil
	}
	var tbs tbsCSR
	if _, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &tbs); err != nil {
		return "", fmt.Errorf("parse CSR attributes: %w", err)
	}
	for _, attr := range tbs.Attributes {
		if !attr.Type.Equal(oidChallengePassword) {
			continue
		}
		// Values is a SET OF DirectoryString; take the first value's content.
		var v asn1.RawValue
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &v); err != nil {
			return "", fmt.Errorf("parse challengePassword value: %w", err)
		}
		if len(v.Bytes) == 0 {
			return "", errors.New("empty challengePassword")
		}
		// The content octets are the string bytes for PrintableString /
		// UTF8String / IA5String, which is what clients use in practice.
		return string(v.Bytes), nil
	}
	return "", nil
}
