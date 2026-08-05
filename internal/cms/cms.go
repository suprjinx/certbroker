// Package cms wraps smallstep/pkcs7 for SCEP: it enforces an algorithm
// allowlist and separates "signature intact" from "signer trusted".
package cms

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/smallstep/pkcs7"
)

// The library picks content encryption from a global defaulting to DES-CBC.
// Set once here: there is no per-call option and mutating it later would race.
func init() {
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
}

// ErrAlgorithmNotPermitted is returned when a message uses a digest outside the
// configured allowlist.
var ErrAlgorithmNotPermitted = errors.New("cms: digest algorithm not permitted")

// Digest OIDs, named so callers configure an allowlist without importing asn1.
var (
	SHA1   = pkcs7.OIDDigestAlgorithmSHA1
	SHA256 = pkcs7.OIDDigestAlgorithmSHA256
	SHA384 = pkcs7.OIDDigestAlgorithmSHA384
	SHA512 = pkcs7.OIDDigestAlgorithmSHA512
)

// DefaultDigests excludes SHA-1: it is collision-broken, so admitting it must
// be a recorded decision rather than a default.
var DefaultDigests = []asn1.ObjectIdentifier{SHA256, SHA384, SHA512}

// Verifier checks CMS SignedData against an algorithm allowlist.
type Verifier struct {
	// Digests permits these digest algorithms; empty means DefaultDigests.
	Digests []asn1.ObjectIdentifier
}

// Signed is a parsed, signature-verified CMS SignedData.
type Signed struct {
	// Content is the encapsulated payload.
	Content []byte
	// Signer is the certificate whose signature was verified. Whether that
	// certificate means anything depends on which verify call produced it.
	Signer *x509.Certificate
	// Chained is true when the signer was verified against a trust anchor.
	Chained bool

	p7 *pkcs7.PKCS7
}

// UnmarshalAttribute decodes an authenticated attribute into out. Only
// attributes covered by the verified signature are readable.
func (s *Signed) UnmarshalAttribute(oid asn1.ObjectIdentifier, out any) error {
	if s.p7 == nil {
		return errors.New("cms: no parsed message")
	}
	return s.p7.UnmarshalSignedAttribute(oid, out)
}

// VerifySignature checks the signature is intact but establishes NO trust — the
// signer may be self-signed. Correct for a PKCSReq; the Signer is not an identity.
func (v *Verifier) VerifySignature(der []byte) (*Signed, error) {
	p7, err := v.parse(der)
	if err != nil {
		return nil, err
	}
	if err := p7.Verify(); err != nil {
		return nil, fmt.Errorf("cms: signature verification failed: %w", err)
	}
	return v.signed(p7, false)
}

// VerifyChain also verifies the signer against roots, so an accepted signer IS
// an identity. Correct for a RenewalReq, whose signer is the device cert.
func (v *Verifier) VerifyChain(der []byte, roots *x509.CertPool) (*Signed, error) {
	if roots == nil {
		return nil, errors.New("cms: no trust anchor configured for this operation")
	}
	p7, err := v.parse(der)
	if err != nil {
		return nil, err
	}
	if err := p7.VerifyWithChain(roots); err != nil {
		return nil, fmt.Errorf("cms: signature or chain verification failed: %w", err)
	}
	return v.signed(p7, true)
}

// parse decodes the message and applies the algorithm allowlist before any
// signature is checked, so an unwanted algorithm costs nothing to reject.
func (v *Verifier) parse(der []byte) (*pkcs7.PKCS7, error) {
	if len(der) == 0 {
		return nil, errors.New("cms: empty message")
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("cms: parse: %w", err)
	}
	if len(p7.Signers) == 0 {
		return nil, errors.New("cms: message has no signers")
	}
	// Exactly one signer. SCEP defines a single signer per message, and
	// tolerating more invites confusion over which one was authenticated.
	if len(p7.Signers) > 1 {
		return nil, fmt.Errorf("cms: expected 1 signer, got %d", len(p7.Signers))
	}
	if err := v.checkDigest(p7.Signers[0].DigestAlgorithm.Algorithm); err != nil {
		return nil, err
	}
	return p7, nil
}

func (v *Verifier) checkDigest(oid asn1.ObjectIdentifier) error {
	allowed := v.Digests
	if len(allowed) == 0 {
		allowed = DefaultDigests
	}
	for _, a := range allowed {
		if a.Equal(oid) {
			return nil
		}
	}
	return fmt.Errorf("%w: %v", ErrAlgorithmNotPermitted, oid)
}

func (v *Verifier) signed(p7 *pkcs7.PKCS7, chained bool) (*Signed, error) {
	signer := p7.GetOnlySigner()
	if signer == nil {
		return nil, errors.New("cms: no signer certificate in message")
	}
	return &Signed{Content: p7.Content, Signer: signer, Chained: chained, p7: p7}, nil
}

// Decrypt opens an EnvelopedData addressed to cert. Runs an RSA private-key
// operation on unauthenticated input: callers must rate-limit and size-bound it.
func Decrypt(der []byte, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	if len(der) == 0 {
		return nil, errors.New("cms: empty enveloped message")
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("cms: parse enveloped: %w", err)
	}
	content, err := p7.Decrypt(cert, key)
	if err != nil {
		// Deliberately unwrapped: decryption failure detail is a padding-oracle
		// hint, so callers get an opaque error and log the cause themselves.
		return nil, errors.New("cms: decryption failed")
	}
	return content, nil
}

// Encrypt seals content to a single recipient as EnvelopedData, using the
// content-encryption algorithm pinned in init.
func Encrypt(content []byte, recipient *x509.Certificate) ([]byte, error) {
	if recipient == nil {
		return nil, errors.New("cms: no recipient certificate")
	}
	der, err := pkcs7.Encrypt(content, []*x509.Certificate{recipient})
	if err != nil {
		return nil, fmt.Errorf("cms: encrypt: %w", err)
	}
	return der, nil
}

// SignOptions configures Sign.
type SignOptions struct {
	// Attributes are authenticated attributes to embed (SCEP message type,
	// transaction ID, nonces).
	Attributes []Attribute
	// Digest selects the digest algorithm; zero uses SHA-256.
	Digest asn1.ObjectIdentifier
}

// Attribute is an authenticated attribute carried in the signature.
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value any
}

// Sign wraps content in SignedData signed by cert/key.
func Sign(content []byte, cert *x509.Certificate, key crypto.PrivateKey, opts SignOptions) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("cms: no signing certificate")
	}
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("cms: new signed data: %w", err)
	}
	digest := opts.Digest
	if digest == nil {
		digest = SHA256
	}
	sd.SetDigestAlgorithm(digest)

	attrs := make([]pkcs7.Attribute, 0, len(opts.Attributes))
	for _, a := range opts.Attributes {
		attrs = append(attrs, pkcs7.Attribute{Type: a.Type, Value: a.Value})
	}
	cfg := pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}
	if err := sd.AddSigner(cert, key, cfg); err != nil {
		return nil, fmt.Errorf("cms: add signer: %w", err)
	}
	der, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("cms: finish: %w", err)
	}
	return der, nil
}

// DegenerateCertsOnly encodes certificates as a certs-only SignedData, the form
// SCEP GetCACert uses to carry the RA and CA certificates together.
func DegenerateCertsOnly(certs ...*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("cms: at least one certificate is required")
	}
	var der []byte
	for _, c := range certs {
		der = append(der, c.Raw...)
	}
	out, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cms: degenerate: %w", err)
	}
	return out, nil
}
