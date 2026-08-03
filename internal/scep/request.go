package scep

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/gr-oss/certbroker/internal/cms"
)

// Request is a parsed, verified SCEP PKIOperation.
type Request struct {
	Attributes *Attributes
	// CSR is the PKCS#10 recovered from the envelope, signature-verified.
	CSR *x509.CertificateRequest
	// Signer is the certificate that signed the outer SignedData.
	Signer *x509.Certificate
	// SignerAuthenticated is true ONLY when Signer verified against the device
	// trust anchor — a RenewalReq. For a PKCSReq it is always false, because
	// that signer is self-signed and proves nothing beyond key possession.
	SignerAuthenticated bool
}

// Parser turns a PKIOperation body into a Request.
type Parser struct {
	// RAKey and RACert decrypt the envelope addressed to the broker.
	RACert *x509.Certificate
	RAKey  crypto.PrivateKey
	// DeviceRoots verifies a RenewalReq signer. Nil makes renewal impossible,
	// which is the correct failure when no anchor is configured.
	DeviceRoots *x509.CertPool
	// Verifier carries the digest allowlist.
	Verifier cms.Verifier
	// ParseCSR validates the recovered PKCS#10, including proof-of-possession
	// and key bounds. Required.
	ParseCSR func(der []byte) (*x509.CertificateRequest, error)
}

// Parse verifies and decodes a PKIOperation body.
//
// Order matters and is defensive: the outer signature is checked before the
// envelope is decrypted, so an unauthenticated caller cannot make the broker
// perform an RSA private-key operation without first producing a well-formed
// signed message.
func (p *Parser) Parse(der []byte) (*Request, error) {
	if p.ParseCSR == nil {
		return nil, errors.New("scep: no CSR parser configured")
	}
	if p.RACert == nil || p.RAKey == nil {
		return nil, errors.New("scep: no RA identity configured")
	}

	// 1. Verify the outer signature WITHOUT establishing trust. Whether the
	//    signer means anything is decided in step 3, by message type.
	signed, err := p.Verifier.VerifySignature(der)
	if err != nil {
		return nil, err
	}

	// 2. Attributes, including the message type that drives the next step.
	attrs, err := parseAttributes(signed)
	if err != nil {
		return nil, err
	}

	// 3. Establish what the signer actually proves.
	//
	// SECURITY: a PKCSReq signer is self-signed by definition (RFC 8894 §3.1).
	// It stays unauthenticated, and the caller must not populate
	// authz.Request.ClientCert from it — doing so would let a device pin issued
	// names to a certificate it minted itself.
	authenticated := false
	if attrs.MessageType == RenewalReq {
		// A renewal signer is the device's current certificate and must chain
		// to the device anchor. Re-verify the whole message against it rather
		// than trusting the earlier signature-only pass.
		chained, err := p.Verifier.VerifyChain(der, p.DeviceRoots)
		if err != nil {
			return nil, fmt.Errorf("scep: renewal signer not trusted: %w", err)
		}
		signed = chained
		authenticated = true
	}

	// 4. Decrypt the pkcsPKIEnvelope addressed to the RA.
	csrDER, err := cms.Decrypt(signed.Content, p.RACert, p.RAKey)
	if err != nil {
		return nil, err
	}

	// 5. Parse the CSR, which checks proof-of-possession and key bounds.
	csr, err := p.ParseCSR(csrDER)
	if err != nil {
		return nil, fmt.Errorf("scep: %w", err)
	}

	return &Request{
		Attributes:          attrs,
		CSR:                 csr,
		Signer:              signed.Signer,
		SignerAuthenticated: authenticated,
	}, nil
}

// Responder builds signed CertRep messages.
type Responder struct {
	RACert *x509.Certificate
	RAKey  crypto.PrivateKey
	// NewNonce supplies the server's senderNonce; nil uses crypto/rand.
	NewNonce func() (Nonce, error)
}

// Success builds a CertRep carrying the issued certificate, encrypted to the
// requester's public key and signed by the RA.
func (r *Responder) Success(req *Request, issued *x509.Certificate) ([]byte, error) {
	if issued == nil {
		return nil, errors.New("scep: no certificate to return")
	}
	// The degenerate certs-only SignedData is the payload SCEP expects.
	certsOnly, err := cms.DegenerateCertsOnly(issued)
	if err != nil {
		return nil, err
	}
	// Encrypted to the requester's own certificate: for a PKCSReq that is the
	// self-signed one, which is exactly right — only the holder of that key can
	// open the reply, so an attacker who replays a request cannot read it.
	enveloped, err := cms.Encrypt(certsOnly, req.Signer)
	if err != nil {
		return nil, err
	}
	return r.sign(req, enveloped, StatusSuccess, "")
}

// Failure builds a CertRep reporting refusal. The payload is empty: a failure
// carries no certificate and must not carry detail either.
func (r *Responder) Failure(req *Request, info FailInfo) ([]byte, error) {
	return r.sign(req, nil, StatusFailure, info)
}

func (r *Responder) sign(req *Request, content []byte, status PKIStatus, info FailInfo) ([]byte, error) {
	if r.RACert == nil || r.RAKey == nil {
		return nil, errors.New("scep: no RA identity configured")
	}
	newNonce := r.NewNonce
	if newNonce == nil {
		newNonce = randomNonce
	}
	sender, err := newNonce()
	if err != nil {
		return nil, fmt.Errorf("scep: nonce: %w", err)
	}

	attrs := []cms.Attribute{
		{Type: oidMessageType, Value: string(CertRep)},
		{Type: oidPKIStatus, Value: string(status)},
		{Type: oidTransactionID, Value: string(req.Attributes.TransactionID)},
		{Type: oidSenderNonce, Value: []byte(sender)},
		// Echoing the request's senderNonce is what lets the client tie this
		// response to its own request rather than an injected one.
		{Type: oidRecipientNonce, Value: []byte(req.Attributes.SenderNonce)},
	}
	if status == StatusFailure {
		attrs = append(attrs, cms.Attribute{Type: oidFailInfo, Value: string(info)})
	}

	return cms.Sign(content, r.RACert, r.RAKey, cms.SignOptions{Attributes: attrs})
}
