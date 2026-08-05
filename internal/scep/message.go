// Package scep implements RFC 8894 over internal/cms. Unlike EST it requires the
// broker to hold a key: "no CA key" still holds, "no key at rest" does not.
package scep

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
)

// SCEP attribute OIDs (RFC 8894 §3.2), all under the Verisign arc.
var (
	oidMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidFailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// MessageType identifies the SCEP operation (RFC 8894 §3.2.1.2).
type MessageType string

const (
	// PKCSReq is an initial enrollment request. Its signer certificate is
	// self-signed and authenticates NOTHING.
	PKCSReq MessageType = "19"
	// RenewalReq renews an existing certificate; its signer is that certificate.
	RenewalReq MessageType = "17"
	// CertRep is the server's response.
	CertRep MessageType = "3"
	// GetCertInitial polls a pending request. Unsupported: issuance here is
	// synchronous, so nothing is ever PENDING.
	GetCertInitial MessageType = "20"
	// GetCert and GetCRL retrieve an existing certificate or CRL. Unsupported.
	GetCert MessageType = "21"
	GetCRL  MessageType = "22"
)

// Valid reports whether m is a message type the broker accepts from a client.
func (m MessageType) Valid() bool {
	switch m {
	case PKCSReq, RenewalReq:
		return true
	default:
		return false
	}
}

func (m MessageType) String() string {
	switch m {
	case PKCSReq:
		return "PKCSReq"
	case RenewalReq:
		return "RenewalReq"
	case CertRep:
		return "CertRep"
	case GetCertInitial:
		return "GetCertInitial"
	case GetCert:
		return "GetCert"
	case GetCRL:
		return "GetCRL"
	default:
		return "unknown(" + string(m) + ")"
	}
}

// PKIStatus is the outcome carried in a CertRep (RFC 8894 §3.2.1.3).
type PKIStatus string

const (
	StatusSuccess PKIStatus = "0"
	StatusFailure PKIStatus = "2"
	StatusPending PKIStatus = "3"
)

// FailInfo explains a StatusFailure (RFC 8894 §3.2.1.4). The vocabulary is
// deliberately coarse — it must not become an oracle for probing policy.
type FailInfo string

const (
	// FailBadAlg means an unrecognised or disallowed algorithm.
	FailBadAlg FailInfo = "0"
	// FailBadMessageCheck means the signature or integrity check failed.
	FailBadMessageCheck FailInfo = "1"
	// FailBadRequest is the catch-all for every authorization denial, so a client
	// cannot tell "unknown device" from "wrong name" from "bad challenge".
	FailBadRequest FailInfo = "2"
	// FailBadTime means the signing time was out of range.
	FailBadTime FailInfo = "3"
	// FailBadCertID means the requested certificate could not be identified.
	FailBadCertID FailInfo = "4"
)

// Nonce is a 16-octet replay-detection value (RFC 8894 §3.2.1.5).
type Nonce []byte

// nonceLen is the size RFC 8894 mandates.
const nonceLen = 16

// TransactionID ties a request to its response and keys the replay cache.
type TransactionID string

// maxTransactionIDLen bounds the identifier before it reaches the replay cache,
// so an attacker cannot store megabytes per request.
const maxTransactionIDLen = 128

// Attributes are the authenticated attributes carried by a SCEP message.
type Attributes struct {
	MessageType    MessageType
	TransactionID  TransactionID
	SenderNonce    Nonce
	RecipientNonce Nonce
	PKIStatus      PKIStatus
	FailInfo       FailInfo
}

// attributeReader is the subset of cms.Signed needed to read attributes,
// declared here so this file does not depend on the parse path's concrete type.
type attributeReader interface {
	UnmarshalAttribute(oid asn1.ObjectIdentifier, out any) error
}

// parseAttributes extracts and validates the request attributes. Every field a
// request must carry is checked here, before any expensive work downstream.
func parseAttributes(r attributeReader) (*Attributes, error) {
	var a Attributes

	var mt string
	if err := r.UnmarshalAttribute(oidMessageType, &mt); err != nil {
		return nil, errors.New("scep: missing messageType attribute")
	}
	a.MessageType = MessageType(mt)
	if !a.MessageType.Valid() {
		return nil, fmt.Errorf("scep: unsupported messageType %s", a.MessageType)
	}

	var txID string
	if err := r.UnmarshalAttribute(oidTransactionID, &txID); err != nil {
		return nil, errors.New("scep: missing transactionID attribute")
	}
	if txID == "" {
		return nil, errors.New("scep: empty transactionID")
	}
	if len(txID) > maxTransactionIDLen {
		return nil, fmt.Errorf("scep: transactionID exceeds %d bytes", maxTransactionIDLen)
	}
	a.TransactionID = TransactionID(txID)

	var nonce []byte
	if err := r.UnmarshalAttribute(oidSenderNonce, &nonce); err != nil {
		return nil, errors.New("scep: missing senderNonce attribute")
	}
	// A short nonce weakens replay detection; a long one is a storage vector.
	if len(nonce) != nonceLen {
		return nil, fmt.Errorf("scep: senderNonce is %d bytes, want %d", len(nonce), nonceLen)
	}
	a.SenderNonce = nonce

	return &a, nil
}

// randomNonce generates a fresh 16-octet nonce.
func randomNonce() (Nonce, error) {
	n := make([]byte, nonceLen)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}
