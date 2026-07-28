// Package pkcs7 encodes the certs-only (degenerate) SignedData that EST returns
// for /cacerts and enrollment. Encode only — no parsing, no CMS dependency.
package pkcs7

import (
	"encoding/asn1"
	"errors"
)

var (
	// oidSignedData = 1.2.840.113549.1.7.2
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// oidData = 1.2.840.113549.1.7.1
	oidData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// contentInfo is the outer wrapper. Content is a self-tagged RawValue because
// asn1.Marshal emits RawValues verbatim and would skip a struct tag.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

// signedData is the certs-only form: no digest algorithms, no content, no
// signers. Each RawValue carries its own tag/class.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue // empty SET
	ContentInfo      asn1.RawValue // SEQUENCE { contentType data }
	Certificates     asn1.RawValue // [0] IMPLICIT SET OF Certificate
	SignerInfos      asn1.RawValue // empty SET
}

// emptySet returns the DER for an empty ASN.1 SET (0x31 0x00).
func emptySet() asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true}
}

// DegenerateCertsOnly encodes DER certificates as a certs-only PKCS#7
// SignedData. At least one certificate is required.
func DegenerateCertsOnly(certDER ...[]byte) ([]byte, error) {
	if len(certDER) == 0 {
		return nil, errors.New("pkcs7: at least one certificate is required")
	}

	// certificates [0] IMPLICIT CertificateSet: the concatenated cert DERs.
	var certBytes []byte
	for i, d := range certDER {
		if len(d) == 0 {
			return nil, errors.New("pkcs7: empty certificate at index " + itoa(i))
		}
		certBytes = append(certBytes, d...)
	}
	certs := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      certBytes,
	}

	// Encapsulated ContentInfo: SEQUENCE { contentType data } with no content.
	innerCI, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
	}{oidData})
	if err != nil {
		return nil, err
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: emptySet(),
		ContentInfo:      asn1.RawValue{FullBytes: innerCI},
		Certificates:     certs,
		SignerInfos:      emptySet(),
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}

	outer := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}
	return asn1.Marshal(outer)
}

// itoa is a tiny int-to-string to avoid pulling in strconv for one error path.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
