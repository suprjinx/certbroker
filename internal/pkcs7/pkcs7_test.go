package pkcs7

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
)

// selfSigned generates a throwaway self-signed cert and returns its DER.
func selfSigned(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	return der
}

// parseContentInfo decodes the outer ContentInfo and returns the SignedData raw.
func parseContentInfo(t *testing.T, der []byte) signedData {
	t.Helper()
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		t.Fatalf("unmarshal contentInfo: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after contentInfo: %d", len(rest))
	}
	if !ci.ContentType.Equal(oidSignedData) {
		t.Fatalf("contentType = %v, want signedData", ci.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal signedData: %v", err)
	}
	return sd
}

// extractCerts pulls the concatenated certificate DERs out of the [0] IMPLICIT set.
func extractCerts(t *testing.T, sd signedData) [][]byte {
	t.Helper()
	var out [][]byte
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			t.Fatalf("unmarshal cert: %v", err)
		}
		out = append(out, raw.FullBytes)
	}
	return out
}

func TestDegenerateSingleCert(t *testing.T) {
	certDER := selfSigned(t, "device01")

	p7, err := DegenerateCertsOnly(certDER)
	if err != nil {
		t.Fatalf("DegenerateCertsOnly: %v", err)
	}

	sd := parseContentInfo(t, p7)
	if sd.Version != 1 {
		t.Errorf("version = %d, want 1", sd.Version)
	}
	certs := extractCerts(t, sd)
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	parsed, err := x509.ParseCertificate(certs[0])
	if err != nil {
		t.Fatalf("reparse embedded cert: %v", err)
	}
	if parsed.Subject.CommonName != "device01" {
		t.Errorf("CN = %q, want device01", parsed.Subject.CommonName)
	}
}

func TestDegenerateMultipleCerts(t *testing.T) {
	a := selfSigned(t, "leaf")
	b := selfSigned(t, "ca")

	p7, err := DegenerateCertsOnly(a, b)
	if err != nil {
		t.Fatalf("DegenerateCertsOnly: %v", err)
	}
	sd := parseContentInfo(t, p7)
	certs := extractCerts(t, sd)
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	// Order must be preserved.
	names := []string{"leaf", "ca"}
	for i, c := range certs {
		parsed, err := x509.ParseCertificate(c)
		if err != nil {
			t.Fatalf("reparse cert %d: %v", i, err)
		}
		if parsed.Subject.CommonName != names[i] {
			t.Errorf("cert %d CN = %q, want %q", i, parsed.Subject.CommonName, names[i])
		}
	}
}

func TestDegenerateEmpty(t *testing.T) {
	if _, err := DegenerateCertsOnly(); err == nil {
		t.Fatal("expected error for zero certs")
	}
	if _, err := DegenerateCertsOnly([]byte{}); err == nil {
		t.Fatal("expected error for empty cert")
	}
}
