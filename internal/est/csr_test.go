package est

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

// csrWithChallengePassword is an EC P-256 CSR for CN=device42.example.com
// carrying challengePassword=s3cr3t-otp (generated with openssl).
const csrWithChallengePassword = `-----BEGIN CERTIFICATE REQUEST-----
MIH1MIGcAgEAMB8xHTAbBgNVBAMMFGRldmljZTQyLmV4YW1wbGUuY29tMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAESaLX46mTqI52nP/CvZQDM+VWy5uPHm28L8Wn
llAZZ+T9dl+M21HSjlfHsSuQFjjKWvXdZqmilszjYfzj7G0r/6AbMBkGCSqGSIb3
DQEJBzEMDApzM2NyM3Qtb3RwMAoGCCqGSM49BAMCA0gAMEUCIQCTaC02ec/LiqFl
bKOFQoqX3lTzYd1aHcwvT1yU/SdwtgIgQj3C819S16UN+u/rcjeFRX6TYsemdmr2
FrbRaYs63u0=
-----END CERTIFICATE REQUEST-----`

func decodePEMCSR(t *testing.T, p string) []byte {
	t.Helper()
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		t.Fatal("no PEM block")
	}
	return blk.Bytes
}

// makeCSR builds a fresh EC CSR and returns its DER.
func makeCSR(t *testing.T, cn string, dns ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dns,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("createcsr: %v", err)
	}
	return der
}

func TestParseCSRAndPoP(t *testing.T) {
	der := makeCSR(t, "device01.example.com", "device01.example.com")
	csr, err := ParseCSR(der)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	if csr.Subject.CommonName != "device01.example.com" {
		t.Errorf("CN = %q", csr.Subject.CommonName)
	}
}

func TestParseCSRBadSignature(t *testing.T) {
	der := makeCSR(t, "device01.example.com")
	// Flip a byte in the signature region (end of the DER) to break PoP.
	corrupt := make([]byte, len(der))
	copy(corrupt, der)
	corrupt[len(corrupt)-1] ^= 0xFF
	if _, err := ParseCSR(corrupt); err == nil {
		t.Fatal("expected PoP failure on corrupted CSR")
	}
}

func TestKeyType(t *testing.T) {
	der := makeCSR(t, "device01.example.com")
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	kt, err := KeyType(csr)
	if err != nil {
		t.Fatal(err)
	}
	if kt != "ec-p256" {
		t.Errorf("KeyType = %q, want ec-p256", kt)
	}
}

func TestValidateKeyType(t *testing.T) {
	der := makeCSR(t, "device01.example.com")
	csr, _ := x509.ParseCertificateRequest(der)

	if err := ValidateKeyType(csr, nil); err != nil {
		t.Errorf("empty allowlist should permit: %v", err)
	}
	if err := ValidateKeyType(csr, []string{"ec-p256", "rsa-2048"}); err != nil {
		t.Errorf("ec-p256 should be permitted: %v", err)
	}
	if err := ValidateKeyType(csr, []string{"rsa-2048"}); err == nil {
		t.Error("ec-p256 should be rejected when not in allowlist")
	}
}

func TestChallengePasswordPresent(t *testing.T) {
	der := decodePEMCSR(t, csrWithChallengePassword)
	csr, err := ParseCSR(der)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	cp, err := ChallengePassword(csr)
	if err != nil {
		t.Fatalf("ChallengePassword: %v", err)
	}
	if cp != "s3cr3t-otp" {
		t.Errorf("challengePassword = %q, want s3cr3t-otp", cp)
	}
}

func TestChallengePasswordAbsent(t *testing.T) {
	der := makeCSR(t, "device01.example.com", "device01.example.com")
	csr, _ := ParseCSR(der)
	cp, err := ChallengePassword(csr)
	if err != nil {
		t.Fatalf("ChallengePassword: %v", err)
	}
	if cp != "" {
		t.Errorf("challengePassword = %q, want empty", cp)
	}
}
