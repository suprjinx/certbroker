package est

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

// makeRSACSR builds an RSA CSR of the given modulus size and returns its DER.
// Key sizes are kept small deliberately: the bounds under test are passed
// explicitly, so there is no need to generate an actually-huge key.
func makeRSACSR(t *testing.T, bits int, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("genkey(%d): %v", bits, err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("createcsr: %v", err)
	}
	return der
}

func TestParseCSRLimitedRejectsUndersizedRSA(t *testing.T) {
	der := makeRSACSR(t, 1024, "weak.example.com")

	if _, err := ParseCSRLimited(der, 2048, 8192); err == nil {
		t.Fatal("expected a 1024-bit RSA key to be rejected")
	} else if !strings.Contains(err.Error(), "too small") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same CSR passes when the floor is lowered, confirming the key itself is
	// well-formed and it is the bound doing the rejecting.
	if _, err := ParseCSRLimited(der, 1024, 8192); err != nil {
		t.Fatalf("1024-bit key with a 1024-bit floor: %v", err)
	}
}

func TestParseCSRLimitedRejectsOversizedRSA(t *testing.T) {
	der := makeRSACSR(t, 2048, "big.example.com")

	if _, err := ParseCSRLimited(der, 512, 1024); err == nil {
		t.Fatal("expected a 2048-bit RSA key to exceed a 1024-bit ceiling")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := ParseCSRLimited(der, 512, 4096); err != nil {
		t.Fatalf("2048-bit key under a 4096-bit ceiling: %v", err)
	}
}

// TestKeySizeCheckedBeforeSignature pins the ordering that makes the ceiling a
// DoS control rather than a policy nicety: an oversized key must be rejected
// without the signature ever being verified. The CSR here has a deliberately
// corrupted signature, so if verification ran first the error would name the
// proof-of-possession instead of the key size.
func TestKeySizeCheckedBeforeSignature(t *testing.T) {
	der := makeRSACSR(t, 2048, "big.example.com")
	corrupt := make([]byte, len(der))
	copy(corrupt, der)
	corrupt[len(corrupt)-1] ^= 0xff // break the signature

	_, err := ParseCSRLimited(corrupt, 512, 1024)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("key size must be checked before the signature; got: %v", err)
	}
}

func TestParseCSRLimitedZeroBoundsUseDefaults(t *testing.T) {
	der := makeRSACSR(t, 1024, "weak.example.com")
	if _, err := ParseCSRLimited(der, 0, 0); err == nil {
		t.Fatal("zero bounds should fall back to the defaults and reject 1024 bits")
	}
}

// TestNonRSAKeysBypassBounds confirms the bounds are RSA-specific: EC keys have
// a fixed, small verification cost and must not be caught by a bit-length test.
func TestNonRSAKeysBypassBounds(t *testing.T) {
	der := makeCSR(t, "ec.example.com")
	if _, err := ParseCSRLimited(der, 4096, 4096); err != nil {
		t.Fatalf("EC CSR rejected by RSA bounds: %v", err)
	}
}
