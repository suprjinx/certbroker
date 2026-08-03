package cms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

type keypair struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// newCA mints a self-signed CA plus a pool trusting it.
func newCA(t *testing.T, cn string) (*keypair, *x509.CertPool) {
	t.Helper()
	kp := issue(t, cn, nil, true)
	pool := x509.NewCertPool()
	pool.AddCert(kp.cert)
	return kp, pool
}

// issue mints a certificate, self-signed when parent is nil.
func issue(t *testing.T, cn string, parent *keypair, isCA bool) *keypair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	signerCert, signerKey := tmpl, any(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &keypair{cert: cert, key: key}
}

func mustSign(t *testing.T, content []byte, kp *keypair, opts SignOptions) []byte {
	t.Helper()
	der, err := Sign(content, kp.cert, kp.key, opts)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return der
}

// --- the security-critical distinction ---------------------------------------

// TestVerifySignatureAcceptsSelfSigned is the PKCSReq case: the signature is
// intact but the signer proves nothing. It must verify, and it must be flagged
// as unchained so callers cannot mistake it for an identity.
func TestVerifySignatureAcceptsSelfSigned(t *testing.T) {
	rogue := issue(t, "attacker", nil, false)
	der := mustSign(t, []byte("payload"), rogue, SignOptions{})

	var v Verifier
	s, err := v.VerifySignature(der)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if s.Chained {
		t.Fatal("a self-signed signer must never be reported as chained")
	}
	if s.Signer.Subject.CommonName != "attacker" {
		t.Errorf("signer CN = %q", s.Signer.Subject.CommonName)
	}
	if string(s.Content) != "payload" {
		t.Errorf("content = %q", s.Content)
	}
}

// TestVerifyChainRejectsSelfSigned is the invariant that keeps a PKCSReq signer
// from being laundered into an authenticated identity: the same message that
// passes VerifySignature must fail VerifyChain against a real anchor.
func TestVerifyChainRejectsSelfSigned(t *testing.T) {
	_, deviceRoots := newCA(t, "device CA")
	rogue := issue(t, "attacker", nil, false)
	der := mustSign(t, []byte("payload"), rogue, SignOptions{})

	var v Verifier
	if _, err := v.VerifyChain(der, deviceRoots); err == nil {
		t.Fatal("a self-signed signer must not verify against the device anchor")
	}
}

// TestVerifyChainAcceptsIssuedCert is the RenewalReq case.
func TestVerifyChainAcceptsIssuedCert(t *testing.T) {
	ca, roots := newCA(t, "device CA")
	device := issue(t, "device01.example.com", ca, false)
	der := mustSign(t, []byte("renewal"), device, SignOptions{})

	var v Verifier
	s, err := v.VerifyChain(der, roots)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !s.Chained {
		t.Fatal("a chain-verified signer must be reported as chained")
	}
}

// TestVerifyChainRequiresAnchor: a nil pool must deny, not silently skip the
// chain check the way the underlying library's Verify(nil) would.
func TestVerifyChainRequiresAnchor(t *testing.T) {
	ca, _ := newCA(t, "device CA")
	device := issue(t, "device01.example.com", ca, false)
	der := mustSign(t, []byte("renewal"), device, SignOptions{})

	var v Verifier
	if _, err := v.VerifyChain(der, nil); err == nil {
		t.Fatal("VerifyChain with no trust anchor must fail closed")
	}
}

func TestVerifyRejectsTamperedContent(t *testing.T) {
	kp := issue(t, "device", nil, false)
	der := mustSign(t, []byte("original"), kp, SignOptions{})
	der[len(der)-1] ^= 0xff

	var v Verifier
	if _, err := v.VerifySignature(der); err == nil {
		t.Fatal("a tampered message must not verify")
	}
}

// --- algorithm allowlist -----------------------------------------------------

// TestSHA1RejectedByDefault: SHA-1 is collision-broken; accepting it must be a
// recorded decision, never a default.
func TestSHA1RejectedByDefault(t *testing.T) {
	kp := issue(t, "device", nil, false)
	der := mustSign(t, []byte("payload"), kp, SignOptions{Digest: SHA1})

	var v Verifier
	_, err := v.VerifySignature(der)
	if err == nil {
		t.Fatal("SHA-1 must be rejected by the default allowlist")
	}
	if !errors.Is(err, ErrAlgorithmNotPermitted) {
		t.Fatalf("error = %v, want ErrAlgorithmNotPermitted", err)
	}
}

// TestSHA1AcceptedWhenExplicitlyAllowed keeps the legacy escape hatch working
// for old clients, but only when configured.
func TestSHA1AcceptedWhenExplicitlyAllowed(t *testing.T) {
	kp := issue(t, "device", nil, false)
	der := mustSign(t, []byte("payload"), kp, SignOptions{Digest: SHA1})

	v := Verifier{Digests: []asn1.ObjectIdentifier{SHA1}}
	if _, err := v.VerifySignature(der); err != nil {
		t.Fatalf("SHA-1 with an explicit allowlist: %v", err)
	}
}

// TestDigestCheckedBeforeSignature: the allowlist is also a cost control, so a
// disallowed algorithm must be rejected without verifying the signature.
func TestDigestCheckedBeforeSignature(t *testing.T) {
	kp := issue(t, "device", nil, false)
	der := mustSign(t, []byte("payload"), kp, SignOptions{Digest: SHA1})
	der[len(der)-1] ^= 0xff // also break the signature

	var v Verifier
	_, err := v.VerifySignature(der)
	if !errors.Is(err, ErrAlgorithmNotPermitted) {
		t.Fatalf("digest must be checked before the signature; got %v", err)
	}
}

// --- envelope ----------------------------------------------------------------

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kp := issue(t, "recipient", nil, false)
	plaintext := []byte("a PKCS#10 would live here")

	env, err := Encrypt(plaintext, kp.cert)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(env, kp.cert, kp.key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}
}

// TestContentEncryptionIsAES pins the init override: the library defaults to
// DES-CBC, which we must never emit.
func TestContentEncryptionIsAES(t *testing.T) {
	if pkcs7.ContentEncryptionAlgorithm != pkcs7.EncryptionAlgorithmAES256CBC {
		t.Fatalf("content encryption = %d, want AES-256-CBC (%d)",
			pkcs7.ContentEncryptionAlgorithm, pkcs7.EncryptionAlgorithmAES256CBC)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	recipient := issue(t, "recipient", nil, false)
	other := issue(t, "other", nil, false)

	env, err := Encrypt([]byte("secret"), recipient.cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(env, other.cert, other.key); err == nil {
		t.Fatal("decryption with the wrong key must fail")
	}
}

// TestDecryptErrorIsOpaque: decryption failures must not leak detail that would
// help build a padding oracle.
func TestDecryptErrorIsOpaque(t *testing.T) {
	recipient := issue(t, "recipient", nil, false)
	other := issue(t, "other", nil, false)
	env, _ := Encrypt([]byte("secret"), recipient.cert)

	_, err := Decrypt(env, other.cert, other.key)
	if err == nil {
		t.Fatal("expected failure")
	}
	if got := err.Error(); got != "cms: decryption failed" {
		t.Fatalf("error = %q, want an opaque message", got)
	}
}

// --- malformed input ---------------------------------------------------------

func TestMalformedInput(t *testing.T) {
	var v Verifier
	cases := []struct {
		name string
		der  []byte
	}{
		{"empty", nil},
		{"garbage", []byte("not asn.1 at all")},
		{"truncated sequence", []byte{0x30, 0x82, 0xff, 0xff}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.VerifySignature(tc.der); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := Decrypt(tc.der, nil, nil); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDegenerateCertsOnly(t *testing.T) {
	ca, _ := newCA(t, "issuing CA")
	ra := issue(t, "RA", ca, false)

	der, err := DegenerateCertsOnly(ra.cert, ca.cert)
	if err != nil {
		t.Fatalf("DegenerateCertsOnly: %v", err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p7.Certificates) != 2 {
		t.Fatalf("got %d certificates, want 2", len(p7.Certificates))
	}
	var names []string
	for _, c := range p7.Certificates {
		names = append(names, c.Subject.CommonName)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "RA") || !strings.Contains(joined, "issuing CA") {
		t.Fatalf("certificates = %s, want both RA and CA", joined)
	}
}

func TestDegenerateCertsOnlyRequiresACert(t *testing.T) {
	if _, err := DegenerateCertsOnly(); err == nil {
		t.Fatal("expected an error with no certificates")
	}
}
