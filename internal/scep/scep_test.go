package scep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
	"github.com/gr-oss/certbroker/internal/bao"
	"github.com/gr-oss/certbroker/internal/cms"
	"github.com/smallstep/pkcs7"
)

// --- harness -----------------------------------------------------------------

type keypair struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

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
	sc, sk := tmpl, any(key)
	if parent != nil {
		sc, sk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, sc, &key.PublicKey, sk)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &keypair{cert: cert, key: key}
}

func makeCSR(t *testing.T, cn string, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// buildPKIOperation assembles a client message: the CSR is enveloped to the RA
// and the envelope is signed by signer.
func buildPKIOperation(t *testing.T, csrDER []byte, ra *x509.Certificate, signer *keypair,
	mt MessageType, txID string, nonce []byte) []byte {
	t.Helper()
	env, err := cms.Encrypt(csrDER, ra)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	der, err := cms.Sign(env, signer.cert, signer.key, cms.SignOptions{
		Attributes: []cms.Attribute{
			{Type: oidMessageType, Value: string(mt)},
			{Type: oidTransactionID, Value: txID},
			{Type: oidSenderNonce, Value: nonce},
		},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return der
}

func testNonce() []byte {
	n := make([]byte, nonceLen)
	for i := range n {
		n[i] = byte(i)
	}
	return n
}

// fakeEnroller mints a certificate honouring the requested CN.
type fakeEnroller struct {
	t        *testing.T
	ca       *keypair
	lastOpts bao.SignOptions
	rogueCN  string // simulate a permissive OpenBao role
}

func (f *fakeEnroller) Sign(_ context.Context, _, csrPEM string, opts bao.SignOptions) (*bao.CertBundle, error) {
	f.lastOpts = opts
	cn := opts.CommonName
	if f.rogueCN != "" {
		cn = f.rogueCN
	}
	leaf := issue(f.t, cn, f.ca, false)
	return &bao.CertBundle{
		Certificate:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.cert.Raw})),
		SerialNumber: "01",
	}, nil
}

func (f *fakeEnroller) CAChain(context.Context) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.cert.Raw}), nil
}

// recordingAuthorizer captures the request the handler built.
type recordingAuthorizer struct {
	last     authz.Request
	decision authz.Decision
	err      error
}

func (a *recordingAuthorizer) Authorize(_ context.Context, r authz.Request) (authz.Decision, error) {
	a.last = r
	if a.err != nil {
		return authz.Decision{}, a.err
	}
	return a.decision, nil
}

type harness struct {
	srv    *httptest.Server
	ra     *keypair
	ca     *keypair
	device *keypair
	az     *recordingAuthorizer
	fe     *fakeEnroller
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ca := issue(t, "test CA", nil, true)
	ra := issue(t, "certbroker RA", ca, false)
	device := issue(t, "device01.example.com", ca, false)

	deviceRoots := x509.NewCertPool()
	deviceRoots.AddCert(ca.cert)

	az := &recordingAuthorizer{decision: authz.Decision{
		Allow: true, Role: "device-role",
		Constraints: authz.CertConstraints{CommonName: "device01.example.com"},
		Reason:      "test",
	}}
	fe := &fakeEnroller{t: t, ca: ca}

	h, err := NewHandler(Options{
		RACert:      ra.cert,
		RAKey:       ra.key,
		DeviceRoots: deviceRoots,
		Enroller:    fe,
		Authorizer:  az,
		ParseCSR: func(der []byte) (*x509.CertificateRequest, error) {
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				return nil, err
			}
			return csr, csr.CheckSignature()
		},
		ReplayCache: NewReplayCache(time.Minute, 1000),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &harness{srv: srv, ra: ra, ca: ca, device: device, az: az, fe: fe}
}

func (h *harness) post(t *testing.T, body []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(h.srv.URL+"?operation=PKIOperation", ctPKIOperation, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// certRepStatus decodes a response and returns its pkiStatus.
func certRepStatus(t *testing.T, resp *http.Response) PKIStatus {
	t.Helper()
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var v cms.Verifier
	signed, err := v.VerifySignature(raw)
	if err != nil {
		t.Fatalf("response not verifiable: %v", err)
	}
	var status string
	if err := signed.UnmarshalAttribute(oidPKIStatus, &status); err != nil {
		t.Fatalf("no pkiStatus: %v", err)
	}
	return PKIStatus(status)
}

// --- the central invariant ----------------------------------------------------

// TestPKCSReqSignerIsNotAuthenticated is the invariant the whole SCEP design
// rests on. A PKCSReq signer is self-signed and attacker-generated; if it
// reached authz.Request.ClientCert, StandardConstraints would pin issued names
// to a certificate the requester minted, inverting identity continuity into a
// rubber stamp. See docs/threat-model.md T1 and §8.
func TestPKCSReqSignerIsNotAuthenticated(t *testing.T) {
	h := newHarness(t)

	// The attacker self-signs a certificate claiming a name it has no right to.
	rogue := issue(t, "admin.example.com", nil, false)
	csr := makeCSR(t, "device01.example.com", rogue.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, rogue, PKCSReq, "tx-1", testNonce())

	resp := h.post(t, msg)
	defer resp.Body.Close()

	if h.az.last.ClientCert != nil {
		t.Fatalf("SECURITY: a self-signed PKCSReq signer reached ClientCert (CN=%q)",
			h.az.last.ClientCert.Subject.CommonName)
	}
	if h.az.last.Operation != authz.OpSimpleEnroll {
		t.Errorf("operation = %v, want simpleenroll", h.az.last.Operation)
	}
}

// TestRenewalReqSignerIsAuthenticated: the counterpart. A signer that chains to
// the device anchor IS an identity and must populate ClientCert.
func TestRenewalReqSignerIsAuthenticated(t *testing.T) {
	h := newHarness(t)

	csr := makeCSR(t, "device01.example.com", h.device.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, h.device, RenewalReq, "tx-2", testNonce())

	resp := h.post(t, msg)
	defer resp.Body.Close()

	if h.az.last.ClientCert == nil {
		t.Fatal("a device-anchor-verified renewal signer must populate ClientCert")
	}
	if got := h.az.last.ClientCert.Subject.CommonName; got != "device01.example.com" {
		t.Errorf("ClientCert CN = %q", got)
	}
	if h.az.last.Operation != authz.OpSimpleReenroll {
		t.Errorf("operation = %v, want simplereenroll", h.az.last.Operation)
	}
}

// TestRenewalReqWithUntrustedSignerRejected: a self-signed signer must not be
// able to claim RenewalReq and thereby reach the authenticated path.
func TestRenewalReqWithUntrustedSignerRejected(t *testing.T) {
	h := newHarness(t)

	rogue := issue(t, "device01.example.com", nil, false)
	csr := makeCSR(t, "device01.example.com", rogue.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, rogue, RenewalReq, "tx-3", testNonce())

	resp := h.post(t, msg)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if h.az.last.ClientCert != nil {
		t.Fatal("SECURITY: an untrusted renewal signer reached ClientCert")
	}
}

// --- replay -------------------------------------------------------------------

// TestReplayRejected: SCEP messages stay valid wherever they are replayed, so
// the cache is the only thing stopping a captured request being reused.
func TestReplayRejected(t *testing.T) {
	h := newHarness(t)

	client := issue(t, "device01.example.com", nil, false)
	csr := makeCSR(t, "device01.example.com", client.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, client, PKCSReq, "tx-replay", testNonce())

	first := h.post(t, msg)
	if got := certRepStatus(t, first); got != StatusSuccess {
		t.Fatalf("first request status = %v, want success", got)
	}

	// Byte-for-byte identical resubmission.
	second := h.post(t, msg)
	if got := certRepStatus(t, second); got != StatusFailure {
		t.Fatalf("replayed request status = %v, want failure", got)
	}
}

// --- authorization ------------------------------------------------------------

func TestAuthorizationDenialReturnsFailure(t *testing.T) {
	h := newHarness(t)
	h.az.decision = authz.Decision{Allow: false, Reason: "device not permitted by inventory"}

	client := issue(t, "rogue.example.com", nil, false)
	csr := makeCSR(t, "rogue.example.com", client.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, client, PKCSReq, "tx-deny", testNonce())

	resp := h.post(t, msg)
	if got := certRepStatus(t, resp); got != StatusFailure {
		t.Fatalf("status = %v, want failure", got)
	}
}

// TestFailureLeaksNoReason: failInfo must stay coarse so a client cannot probe
// policy by observing which denial it triggered.
func TestFailureLeaksNoReason(t *testing.T) {
	h := newHarness(t)
	h.az.decision = authz.Decision{Allow: false, Reason: "device secret-fleet-01 is not in inventory"}

	client := issue(t, "x.example.com", nil, false)
	csr := makeCSR(t, "x.example.com", client.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, client, PKCSReq, "tx-leak", testNonce())

	resp := h.post(t, msg)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if strings.Contains(string(raw), "secret-fleet-01") {
		t.Fatal("the denial reason leaked into the response")
	}
}

// TestConstraintsSentToIssuer: the handler must send policy's constraints, not
// the CSR's own names.
func TestConstraintsSentToIssuer(t *testing.T) {
	h := newHarness(t)
	h.az.decision = authz.Decision{
		Allow: true, Role: "device-role",
		Constraints: authz.CertConstraints{CommonName: "authorized.example.com"},
	}

	client := issue(t, "requested.example.com", nil, false)
	csr := makeCSR(t, "requested.example.com", client.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, client, PKCSReq, "tx-cn", testNonce())

	resp := h.post(t, msg)
	defer resp.Body.Close()

	if got := h.fe.lastOpts.CommonName; got != "authorized.example.com" {
		t.Fatalf("issuer asked for CN %q, want the authorized name", got)
	}
}

// TestVerifyIssuedWithholdsOverBroadCert: the same backstop EST applies, here
// against a role that ignores the broker's parameters.
func TestVerifyIssuedWithholdsOverBroadCert(t *testing.T) {
	h := newHarness(t)
	h.fe.rogueCN = "attacker.example.com" // permissive role substitutes the CN

	// Wire the real check.
	ca := h.ca
	deviceRoots := x509.NewCertPool()
	deviceRoots.AddCert(ca.cert)
	handler, err := NewHandler(Options{
		RACert: h.ra.cert, RAKey: h.ra.key, DeviceRoots: deviceRoots,
		Enroller: h.fe, Authorizer: h.az,
		ParseCSR: func(der []byte) (*x509.CertificateRequest, error) {
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				return nil, err
			}
			return csr, csr.CheckSignature()
		},
		VerifyIssued: func(cert *x509.Certificate, c authz.CertConstraints) error {
			if c.CommonName != "" && cert.Subject.CommonName != c.CommonName {
				return errIssuedMismatch
			}
			return nil
		},
		ReplayCache: NewReplayCache(time.Minute, 100),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := issue(t, "device01.example.com", nil, false)
	csr := makeCSR(t, "device01.example.com", client.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, client, PKCSReq, "tx-rogue", testNonce())

	resp, err := http.Post(srv.URL+"?operation=PKIOperation", ctPKIOperation, strings.NewReader(string(msg)))
	if err != nil {
		t.Fatal(err)
	}
	if got := certRepStatus(t, resp); got != StatusFailure {
		t.Fatalf("status = %v, want failure — an over-broad certificate must be withheld", got)
	}
}

var errIssuedMismatch = &mismatchError{}

type mismatchError struct{}

func (*mismatchError) Error() string { return "issued CN does not match" }

// --- message validation -------------------------------------------------------

func TestUnsupportedMessageTypeRejected(t *testing.T) {
	h := newHarness(t)
	client := issue(t, "device01.example.com", nil, false)
	csr := makeCSR(t, "device01.example.com", client.key)

	for _, mt := range []MessageType{GetCertInitial, GetCert, GetCRL, MessageType("99")} {
		t.Run(mt.String(), func(t *testing.T) {
			msg := buildPKIOperation(t, csr, h.ra.cert, client, mt, "tx-"+string(mt), testNonce())
			resp := h.post(t, msg)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestShortNonceRejected(t *testing.T) {
	h := newHarness(t)
	client := issue(t, "device01.example.com", nil, false)
	csr := makeCSR(t, "device01.example.com", client.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, client, PKCSReq, "tx-n", []byte{1, 2, 3})

	resp := h.post(t, msg)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a short senderNonce", resp.StatusCode)
	}
}

func TestOversizedTransactionIDRejected(t *testing.T) {
	h := newHarness(t)
	client := issue(t, "device01.example.com", nil, false)
	csr := makeCSR(t, "device01.example.com", client.key)
	msg := buildPKIOperation(t, csr, h.ra.cert, client, PKCSReq,
		strings.Repeat("A", maxTransactionIDLen+1), testNonce())

	resp := h.post(t, msg)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestGarbageBodyRejected(t *testing.T) {
	h := newHarness(t)
	resp := h.post(t, []byte("this is not a CMS message"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	ca := issue(t, "ca", nil, true)
	ra := issue(t, "ra", ca, false)
	h, err := NewHandler(Options{
		RACert: ra.cert, RAKey: ra.key,
		Enroller:   &fakeEnroller{t: t, ca: ca},
		Authorizer: &recordingAuthorizer{},
		ParseCSR: func(der []byte) (*x509.CertificateRequest, error) {
			return x509.ParseCertificateRequest(der)
		},
		ReplayCache:     NewReplayCache(time.Minute, 100),
		MaxRequestBytes: 1024,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"?operation=PKIOperation", ctPKIOperation,
		strings.NewReader(strings.Repeat("A", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

// --- CA endpoints -------------------------------------------------------------

// TestGetCACertIncludesRA: a client needs the RA certificate to encrypt to, and
// the CA certificate to trust. Omitting the RA breaks enrollment entirely.
func TestGetCACertIncludesRA(t *testing.T) {
	h := newHarness(t)

	resp, err := http.Get(h.srv.URL + "?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != ctCACertChain {
		t.Errorf("content-type = %q, want %q", ct, ctCACertChain)
	}
	raw, _ := io.ReadAll(resp.Body)

	certs, err := parseDegenerate(raw)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	var names []string
	for _, c := range certs {
		names = append(names, c.Subject.CommonName)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "certbroker RA") {
		t.Errorf("RA certificate missing from GetCACert: %s", joined)
	}
	if !strings.Contains(joined, "test CA") {
		t.Errorf("CA certificate missing from GetCACert: %s", joined)
	}
}

// TestGetCACapsOmitsWeakAlgorithms: advertising SHA-1 or DES would invite
// clients to use them.
func TestGetCACapsOmitsWeakAlgorithms(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.srv.URL + "?operation=GetCACaps")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	caps := string(raw)

	for _, weak := range []string{"SHA-1", "DES", "GetNextCACert"} {
		if strings.Contains(caps, weak) {
			t.Errorf("GetCACaps advertises %q:\n%s", weak, caps)
		}
	}
	for _, want := range []string{"POSTPKIOperation", "Renewal", "SHA-256"} {
		if !strings.Contains(caps, want) {
			t.Errorf("GetCACaps missing %q", want)
		}
	}
}

func TestUnknownOperationRejected(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.srv.URL + "?operation=Nonsense")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestNewHandlerRequiresReplayCache: a nil cache would make every request
// replayable, so construction must refuse it.
func TestNewHandlerRequiresReplayCache(t *testing.T) {
	ca := issue(t, "ca", nil, true)
	ra := issue(t, "ra", ca, false)
	_, err := NewHandler(Options{
		RACert: ra.cert, RAKey: ra.key,
		Enroller:   &fakeEnroller{t: t, ca: ca},
		Authorizer: &recordingAuthorizer{},
		ParseCSR:   func(der []byte) (*x509.CertificateRequest, error) { return nil, nil },
	})
	if err == nil {
		t.Fatal("NewHandler must refuse a nil ReplayCache")
	}
}

// parseDegenerate extracts certificates from a certs-only SignedData.
func parseDegenerate(der []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}
