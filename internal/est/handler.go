package est

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
	"github.com/gr-oss/certbroker/internal/bao"
	"github.com/gr-oss/certbroker/internal/pkcs7"
)

// wellKnownPrefix is the EST application's URI root (RFC 7030 §3.2.2).
const wellKnownPrefix = "/.well-known/est/"

// defaultMaxRequestBytes bounds a request body: a DoS guard, not a real limit.
const defaultMaxRequestBytes = 256 * 1024

// defaultUpstreamTimeout bounds one OpenBao call made while serving a request.
const defaultUpstreamTimeout = 20 * time.Second

const (
	ctPKCS7CertsOnly = "application/pkcs7-mime; smime-type=certs-only"
	ctPKCS10         = "application/pkcs10"
	ctCSRAttrs       = "application/csrattrs"
	ctPKCS8          = "application/pkcs8"
)

// Enroller is the subset of the OpenBao client the EST handlers depend on.
// *bao.Client satisfies it.
type Enroller interface {
	Sign(ctx context.Context, role, csrPEM string, opts bao.SignOptions) (*bao.CertBundle, error)
	Issue(ctx context.Context, role, commonName string, opts bao.SignOptions) (*bao.CertBundle, error)
	CAChain(ctx context.Context) ([]byte, error)
}

// Options configures an EST handler.
type Options struct {
	// BootstrapRoots verifies client certs presented during initial enrollment.
	BootstrapRoots *x509.CertPool
	// DeviceRoots verifies the existing device cert during re-enrollment.
	DeviceRoots *x509.CertPool
	// Enroller performs issuance against OpenBao.
	Enroller Enroller
	// Authorizer decides each request; nil means authz.DenyAll (fail closed).
	Authorizer authz.Authorizer
	// AllowedKeyTypes optionally restricts CSR key types (empty = any recognized).
	AllowedKeyTypes []string
	// CSRAttrs is the DER served by /csrattrs; empty yields 204.
	CSRAttrs []byte
	// MaxRequestBytes bounds request bodies; 0 uses defaultMaxRequestBytes.
	MaxRequestBytes int64
	// MinRSABits/MaxRSABits bound CSR RSA moduli; 0 uses the package defaults.
	MinRSABits int
	MaxRSABits int
	// ServerKeyGenKeyType/Bits select the key OpenBao generates for /serverkeygen.
	// Required when the role's key_type is "any"; empty defers to the role.
	ServerKeyGenKeyType string
	ServerKeyGenKeyBits int
	// UpstreamTimeout bounds one OpenBao call (0 = default), so a wedged upstream
	// cannot pin request goroutines and their concurrency slots.
	UpstreamTimeout time.Duration
	Logger          *slog.Logger
}

type handler struct {
	opts     Options
	logger   *slog.Logger
	authz    authz.Authorizer
	maxReq   int64
	upstream time.Duration
}

// NewHandler builds the EST HTTP handler.
func NewHandler(opts Options) (http.Handler, error) {
	if opts.Enroller == nil {
		return nil, errors.New("est: Enroller is required")
	}
	h := &handler{
		opts:     opts,
		logger:   opts.Logger,
		authz:    opts.Authorizer,
		maxReq:   opts.MaxRequestBytes,
		upstream: opts.UpstreamTimeout,
	}
	if h.logger == nil {
		h.logger = slog.Default()
	}
	if h.authz == nil {
		h.authz = authz.DenyAll{} // fail closed
	}
	if h.maxReq <= 0 {
		h.maxReq = defaultMaxRequestBytes
	}
	if h.upstream <= 0 {
		h.upstream = defaultUpstreamTimeout
	}
	return h, nil
}

// upstreamCtx derives a context bounding one OpenBao call.
func (h *handler) upstreamCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), h.upstream)
}

// parseCSR applies the handler's configured key bounds.
func (h *handler) parseCSR(der []byte) (*x509.CertificateRequest, error) {
	return ParseCSRLimited(der, h.opts.MinRSABits, h.opts.MaxRSABits)
}

// checkIssued withholds a certificate exceeding what was authorized: a role
// misconfiguration, logged at ERROR with the serial since it needs revoking.
func (h *handler) checkIssued(certDER []byte, d authz.Decision, serial string) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		h.logger.Error("issued certificate could not be parsed", "err", err)
		return fmt.Errorf("parse issued certificate: %w", err)
	}
	if err := verifyIssued(cert, d.Constraints); err != nil {
		h.logger.Error("SECURITY: issued certificate exceeds authorized constraints; withholding it",
			"err", err,
			"role", d.Role,
			"serial", serial,
			"authorized_cn", d.Constraints.CommonName,
			"authorized_dns", d.Constraints.DNSNames,
			"issued_cn", cert.Subject.CommonName,
			"issued_dns", cert.DNSNames,
			"hint", "check the OpenBao role's use_csr_sans and use_csr_common_name settings",
		)
		return err
	}
	return nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, wellKnownPrefix) {
		http.NotFound(w, r)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, wellKnownPrefix), "/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	// Final segment is the operation; anything before it is the optional label.
	label, op := "", rest
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		label, op = rest[:i], rest[i+1:]
	}

	switch op {
	case "cacerts":
		h.methodGuard(w, r, http.MethodGet, func() { h.caCerts(w, r) })
	case "simpleenroll":
		h.methodGuard(w, r, http.MethodPost, func() { h.enroll(w, r, authz.OpSimpleEnroll, label) })
	case "simplereenroll":
		h.methodGuard(w, r, http.MethodPost, func() { h.enroll(w, r, authz.OpSimpleReenroll, label) })
	case "serverkeygen":
		h.methodGuard(w, r, http.MethodPost, func() { h.serverKeyGen(w, r, label) })
	case "csrattrs":
		h.methodGuard(w, r, http.MethodGet, func() { h.csrAttrs(w, r) })
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) methodGuard(w http.ResponseWriter, r *http.Request, method string, fn func()) {
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fn()
}

// caCerts serves the CA chain as a certs-only PKCS#7 (RFC 7030 §4.1).
func (h *handler) caCerts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.upstreamCtx(r)
	defer cancel()

	chainPEM, err := h.opts.Enroller.CAChain(ctx)
	if err != nil {
		h.logger.Error("cacerts: fetch chain", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	ders, err := pemCertsToDER(chainPEM)
	if err != nil {
		h.logger.Error("cacerts: decode chain", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	p7, err := pkcs7.DegenerateCertsOnly(ders...)
	if err != nil {
		h.logger.Error("cacerts: encode pkcs7", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writePKCS7(w, p7)
}

// enroll handles /simpleenroll and /simplereenroll. Re-enrollment demands a
// device-anchor cert; initial enrollment treats a bootstrap cert as optional.
func (h *handler) enroll(w http.ResponseWriter, r *http.Request, op authz.Operation, label string) {
	csrDER, status, err := h.readCSR(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	csr, err := h.parseCSR(csrDER)
	if err != nil {
		http.Error(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := ValidateKeyType(csr, h.opts.AllowedKeyTypes); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	cp, err := ChallengePassword(csr)
	if err != nil {
		h.logger.Warn("enroll: challengePassword parse", "err", err)
	}

	clientCert, err := h.clientIdentity(r, op)
	if err != nil {
		// Re-enrollment demands a valid device certificate; refuse otherwise.
		h.logger.Warn("enroll: client cert", "op", op, "err", err)
		http.Error(w, "client certificate required", http.StatusForbidden)
		return
	}

	req := authz.Request{
		Operation:         op,
		ClientCert:        clientCert,
		CSR:               csr,
		ChallengePassword: cp,
		Label:             label,
		RemoteAddr:        r.RemoteAddr,
	}
	decision, err := h.authz.Authorize(r.Context(), req)
	if err != nil {
		h.audit(op, req, decision, "error", err)
		http.Error(w, "authorization error", http.StatusInternalServerError)
		return
	}
	if !decision.Allow {
		h.audit(op, req, decision, "deny", nil)
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	ctx, cancel := h.upstreamCtx(r)
	defer cancel()

	bundle, err := h.opts.Enroller.Sign(ctx, decision.Role, csrPEM, toSignOptions(decision.Constraints))
	if err != nil {
		h.audit(op, req, decision, "issue-error", err)
		http.Error(w, "issuance failed", http.StatusBadGateway)
		return
	}

	leafDER, err := singleCertDER(bundle.Certificate)
	if err != nil {
		h.logger.Error("enroll: decode issued cert", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.checkIssued(leafDER, decision, bundle.SerialNumber); err != nil {
		h.audit(op, req, decision, "constraint-violation", err)
		http.Error(w, "issuance failed", http.StatusBadGateway)
		return
	}
	p7, err := pkcs7.DegenerateCertsOnly(leafDER)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(op, req, decision, "issued", nil)
	writePKCS7(w, p7)
}

// serverKeyGen handles /serverkeygen: OpenBao generates the key and the reply is
// multipart/mixed of PKCS#8 key + PKCS#7 cert. The CSR still carries PoP.
func (h *handler) serverKeyGen(w http.ResponseWriter, r *http.Request, label string) {
	csrDER, status, err := h.readCSR(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	csr, err := h.parseCSR(csrDER)
	if err != nil {
		http.Error(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := ValidateKeyType(csr, h.opts.AllowedKeyTypes); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	cp, err := ChallengePassword(csr)
	if err != nil {
		h.logger.Warn("serverkeygen: challengePassword parse", "err", err)
	}
	clientCert, err := h.clientIdentity(r, authz.OpServerKeyGen)
	if err != nil {
		http.Error(w, "client certificate required", http.StatusForbidden)
		return
	}

	req := authz.Request{
		Operation:         authz.OpServerKeyGen,
		ClientCert:        clientCert,
		CSR:               csr,
		ChallengePassword: cp,
		Label:             label,
		RemoteAddr:        r.RemoteAddr,
	}
	decision, err := h.authz.Authorize(r.Context(), req)
	if err != nil {
		h.audit(authz.OpServerKeyGen, req, decision, "error", err)
		http.Error(w, "authorization error", http.StatusInternalServerError)
		return
	}
	if !decision.Allow {
		h.audit(authz.OpServerKeyGen, req, decision, "deny", nil)
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}

	ctx, cancel := h.upstreamCtx(r)
	defer cancel()

	issueOpts := toSignOptions(decision.Constraints)
	issueOpts.KeyType = h.opts.ServerKeyGenKeyType
	issueOpts.KeyBits = h.opts.ServerKeyGenKeyBits

	bundle, err := h.opts.Enroller.Issue(ctx, decision.Role, decision.Constraints.CommonName, issueOpts)
	if err != nil {
		h.audit(authz.OpServerKeyGen, req, decision, "issue-error", err)
		http.Error(w, "issuance failed", http.StatusBadGateway)
		return
	}

	keyDER, err := singleBlockDER(bundle.PrivateKey)
	if err != nil {
		h.logger.Error("serverkeygen: decode key", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Best-effort scrub of the decoded private key once the response is written.
	defer zero(keyDER)

	certDER, err := singleCertDER(bundle.Certificate)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.checkIssued(certDER, decision, bundle.SerialNumber); err != nil {
		h.audit(authz.OpServerKeyGen, req, decision, "constraint-violation", err)
		http.Error(w, "issuance failed", http.StatusBadGateway)
		return
	}
	p7, err := pkcs7.DegenerateCertsOnly(certDER)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.audit(authz.OpServerKeyGen, req, decision, "issued", nil)
	writeServerKeyGen(w, keyDER, p7)
}

// csrAttrs serves the optional CSR attributes advertisement (RFC 7030 §4.5).
func (h *handler) csrAttrs(w http.ResponseWriter, r *http.Request) {
	if len(h.opts.CSRAttrs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", ctCSRAttrs)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	w.Write(base64Lines(h.opts.CSRAttrs))
}

// clientIdentity verifies the mTLS cert against the anchor for this operation.
// Initial enrollment may return (nil, nil), leaving the decision to policy.
func (h *handler) clientIdentity(r *http.Request, op authz.Operation) (*x509.Certificate, error) {
	switch op {
	case authz.OpSimpleReenroll:
		return VerifyPeer(r.TLS, h.opts.DeviceRoots)
	case authz.OpServerKeyGen:
		// serverkeygen may be used for bootstrap or renewal; prefer a device
		// cert if presented and valid, else fall back to bootstrap.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if cert, err := VerifyPeer(r.TLS, h.opts.DeviceRoots); err == nil {
				return cert, nil
			}
		}
		fallthrough
	case authz.OpSimpleEnroll:
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return nil, nil // no client cert; policy may still allow via challenge/inventory
		}
		cert, err := VerifyPeer(r.TLS, h.opts.BootstrapRoots)
		if err != nil {
			// A presented-but-unverifiable cert is ignored, not fatal, for
			// initial enrollment; policy decides based on other factors.
			h.logger.Warn("enroll: bootstrap cert not verified, ignoring", "err", err)
			return nil, nil
		}
		return cert, nil
	default:
		return nil, fmt.Errorf("unexpected operation %q", op)
	}
}

func (h *handler) audit(op authz.Operation, req authz.Request, d authz.Decision, outcome string, err error) {
	attrs := []any{
		"op", string(op),
		"outcome", outcome,
		"remote", req.RemoteAddr,
	}
	if d.Role != "" {
		attrs = append(attrs, "role", d.Role)
	}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
	}
	if req.CSR != nil {
		attrs = append(attrs, "requested_cn", req.CSR.Subject.CommonName)
	}
	if d.Constraints.CommonName != "" {
		attrs = append(attrs, "granted_cn", d.Constraints.CommonName)
	}
	if req.ClientCert != nil {
		attrs = append(attrs, "client_cn", req.ClientCert.Subject.CommonName)
	}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	h.logger.Info("enrollment decision", attrs...)
}

// readCSR decodes the body to DER, honoring base64 CTE and the size limit.
// The returned int is an HTTP status to use on error.
func (h *handler) readCSR(r *http.Request) ([]byte, int, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, h.maxReq+1))
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("read body: %w", err)
	}
	if int64(len(raw)) > h.maxReq {
		return nil, http.StatusRequestEntityTooLarge, errors.New("request too large")
	}
	if len(raw) == 0 {
		return nil, http.StatusBadRequest, errors.New("empty request body")
	}

	cte := r.Header.Get("Content-Transfer-Encoding")
	stripped := stripASCIIWhitespace(raw)
	if strings.EqualFold(cte, "base64") {
		dec, err := base64.StdEncoding.DecodeString(string(stripped))
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("base64 decode: %w", err)
		}
		return dec, 0, nil
	}
	// No/unknown CTE: try base64, fall back to raw DER (a DER SEQUENCE is not
	// valid base64, so this disambiguates cleanly in practice).
	if dec, derr := base64.StdEncoding.DecodeString(string(stripped)); derr == nil && len(dec) > 0 {
		return dec, 0, nil
	}
	return raw, 0, nil
}

// --- response writers ---

func writePKCS7(w http.ResponseWriter, der []byte) {
	w.Header().Set("Content-Type", ctPKCS7CertsOnly)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	w.Write(base64Lines(der))
}

func writeServerKeyGen(w http.ResponseWriter, keyDER, certP7 []byte) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Part 1: the generated private key (PKCS#8).
	keyHdr := textproto.MIMEHeader{}
	keyHdr.Set("Content-Type", ctPKCS8)
	keyHdr.Set("Content-Transfer-Encoding", "base64")
	if part, err := mw.CreatePart(keyHdr); err == nil {
		part.Write(base64Lines(keyDER))
	}

	// Part 2: the issued certificate (certs-only PKCS#7).
	certHdr := textproto.MIMEHeader{}
	certHdr.Set("Content-Type", ctPKCS7CertsOnly)
	certHdr.Set("Content-Transfer-Encoding", "base64")
	if part, err := mw.CreatePart(certHdr); err == nil {
		part.Write(base64Lines(certP7))
	}
	mw.Close()

	w.Header().Set("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

// --- helpers ---

// toSignOptions maps policy-approved constraints to OpenBao sign/issue params.
func toSignOptions(c authz.CertConstraints) bao.SignOptions {
	o := bao.SignOptions{
		CommonName:        c.CommonName,
		AltNames:          c.DNSNames,
		IPSANs:            c.IPs,
		URISANs:           c.URIs,
		ExcludeCNFromSANs: c.ExcludeCNFromSANs,
	}
	if c.TTL > 0 {
		o.TTL = c.TTL.String()
	}
	return o
}

// pemCertsToDER extracts all CERTIFICATE blocks from a PEM bundle as DER.
func pemCertsToDER(pemBytes []byte) ([][]byte, error) {
	var out [][]byte
	rest := pemBytes
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, blk.Bytes)
		}
		rest = r
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found")
	}
	return out, nil
}

// singleCertDER returns the DER of the first CERTIFICATE block in a PEM string.
func singleCertDER(pemStr string) ([]byte, error) {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("expected a CERTIFICATE PEM block")
	}
	return blk.Bytes, nil
}

// singleBlockDER returns the DER of the first PEM block regardless of type
// (used for the private key, whose label varies by key algorithm).
func singleBlockDER(pemStr string) ([]byte, error) {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		return nil, errors.New("expected a PEM block")
	}
	return blk.Bytes, nil
}

// base64Lines base64-encodes der and wraps at 64 columns (RFC 2045 style).
func base64Lines(der []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(der)
	var b bytes.Buffer
	for len(enc) > 64 {
		b.WriteString(enc[:64])
		b.WriteByte('\n')
		enc = enc[64:]
	}
	b.WriteString(enc)
	b.WriteByte('\n')
	return b.Bytes()
}

func stripASCIIWhitespace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			out = append(out, c)
		}
	}
	return out
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
