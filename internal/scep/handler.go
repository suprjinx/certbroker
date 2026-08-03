package scep

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
	"github.com/gr-oss/certbroker/internal/bao"
	"github.com/gr-oss/certbroker/internal/cms"
)

const (
	// defaultMaxRequestBytes bounds a PKIOperation body. Larger than EST's
	// because a CMS envelope wraps the CSR, but still a DoS guard.
	defaultMaxRequestBytes = 512 * 1024
	// defaultUpstreamTimeout bounds one OpenBao call.
	defaultUpstreamTimeout = 20 * time.Second

	ctPKIOperation = "application/x-pki-message"
	ctCACert       = "application/x-x509-ca-cert"
	ctCACertChain  = "application/x-x509-ca-ra-cert"
)

// Enroller is the subset of the OpenBao client SCEP needs.
type Enroller interface {
	Sign(ctx context.Context, role, csrPEM string, opts bao.SignOptions) (*bao.CertBundle, error)
	CAChain(ctx context.Context) ([]byte, error)
}

// Options configures the SCEP handler.
type Options struct {
	// RACert and RAKey are the broker's own identity: requests are encrypted to
	// this certificate and responses signed by this key.
	RACert *x509.Certificate
	RAKey  crypto.PrivateKey
	// DeviceRoots verifies a RenewalReq signer.
	DeviceRoots *x509.CertPool
	Enroller    Enroller
	Authorizer  authz.Authorizer
	// ParseCSR validates a recovered PKCS#10 (PoP, key type, key bounds).
	ParseCSR func(der []byte) (*x509.CertificateRequest, error)
	// ChallengePassword extracts the PKCS#9 challengePassword. Injected rather
	// than imported: it is a PKCS#10 concern shared with EST, and scep must not
	// depend on est.
	ChallengePassword func(*x509.CertificateRequest) (string, error)
	// VerifyIssued re-checks an issued certificate against the decision, the
	// same backstop EST applies against permissive OpenBao roles.
	VerifyIssued func(cert *x509.Certificate, c authz.CertConstraints) error
	// Digests is the CMS digest allowlist; empty uses cms.DefaultDigests.
	Digests []asn1.ObjectIdentifier
	// ReplayCache rejects repeated transactionID/senderNonce pairs. Required:
	// a nil cache would make every request replayable.
	ReplayCache *ReplayCache

	MaxRequestBytes int64
	UpstreamTimeout time.Duration
	Logger          *slog.Logger
}

type handler struct {
	opts     Options
	logger   *slog.Logger
	parser   *Parser
	resp     *Responder
	maxReq   int64
	upstream time.Duration
	caChain  []*x509.Certificate
}

// NewHandler builds the SCEP HTTP handler.
func NewHandler(opts Options) (http.Handler, error) {
	switch {
	case opts.RACert == nil || opts.RAKey == nil:
		return nil, errors.New("scep: RA certificate and key are required")
	case opts.Enroller == nil:
		return nil, errors.New("scep: Enroller is required")
	case opts.ParseCSR == nil:
		return nil, errors.New("scep: ParseCSR is required")
	case opts.ReplayCache == nil:
		// Fail closed rather than silently accepting replays.
		return nil, errors.New("scep: ReplayCache is required")
	}

	h := &handler{
		opts:     opts,
		logger:   opts.Logger,
		maxReq:   opts.MaxRequestBytes,
		upstream: opts.UpstreamTimeout,
	}
	if h.logger == nil {
		h.logger = slog.Default()
	}
	if h.maxReq <= 0 {
		h.maxReq = defaultMaxRequestBytes
	}
	if h.upstream <= 0 {
		h.upstream = defaultUpstreamTimeout
	}

	verifier := cms.Verifier{Digests: opts.Digests}
	h.parser = &Parser{
		RACert:      opts.RACert,
		RAKey:       opts.RAKey,
		DeviceRoots: opts.DeviceRoots,
		Verifier:    verifier,
		ParseCSR:    opts.ParseCSR,
	}
	h.resp = &Responder{RACert: opts.RACert, RAKey: opts.RAKey}
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := r.URL.Query().Get("operation")
	switch op {
	case "GetCACert":
		h.getCACert(w, r)
	case "GetCACaps":
		h.getCACaps(w, r)
	case "PKIOperation":
		h.pkiOperation(w, r)
	default:
		http.Error(w, "unsupported operation", http.StatusBadRequest)
	}
}

// getCACert returns the RA certificate together with the CA chain, so a client
// learns both who to encrypt to (RA) and who to trust (CA).
func (h *handler) getCACert(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.upstream)
	defer cancel()

	chain, err := h.caChainCerts(ctx)
	if err != nil {
		h.logger.Error("scep: fetch CA chain", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	// RA first, then the CA chain. A lone CA certificate would use
	// application/x-x509-ca-cert; carrying both requires the -ra- form.
	certs := append([]*x509.Certificate{h.opts.RACert}, chain...)
	der, err := cms.DegenerateCertsOnly(certs...)
	if err != nil {
		h.logger.Error("scep: encode CA chain", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ctCACertChain)
	w.WriteHeader(http.StatusOK)
	w.Write(der)
}

// getCACaps advertises what this server supports. Deliberately conservative:
// SHA-1 and DES are omitted, GetNextCACert is absent because there is no
// rollover support, and POSTPKIOperation avoids URL-length limits on the
// base64 GET form.
func (h *handler) getCACaps(w http.ResponseWriter, _ *http.Request) {
	caps := []string{
		"POSTPKIOperation",
		"Renewal",
		"SHA-256",
		"SHA-512",
		"AES",
		"SCEPStandard",
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(strings.Join(caps, "\n") + "\n"))
}

// pkiOperation handles enrollment and renewal.
func (h *handler) pkiOperation(w http.ResponseWriter, r *http.Request) {
	body, status, err := h.readMessage(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	req, err := h.parser.Parse(body)
	if err != nil {
		// Parse failures precede any identified transaction, so there is no
		// nonce to echo and no signed CertRep to build: answer at HTTP level.
		h.logger.Warn("scep: parse", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Replay check before any issuance work. Recorded on first sight, so a
	// request that fails downstream is not retryable either.
	if !h.opts.ReplayCache.Check(req.Attributes.TransactionID, req.Attributes.SenderNonce) {
		h.logger.Warn("scep: replayed message rejected",
			"remote", r.RemoteAddr, "type", req.Attributes.MessageType.String())
		h.fail(w, req, FailBadRequest, "replay")
		return
	}

	azReq := h.authzRequest(req, r)
	decision, err := h.opts.Authorizer.Authorize(r.Context(), azReq)
	if err != nil {
		h.audit(req, decision, "error", r.RemoteAddr, err)
		h.fail(w, req, FailBadRequest, "authorization error")
		return
	}
	if !decision.Allow {
		h.audit(req, decision, "deny", r.RemoteAddr, nil)
		h.fail(w, req, FailBadRequest, decision.Reason)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.upstream)
	defer cancel()

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: req.CSR.Raw,
	}))
	bundle, err := h.opts.Enroller.Sign(ctx, decision.Role, csrPEM, toSignOptions(decision.Constraints))
	if err != nil {
		h.audit(req, decision, "issue-error", r.RemoteAddr, err)
		h.fail(w, req, FailBadRequest, "issuance failed")
		return
	}

	issued, err := parseFirstCert(bundle.Certificate)
	if err != nil {
		h.logger.Error("scep: decode issued certificate", "err", err)
		h.fail(w, req, FailBadRequest, "internal error")
		return
	}
	if h.opts.VerifyIssued != nil {
		if err := h.opts.VerifyIssued(issued, decision.Constraints); err != nil {
			h.logger.Error("SECURITY: issued certificate exceeds authorized constraints; withholding it",
				"err", err, "role", decision.Role, "serial", bundle.SerialNumber,
				"hint", "check the OpenBao role's use_csr_sans and use_csr_common_name settings")
			h.audit(req, decision, "constraint-violation", r.RemoteAddr, err)
			h.fail(w, req, FailBadRequest, "issuance failed")
			return
		}
	}

	out, err := h.resp.Success(req, issued)
	if err != nil {
		h.logger.Error("scep: build response", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(req, decision, "issued", r.RemoteAddr, nil)
	writePKIMessage(w, out)
}

// authzRequest maps a SCEP request onto the shared authorization pipeline.
//
// SECURITY: ClientCert is populated ONLY when the signer chained to the device
// anchor. A PKCSReq signer is self-signed and must never reach this field, or
// StandardConstraints would pin issued names to a certificate the requester
// generated — see docs/threat-model.md T1 and §8.
func (h *handler) authzRequest(req *Request, r *http.Request) authz.Request {
	az := authz.Request{
		Operation:         authz.OpSimpleEnroll,
		CSR:               req.CSR,
		ChallengePassword: h.challengePassword(req.CSR),
		RemoteAddr:        r.RemoteAddr,
	}
	if req.Attributes.MessageType == RenewalReq {
		az.Operation = authz.OpSimpleReenroll
	}
	if req.SignerAuthenticated {
		az.ClientCert = req.Signer
	}
	return az
}

// challengePassword extracts the challenge, tolerating a parse failure: a
// malformed attribute means no secret was supplied, which the pipeline then
// treats as unauthenticated rather than as an error.
func (h *handler) challengePassword(csr *x509.CertificateRequest) string {
	if h.opts.ChallengePassword == nil {
		return ""
	}
	cp, err := h.opts.ChallengePassword(csr)
	if err != nil {
		h.logger.Warn("scep: challengePassword parse", "err", err)
		return ""
	}
	return cp
}

// readMessage returns the PKIOperation body. POST carries raw DER; the legacy
// GET form carries base64 in the message parameter.
func (h *handler) readMessage(r *http.Request) ([]byte, int, error) {
	switch r.Method {
	case http.MethodPost:
		raw, err := io.ReadAll(io.LimitReader(r.Body, h.maxReq+1))
		if err != nil {
			return nil, http.StatusBadRequest, errors.New("read body")
		}
		if int64(len(raw)) > h.maxReq {
			return nil, http.StatusRequestEntityTooLarge, errors.New("request too large")
		}
		if len(raw) == 0 {
			return nil, http.StatusBadRequest, errors.New("empty request body")
		}
		return raw, 0, nil

	case http.MethodGet:
		msg := r.URL.Query().Get("message")
		if msg == "" {
			return nil, http.StatusBadRequest, errors.New("missing message parameter")
		}
		if int64(len(msg)) > h.maxReq {
			return nil, http.StatusRequestEntityTooLarge, errors.New("request too large")
		}
		der, err := base64.StdEncoding.DecodeString(msg)
		if err != nil {
			return nil, http.StatusBadRequest, errors.New("invalid base64 message")
		}
		return der, 0, nil

	default:
		return nil, http.StatusMethodNotAllowed, errors.New("method not allowed")
	}
}

// fail returns a signed CertRep carrying a failure. The reason is logged but
// never sent: failInfo stays coarse so a client cannot probe policy.
func (h *handler) fail(w http.ResponseWriter, req *Request, info FailInfo, reason string) {
	h.logger.Info("scep: request refused", "reason", reason,
		"type", req.Attributes.MessageType.String())
	out, err := h.resp.Failure(req, info)
	if err != nil {
		h.logger.Error("scep: build failure response", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writePKIMessage(w, out)
}

func (h *handler) audit(req *Request, d authz.Decision, outcome, remote string, err error) {
	attrs := []any{
		"protocol", "scep",
		"op", req.Attributes.MessageType.String(),
		"outcome", outcome,
		"remote", remote,
		"transaction_id", string(req.Attributes.TransactionID),
		"authenticated", req.SignerAuthenticated,
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
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	h.logger.Info("enrollment decision", attrs...)
}

// caChainCerts fetches and parses the CA chain from OpenBao.
func (h *handler) caChainCerts(ctx context.Context) ([]*x509.Certificate, error) {
	pemBytes, err := h.opts.Enroller.CAChain(ctx)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	rest := pemBytes
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse CA chain: %w", err)
			}
			out = append(out, c)
		}
		rest = r
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates in CA chain")
	}
	return out, nil
}

func writePKIMessage(w http.ResponseWriter, der []byte) {
	w.Header().Set("Content-Type", ctPKIOperation)
	w.WriteHeader(http.StatusOK)
	w.Write(der)
}

func parseFirstCert(pemStr string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("expected a CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// toSignOptions maps approved constraints to OpenBao parameters.
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
