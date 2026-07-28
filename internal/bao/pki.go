package bao

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// CertBundle is the result of a sign/issue operation.
type CertBundle struct {
	// Certificate is the issued leaf certificate in PEM.
	Certificate string
	// IssuingCA is the immediate issuer (intermediate) certificate in PEM.
	IssuingCA string
	// CAChain is the issuer chain in PEM, leaf-issuer first (may be empty
	// depending on the OpenBao role's configuration).
	CAChain []string
	// PrivateKey is populated only by Issue (server-side key generation); it is
	// empty for Sign. Callers must treat it as sensitive.
	PrivateKey string
	// SerialNumber is the issued certificate's serial (colon-hex form).
	SerialNumber string
}

// pkiData is the OpenBao PKI response `data` block.
type pkiData struct {
	Data struct {
		Certificate  string   `json:"certificate"`
		IssuingCA    string   `json:"issuing_ca"`
		CAChain      []string `json:"ca_chain"`
		PrivateKey   string   `json:"private_key"`
		SerialNumber string   `json:"serial_number"`
	} `json:"data"`
}

func (p pkiData) bundle() *CertBundle {
	return &CertBundle{
		Certificate:  p.Data.Certificate,
		IssuingCA:    p.Data.IssuingCA,
		CAChain:      p.Data.CAChain,
		PrivateKey:   p.Data.PrivateKey,
		SerialNumber: p.Data.SerialNumber,
	}
}

// SignOptions are the constrained parameters the broker passes to OpenBao.
// The broker derives/validates these from the authenticated identity and policy
// before calling; OpenBao's role enforces them a second time (defense in depth).
type SignOptions struct {
	// CommonName, when set, overrides the CSR subject CN at issuance.
	CommonName string
	// AltNames / IPSANs / URISANs constrain the subject alternative names.
	AltNames []string
	IPSANs   []string
	URISANs  []string
	// TTL, when set, requests a specific validity (e.g. "720h"); the role caps it.
	TTL string
	// ExcludeCNFromSANs mirrors the OpenBao flag of the same name.
	ExcludeCNFromSANs bool
	// KeyType/KeyBits select the key OpenBao generates for Issue. They are
	// required when the role's key_type is "any" — which is the useful setting
	// for Sign, since it lets devices bring any policy-permitted key — and are
	// ignored by Sign, where the key comes from the CSR.
	KeyType string
	KeyBits int
	// Extra carries any additional role-permitted fields without a typed field here.
	Extra map[string]any
}

func (o SignOptions) apply(body map[string]any) {
	if o.CommonName != "" {
		body["common_name"] = o.CommonName
	}
	if len(o.AltNames) > 0 {
		body["alt_names"] = joinComma(o.AltNames)
	}
	if len(o.IPSANs) > 0 {
		body["ip_sans"] = joinComma(o.IPSANs)
	}
	if len(o.URISANs) > 0 {
		body["uri_sans"] = joinComma(o.URISANs)
	}
	if o.TTL != "" {
		body["ttl"] = o.TTL
	}
	if o.ExcludeCNFromSANs {
		body["exclude_cn_from_sans"] = true
	}
	for k, v := range o.Extra {
		body[k] = v
	}
}

// Sign signs a client-supplied PKCS#10 CSR via pki/sign/:role. This is the EST
// /simpleenroll and /simplereenroll path: the device holds its own private key.
func (c *Client) Sign(ctx context.Context, role, csrPEM string, opts SignOptions) (*CertBundle, error) {
	if role == "" {
		return nil, errors.New("bao: sign requires a role")
	}
	if csrPEM == "" {
		return nil, errors.New("bao: sign requires a CSR")
	}
	body := map[string]any{"csr": csrPEM, "format": "pem"}
	opts.apply(body)

	var out pkiData
	path := fmt.Sprintf("v1/%s/sign/%s", c.cfg.PKIMount, url.PathEscape(role))
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	if out.Data.Certificate == "" {
		return nil, errors.New("bao: sign returned no certificate")
	}
	return out.bundle(), nil
}

// Issue generates a key pair server-side and issues a certificate via
// pki/issue/:role. This backs EST /serverkeygen; the returned PrivateKey is
// sensitive and must be delivered to the client over the mTLS channel only.
func (c *Client) Issue(ctx context.Context, role, commonName string, opts SignOptions) (*CertBundle, error) {
	if role == "" {
		return nil, errors.New("bao: issue requires a role")
	}
	body := map[string]any{"format": "pem"}
	if commonName != "" {
		body["common_name"] = commonName
	}
	opts.apply(body)
	// Only meaningful here: pki/issue generates the key, pki/sign does not.
	if opts.KeyType != "" {
		body["key_type"] = opts.KeyType
	}
	if opts.KeyBits > 0 {
		body["key_bits"] = opts.KeyBits
	}

	var out pkiData
	path := fmt.Sprintf("v1/%s/issue/%s", c.cfg.PKIMount, url.PathEscape(role))
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	if out.Data.Certificate == "" {
		return nil, errors.New("bao: issue returned no certificate")
	}
	if out.Data.PrivateKey == "" {
		return nil, errors.New("bao: issue returned no private key")
	}
	return out.bundle(), nil
}

// CAChain fetches the mount's CA certificate chain as PEM, for serving EST
// /cacerts. The pki/ca_chain endpoint is unauthenticated in OpenBao but we send
// the token harmlessly; it returns the concatenated PEM chain directly.
func (c *Client) CAChain(ctx context.Context) ([]byte, error) {
	path := fmt.Sprintf("v1/%s/ca_chain", c.cfg.PKIMount)
	pem, err := c.doRawBytes(ctx, http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	if len(pem) == 0 {
		return nil, errors.New("bao: empty CA chain")
	}
	return pem, nil
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
