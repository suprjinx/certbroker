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
	// CAChain is the issuer chain in PEM, leaf-issuer first; may be empty.
	CAChain []string
	// PrivateKey is set only by Issue and must be treated as sensitive.
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

// SignOptions are the policy-bounded parameters passed to OpenBao, which
// enforces its own role constraints a second time (defense in depth).
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
	// KeyType/KeyBits select the key Issue generates; required when the role's
	// key_type is "any". Ignored by Sign, where the key comes from the CSR.
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

// Sign signs a client CSR via pki/sign/:role — the /simpleenroll path, where
// the device holds its own key.
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

// Issue generates the key server-side via pki/issue/:role, backing EST
// /serverkeygen. The returned PrivateKey is sensitive: mTLS channel only.
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

// CAChain fetches the mount's CA chain as PEM for EST /cacerts. The endpoint is
// unauthenticated upstream; the token is sent harmlessly.
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
