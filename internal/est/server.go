package est

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// TLSConfig builds the listener's TLS config. RequestClientCert, unverified at
// handshake: each endpoint checks its own anchor (bootstrap vs device).
func TLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
	}
}

// VerifyPeer verifies the peer certificate against roots and returns the leaf,
// which must carry the client-auth EKU. Extra certs are candidate intermediates.
func VerifyPeer(state *tls.ConnectionState, roots *x509.CertPool) (*x509.Certificate, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate presented")
	}
	if roots == nil {
		return nil, errors.New("no trust anchor configured for this operation")
	}

	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, fmt.Errorf("client certificate verification failed: %w", err)
	}
	return leaf, nil
}
