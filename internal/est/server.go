package est

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// TLSConfig builds the server TLS configuration for the EST listener.
//
// ClientAuth is RequestClientCert: the server asks for a client certificate but
// does NOT verify it during the handshake. The broker verifies presented certs
// explicitly per-endpoint (see VerifyPeer) against the correct trust anchor —
// the bootstrap CA for initial enrollment versus the device CA for
// re-enrollment — which a single handshake-time ClientCAs pool cannot express.
//
// TLS is terminated in-app, so this works unchanged behind an L4 passthrough
// proxy.
func TLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
	}
}

// VerifyPeer verifies the client certificate from a TLS connection against the
// given roots, returning the verified leaf. It returns an error when no client
// certificate was presented or when the chain does not verify.
//
// Any additional certificates the client sent are treated as candidate
// intermediates. The leaf must carry the client-auth EKU.
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
