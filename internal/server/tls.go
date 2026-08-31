package server

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// NormalizePin canonicalizes a SHA-256 certificate fingerprint: lowercase
// hex, tolerating "sha256:" prefixes, colons and whitespace.
func NormalizePin(pin string) string {
	p := strings.ToLower(strings.TrimSpace(pin))
	p = strings.TrimPrefix(p, "sha256:")
	p = strings.ReplaceAll(p, ":", "")
	return p
}

// BuildTLSConfig implements design.md §10: TLS 1.3 minimum, mandatory client
// certificates verified against the private CA, plus SHA-256 fingerprint
// pinning of the client leaf so even a mis-issued cert from the same CA is
// rejected.
func BuildTLSConfig(certFile, keyFile, clientCAFile string, clientPins []string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("server: load server keypair: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("server: read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("server: client CA file contains no valid certificates")
	}
	pins := make(map[string]bool, len(clientPins))
	for _, p := range clientPins {
		n := NormalizePin(p)
		if len(n) != 64 {
			return nil, fmt.Errorf("server: client pin %q is not a sha256 hex fingerprint", p)
		}
		pins[n] = true
	}
	if len(pins) == 0 {
		return nil, errors.New("server: at least one client certificate pin is required")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no client certificate presented")
			}
			fp := sha256.Sum256(rawCerts[0])
			if !pins[hex.EncodeToString(fp[:])] {
				return errors.New("client certificate fingerprint not in pin allowlist")
			}
			return nil
		},
	}, nil
}
