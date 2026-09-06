package credential

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNoPEM is returned when the input holds no private-key PEM block.
	ErrNoPEM = errors.New("credential: no private key found in PEM")
	// ErrEncryptedKey is returned for a password-protected key; the password
	// never needs to reach the page — decrypt the file first.
	ErrEncryptedKey = errors.New("credential: the private key is encrypted; decrypt it first (openssl pkey -in key.pem -out plain.pem)")
	// ErrNoCertificate is returned when the chain PEM holds no certificate.
	ErrNoCertificate = errors.New("credential: no CERTIFICATE block found in PEM")
)

// ParsePrivateKeyPEM finds the first private-key block — PKCS#8 "PRIVATE KEY",
// SEC 1 "EC PRIVATE KEY" or PKCS#1 "RSA PRIVATE KEY" — and returns it as PKCS#8
// DER ready for subtle.importKey, with the algorithm read from its identifier.
// Other blocks (a certificate in the same file) are skipped. The key material
// is never decoded, and no error carries any of it.
func ParsePrivateKeyPEM(data []byte) (pkcs8DER []byte, alg Algorithm, err error) {
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, Algorithm{}, ErrNoPEM
		}
		if strings.Contains(block.Type, "ENCRYPTED") || block.Headers["Proc-Type"] == "4,ENCRYPTED" {
			return nil, Algorithm{}, ErrEncryptedKey
		}
		switch block.Type {
		case "PRIVATE KEY":
			alg, err := SniffPKCS8(block.Bytes)
			if err != nil {
				return nil, Algorithm{}, err
			}
			return block.Bytes, alg, nil
		case "EC PRIVATE KEY":
			return SEC1ToPKCS8(block.Bytes)
		case "RSA PRIVATE KEY":
			return PKCS1ToPKCS8(block.Bytes)
		}
	}
}

// ParseChainPEM collects every CERTIFICATE block in order, leaf first.
func ParseChainPEM(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %v", ErrNoCertificate, len(chain), err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, ErrNoCertificate
	}
	return chain, nil
}

// EncodeChainPEM renders a chain as concatenated CERTIFICATE blocks.
func EncodeChainPEM(chain []*x509.Certificate) string {
	var b strings.Builder
	for _, c := range chain {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}
