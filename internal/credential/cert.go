package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// TestIdentityOrganization marks a certificate the page issued to itself.
const TestIdentityOrganization = "c2pa-inspector test identity"

// SelfSignedTemplate is the test identity's certificate: the shape the c2pa
// library's own example uses and its profile check accepts — digitalSignature,
// an emailProtection EKU, not a CA — valid for a year. It is ECDSA-only by
// design: x509 would sign an RSA template with PKCS#1 v1.5, which a CryptoKey
// imported for RSA-PSS cannot produce.
func SelfSignedTemplate(name string, now time.Time) (*x509.Certificate, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Test identity"
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("credential: serial: %w", err)
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{TestIdentityOrganization}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}, nil
}

// Summary is what the page shows about a loaded identity.
type Summary struct {
	Label       string `json:"label"`
	Kind        string `json:"kind"` // "test" or "imported"
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   string `json:"notBefore"`
	NotAfter    string `json:"notAfter"`
	Algorithm   string `json:"algorithm"`
	COSE        string `json:"cose"`
	Fingerprint string `json:"fingerprint"` // SHA-256 of the leaf, hex
	SelfSigned  bool   `json:"selfSigned"`
	ChainLength int    `json:"chainLength"`
}

// Summarize describes a chain for the page.
func Summarize(chain []*x509.Certificate, alg Algorithm, kind, label string) Summary {
	leaf := chain[0]
	fp := sha256.Sum256(leaf.Raw)
	if label == "" {
		label = leaf.Subject.CommonName
	}
	return Summary{
		Label:       label,
		Kind:        kind,
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		NotBefore:   leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    leaf.NotAfter.UTC().Format(time.RFC3339),
		Algorithm:   alg.String(),
		COSE:        alg.COSE,
		Fingerprint: hex.EncodeToString(fp[:]),
		SelfSigned:  len(chain) == 1 && leaf.Subject.String() == leaf.Issuer.String(),
		ChainLength: len(chain),
	}
}
