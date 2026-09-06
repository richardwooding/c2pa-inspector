// Package credential is the pure-Go half of in-browser signing: everything
// about keys, certificates and manifests that needs no syscall/js, so it can
// be tested natively. The wasm bridge (wasm/) wraps a WebCrypto CryptoKey
// around it.
//
// The design constraint that shapes this package: WebCrypto only signs whole
// messages and never hands out a non-extractable private key. So keys are
// described (Algorithm) rather than parsed, PEM is re-wrapped rather than
// decoded, and WebCrypto's raw ECDSA signatures are converted to the DER that
// x509 and the c2pa library expect from a crypto.MessageSigner.
package credential

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
)

// Algorithm describes a signing key the way WebCrypto and COSE each need it.
type Algorithm struct {
	Kind  string      // "ECDSA", "RSA-PSS" or "Ed25519" — WebCrypto's algorithm name
	Curve string      // "P-256", "P-384", "P-521" for ECDSA
	Bits  int         // RSA modulus size
	Hash  crypto.Hash // the digest the COSE algorithm uses; 0 for Ed25519
	COSE  string      // "ES256", "ES384", "ES512", "PS256", "EdDSA"
}

var (
	ecdsaP256  = Algorithm{Kind: "ECDSA", Curve: "P-256", Hash: crypto.SHA256, COSE: "ES256"}
	ecdsaP384  = Algorithm{Kind: "ECDSA", Curve: "P-384", Hash: crypto.SHA384, COSE: "ES384"}
	ecdsaP521  = Algorithm{Kind: "ECDSA", Curve: "P-521", Hash: crypto.SHA512, COSE: "ES512"}
	rsaPSS     = Algorithm{Kind: "RSA-PSS", Hash: crypto.SHA256, COSE: "PS256"}
	ed25519Alg = Algorithm{Kind: "Ed25519", COSE: "EdDSA"}
)

// ErrUnsupportedKey is returned for a key type or size the C2PA profile and
// WebCrypto cannot both handle.
var ErrUnsupportedKey = errors.New("credential: unsupported private key")

// AlgorithmForPublicKey mirrors the c2pa library's key → COSE algorithm rule:
// P-256/384/521 → ES256/384/512, RSA of at least 2048 bits → PS256,
// Ed25519 → EdDSA.
func AlgorithmForPublicKey(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return ecdsaP256, nil
		case elliptic.P384():
			return ecdsaP384, nil
		case elliptic.P521():
			return ecdsaP521, nil
		}
		return Algorithm{}, fmt.Errorf("%w: ECDSA curve %s", ErrUnsupportedKey, k.Curve.Params().Name)
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return Algorithm{}, fmt.Errorf("%w: RSA key is %d bits; the C2PA profile needs 2048", ErrUnsupportedKey, k.N.BitLen())
		}
		a := rsaPSS
		a.Bits = k.N.BitLen()
		return a, nil
	case ed25519.PublicKey:
		return ed25519Alg, nil
	}
	return Algorithm{}, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
}

// Same reports whether two algorithms name the same key type — the check an
// imported key must pass against the certificate it claims to belong to.
func (a Algorithm) Same(b Algorithm) bool {
	return a.Kind == b.Kind && a.Curve == b.Curve && (a.Kind != "RSA-PSS" || a.Bits == 0 || b.Bits == 0 || a.Bits == b.Bits)
}

// String is the label the page shows: "ECDSA P-256", "RSA-PSS 2048", "Ed25519".
func (a Algorithm) String() string {
	switch a.Kind {
	case "ECDSA":
		return "ECDSA " + a.Curve
	case "RSA-PSS":
		if a.Bits > 0 {
			return fmt.Sprintf("RSA-PSS %d", a.Bits)
		}
		return "RSA-PSS"
	default:
		return a.Kind
	}
}

// ImportParams is the algorithm object subtle.importKey / generateKey takes
// for this key type. An RSA key is imported for RSA-PSS with SHA-256: PS256 is
// the only RSA algorithm the c2pa library signs with, and a CryptoKey is bound
// to one algorithm at import.
func (a Algorithm) ImportParams() map[string]any {
	switch a.Kind {
	case "ECDSA":
		return map[string]any{"name": "ECDSA", "namedCurve": a.Curve}
	case "RSA-PSS":
		return map[string]any{"name": "RSA-PSS", "hash": "SHA-256"}
	default:
		return map[string]any{"name": a.Kind}
	}
}

// SignParams is the algorithm object subtle.sign takes for a SignMessage call
// with opts — the opts x509.CreateCertificate and the c2pa library pass. The
// hash comes from opts, never from the curve: the two agree today, and
// hard-coding it would mis-sign silently if either ever changed. RSA is
// PSS-only (the import hash is fixed at SHA-256, so any other hash is
// refused); Ed25519 signs the message itself and accepts only a zero hash.
func (a Algorithm) SignParams(opts crypto.SignerOpts) (map[string]any, error) {
	switch a.Kind {
	case "ECDSA":
		if opts == nil {
			return nil, errors.New("credential: ECDSA signing needs the digest algorithm in opts")
		}
		name, ok := hashName(opts.HashFunc())
		if !ok {
			return nil, fmt.Errorf("credential: ECDSA cannot sign with hash %v", opts.HashFunc())
		}
		return map[string]any{"name": "ECDSA", "hash": map[string]any{"name": name}}, nil
	case "RSA-PSS":
		pss, ok := opts.(*rsa.PSSOptions)
		if !ok {
			return nil, errors.New("credential: an RSA key imported for RSA-PSS cannot sign PKCS#1 v1.5")
		}
		if pss.HashFunc() != crypto.SHA256 {
			return nil, fmt.Errorf("credential: RSA-PSS key is bound to SHA-256, not %v", pss.HashFunc())
		}
		salt := pss.SaltLength
		if salt <= 0 { // PSSSaltLengthEqualsHash (0) and PSSSaltLengthAuto (-1)
			salt = crypto.SHA256.Size()
		}
		return map[string]any{"name": "RSA-PSS", "saltLength": salt}, nil
	case "Ed25519":
		if opts != nil && opts.HashFunc() != 0 {
			return nil, fmt.Errorf("credential: Ed25519 signs messages, not %v digests", opts.HashFunc())
		}
		return map[string]any{"name": "Ed25519"}, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedKey, a.Kind)
}

// hashName is the WebCrypto spelling of a Go hash.
func hashName(h crypto.Hash) (string, bool) {
	switch h {
	case crypto.SHA256:
		return "SHA-256", true
	case crypto.SHA384:
		return "SHA-384", true
	case crypto.SHA512:
		return "SHA-512", true
	}
	return "", false
}
