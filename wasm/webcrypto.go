//go:build js && wasm

package main

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"syscall/js"

	"github.com/richardwooding/c2pa-inspector/internal/credential"
)

// errDigestSigning is what Sign returns: WebCrypto hashes internally and
// cannot sign a caller-supplied digest, so the key is usable only through
// crypto.MessageSigner — which the c2pa library (v0.16+) and x509 both honour.
var errDigestSigning = errors.New("webcrypto: cannot sign a precomputed digest; the key signs whole messages (crypto.MessageSigner)")

// browserError is a WebCrypto rejection for an operation this browser does
// not support (an Ed25519 import on an older engine, say).
type browserError struct {
	op  string
	alg credential.Algorithm
	err error
}

func (e *browserError) Error() string { return fmt.Sprintf("webcrypto: %s %s: %v", e.op, e.alg, e.err) }
func (e *browserError) Unwrap() error { return e.err }

// webCryptoKey is a non-extractable private CryptoKey seen as a Go key. It
// implements crypto.Signer for Public() and the type checks, and
// crypto.MessageSigner for the actual signing: the whole message goes to
// subtle.sign, which hashes it, and the signature comes back in the encoding
// the standard library contract asks for — DER for ECDSA (WebCrypto's raw
// r‖s converted), raw for RSA-PSS and Ed25519.
type webCryptoKey struct {
	key js.Value
	pub crypto.PublicKey
	alg credential.Algorithm
}

var _ crypto.MessageSigner = (*webCryptoKey)(nil)

// newWebCryptoKey pairs a CryptoKey with the public key it is claimed to
// belong to — from exportKey on create, from the leaf certificate on import
// (a non-extractable private key cannot export its own) — and checks the two
// name the same algorithm. Whether the pair truly matches is proven by a test
// signature in credentialImport; here only the shape is checked.
func newWebCryptoKey(key js.Value, pub crypto.PublicKey) (*webCryptoKey, error) {
	alg, err := credential.AlgorithmForPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if key.Type() != js.TypeObject {
		return nil, errors.New("webcrypto: no CryptoKey was given")
	}
	ka := key.Get("algorithm")
	if name := ka.Get("name"); name.Type() == js.TypeString && name.String() != alg.Kind {
		return nil, fmt.Errorf("%w: the key is %s but the certificate needs %s", errKeyMismatch, name.String(), alg.Kind)
	}
	if curve := ka.Get("namedCurve"); alg.Kind == "ECDSA" && curve.Type() == js.TypeString && curve.String() != alg.Curve {
		return nil, fmt.Errorf("%w: the key is on %s but the certificate needs %s", errKeyMismatch, curve.String(), alg.Curve)
	}
	if bits := ka.Get("modulusLength"); alg.Kind == "RSA-PSS" && bits.Type() == js.TypeNumber && bits.Int() != alg.Bits {
		return nil, fmt.Errorf("%w: the key is RSA %d but the certificate needs RSA %d", errKeyMismatch, bits.Int(), alg.Bits)
	}
	return &webCryptoKey{key: key, pub: pub, alg: alg}, nil
}

func (k *webCryptoKey) Public() crypto.PublicKey { return k.pub }

// Sign serves only Ed25519, whose "digest" is the message itself (go-cose's
// Ed25519 path and x509 both pass the message with a zero hash). Everything
// else needs SignMessage. opts may be nil — go-cose passes nil for ECDSA.
func (k *webCryptoKey) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k.alg.Kind == "Ed25519" && (opts == nil || opts.HashFunc() == 0) {
		return k.SignMessage(rnd, digest, opts)
	}
	return nil, errDigestSigning
}

// SignMessage signs msg with subtle.sign using the parameters opts calls for.
func (k *webCryptoKey) SignMessage(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	params, err := k.alg.SignParams(opts)
	if err != nil {
		return nil, err
	}
	s, err := subtle()
	if err != nil {
		return nil, err
	}
	res, err := await(s.Call("sign", js.ValueOf(params), k.key, toUint8Array(msg)))
	if err != nil {
		return nil, &browserError{op: "sign with", alg: k.alg, err: err}
	}
	sig, err := fromUint8Array(res)
	if err != nil {
		return nil, fmt.Errorf("webcrypto: sign returned %v", err)
	}
	if k.alg.Kind == "ECDSA" {
		return credential.RawToDER(sig)
	}
	return sig, nil
}

// generateP256 makes a non-extractable ECDSA P-256 key pair and returns the
// private CryptoKey with the public key's SPKI (public keys always export).
func generateP256() (priv js.Value, spki []byte, err error) {
	s, err := subtle()
	if err != nil {
		return js.Undefined(), nil, err
	}
	alg := credential.Algorithm{Kind: "ECDSA", Curve: "P-256"}
	pair, err := await(s.Call("generateKey", js.ValueOf(alg.ImportParams()), false, js.ValueOf([]any{"sign", "verify"})))
	if err != nil {
		return js.Undefined(), nil, &browserError{op: "generate", alg: alg, err: err}
	}
	exported, err := await(s.Call("exportKey", "spki", pair.Get("publicKey")))
	if err != nil {
		return js.Undefined(), nil, &browserError{op: "export the public key of", alg: alg, err: err}
	}
	spki, err = fromUint8Array(exported)
	if err != nil {
		return js.Undefined(), nil, err
	}
	return pair.Get("privateKey"), spki, nil
}

// importPKCS8 imports a PKCS#8 key as a non-extractable, sign-only CryptoKey.
func importPKCS8(der []byte, alg credential.Algorithm) (js.Value, error) {
	s, err := subtle()
	if err != nil {
		return js.Undefined(), err
	}
	key, err := await(s.Call("importKey", "pkcs8", toUint8Array(der), js.ValueOf(alg.ImportParams()), false, js.ValueOf([]any{"sign"})))
	if err != nil {
		return js.Undefined(), &browserError{op: "import", alg: alg, err: err}
	}
	return key, nil
}
