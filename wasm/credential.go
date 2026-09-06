//go:build js && wasm

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"
	"time"

	"github.com/richardwooding/c2pa"

	"github.com/richardwooding/c2pa-inspector/internal/credential"
)

// errKeyMismatch: the private key does not belong to the first certificate.
var errKeyMismatch = errors.New("the private key does not belong to the first certificate in the chain")

// claimGenerator names this page in the manifests it writes.
const claimGenerator = "c2pa-inspector"

// credentialCreate mints a test identity: a non-extractable P-256 key in
// WebCrypto and a self-signed certificate Go builds around its public key —
// x509.CreateCertificate hands the TBS to SignMessage, so the browser key
// signs its own certificate and the DER conversion is verified right there.
func credentialCreate(name string) (js.Value, error) {
	priv, spki, err := generateP256()
	if err != nil {
		return js.Undefined(), err
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return js.Undefined(), fmt.Errorf("webcrypto: exported public key: %w", err)
	}
	key, err := newWebCryptoKey(priv, pub)
	if err != nil {
		return js.Undefined(), err
	}
	tmpl, err := credential.SelfSignedTemplate(name, time.Now())
	if err != nil {
		return js.Undefined(), err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return js.Undefined(), fmt.Errorf("%w: certificate: %v", errInternal, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return js.Undefined(), fmt.Errorf("%w: certificate: %v", errInternal, err)
	}
	chain := []*x509.Certificate{cert}
	if _, err := c2pa.NewSigner(key, chain, c2pa.WithClaimGenerator(claimGenerator, inspectorVersion())); err != nil {
		return js.Undefined(), err
	}
	return credentialObject(priv, chain, credential.Summarize(chain, key.alg, "test", tmpl.Subject.CommonName)), nil
}

// credentialImport takes a PEM private key and PEM chain, imports the key into
// WebCrypto non-extractably, PROVES it belongs to the leaf with a test
// signature (Public() is borrowed from the leaf, so nothing else would notice
// a mismatch), and runs the library's chain and profile checks. The PEM text
// is not retained; only the CryptoKey and the chain come back.
func credentialImport(keyPEM, chainPEM string) (js.Value, error) {
	der, alg, err := credential.ParsePrivateKeyPEM([]byte(keyPEM))
	if err != nil {
		return js.Undefined(), err
	}
	chain, err := credential.ParseChainPEM([]byte(chainPEM))
	if err != nil {
		return js.Undefined(), err
	}
	leafAlg, err := credential.AlgorithmForPublicKey(chain[0].PublicKey)
	if err != nil {
		return js.Undefined(), err
	}
	if !alg.Same(leafAlg) {
		return js.Undefined(), fmt.Errorf("%w: the key is %s, the certificate %s", errKeyMismatch, alg, leafAlg)
	}
	ck, err := importPKCS8(der, alg)
	if err != nil {
		return js.Undefined(), err
	}
	key, err := newWebCryptoKey(ck, chain[0].PublicKey)
	if err != nil {
		return js.Undefined(), err
	}
	if err := proveKeyMatchesLeaf(key, chain[0]); err != nil {
		return js.Undefined(), err
	}
	if _, err := c2pa.NewSigner(key, chain, c2pa.WithClaimGenerator(claimGenerator, inspectorVersion())); err != nil {
		return js.Undefined(), err
	}
	return credentialObject(ck, chain, credential.Summarize(chain, leafAlg, "imported", "")), nil
}

// proveKeyMatchesLeaf signs a fresh nonce with the CryptoKey and verifies it
// with the leaf's public key in Go.
func proveKeyMatchesLeaf(key *webCryptoKey, leaf *x509.Certificate) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	var opts crypto.SignerOpts
	switch key.alg.Kind {
	case "ECDSA":
		opts = key.alg.Hash
	case "RSA-PSS":
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	default:
		opts = crypto.Hash(0)
	}
	sig, err := key.SignMessage(nil, nonce, opts)
	if err != nil {
		return err
	}
	ok := false
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		h := key.alg.Hash.New()
		h.Write(nonce)
		ok = ecdsa.VerifyASN1(pub, h.Sum(nil), sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(nonce)
		ok = rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case ed25519.PublicKey:
		ok = ed25519.Verify(pub, nonce, sig)
	}
	if !ok {
		return errKeyMismatch
	}
	return nil
}

// credentialObject is what the create and import promises resolve to:
// {key: CryptoKey, certPEM: string, summary: object}.
func credentialObject(key js.Value, chain []*x509.Certificate, s credential.Summary) js.Value {
	raw, _ := json.Marshal(s)
	return js.ValueOf(map[string]any{
		"key":     key,
		"certPEM": credential.EncodeChainPEM(chain),
		"summary": js.Global().Get("JSON").Call("parse", string(raw)),
	})
}
