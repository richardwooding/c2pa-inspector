//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"syscall/js"
	"testing"
	"time"

	"github.com/richardwooding/c2pa"

	"github.com/richardwooding/c2pa-inspector/internal/credential"
	"github.com/richardwooding/c2pa-inspector/internal/report"
)

// These tests run under Node through go_js_wasm_exec: Node's globalThis.crypto
// is the same WebCrypto the browser has, so the bridge is exercised for real.

func TestMain(m *testing.M) {
	registerGlobals()
	os.Exit(m.Run())
}

func encodeImage(t *testing.T, enc func(*bytes.Buffer, image.Image) error) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 20, 20))
	for x := range 20 {
		for y := range 20 {
			img.Set(x, y, color.RGBA{uint8(x * 12), 80, uint8(y * 12), 255})
		}
	}
	var buf bytes.Buffer
	if err := enc(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func unsignedJPEG(t *testing.T) []byte {
	return encodeImage(t, func(b *bytes.Buffer, i image.Image) error { return jpeg.Encode(b, i, nil) })
}

func unsignedPNG(t *testing.T) []byte {
	return encodeImage(t, func(b *bytes.Buffer, i image.Image) error { return png.Encode(b, i) })
}

// settle awaits p and returns the fulfilment value or the rejection reason.
func settle(t *testing.T, p js.Value) (value, reason js.Value, ok bool) {
	t.Helper()
	ch := make(chan struct {
		v  js.Value
		ok bool
	}, 1)
	onOK := js.FuncOf(func(_ js.Value, a []js.Value) any {
		ch <- struct {
			v  js.Value
			ok bool
		}{a[0], true}
		return nil
	})
	onErr := js.FuncOf(func(_ js.Value, a []js.Value) any {
		ch <- struct {
			v  js.Value
			ok bool
		}{a[0], false}
		return nil
	})
	defer onOK.Release()
	defer onErr.Release()
	p.Call("then", onOK, onErr)
	r := <-ch
	if r.ok {
		return r.v, js.Undefined(), true
	}
	return js.Undefined(), r.v, false
}

func TestAwait(t *testing.T) {
	v, err := await(js.Global().Get("Promise").Call("resolve", 42))
	if err != nil || v.Int() != 42 {
		t.Fatalf("resolve: %v %v", v, err)
	}
	_, err = await(js.Global().Get("Promise").Call("reject", js.Global().Get("TypeError").New("boom")))
	if err == nil || err.Error() != "TypeError: boom" {
		t.Fatalf("reject: %v", err)
	}
	_, err = await(js.Global().Get("Promise").Call("reject", "plain"))
	if err == nil || err.Error() != "plain" {
		t.Fatalf("reject string: %v", err)
	}
}

func TestPromisify(t *testing.T) {
	v, _, ok := settle(t, promisify(func() (any, error) { return "done", nil }))
	if !ok || v.String() != "done" {
		t.Fatalf("resolve: %v %v", v, ok)
	}
	_, reason, ok := settle(t, promisify(func() (any, error) { return nil, errKeyMismatch }))
	if ok || reason.Get("code").String() != "key-mismatch" || reason.Get("message").String() == "" {
		t.Fatalf("reject: %v", reason)
	}
	_, reason, ok = settle(t, promisify(func() (any, error) { panic("kaboom") }))
	if ok || reason.Get("code").String() != "internal" {
		t.Fatalf("panic: %v", reason)
	}
}

func TestWebCryptoKey_ECDSA(t *testing.T) {
	priv, spki, err := generateP256()
	if err != nil {
		t.Fatal(err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubAny.(*ecdsa.PublicKey)
	key, err := newWebCryptoKey(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the whole message, not a digest")
	sig, err := key.SignMessage(nil, msg, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("SignMessage output does not verify as DER over SHA-256(msg)")
	}
	if _, err := key.Sign(nil, digest[:], crypto.SHA256); !errors.Is(err, errDigestSigning) {
		t.Fatalf("Sign(digest, SHA256) = %v", err)
	}
	if _, err := key.Sign(nil, digest[:], nil); !errors.Is(err, errDigestSigning) {
		t.Fatalf("Sign(digest, nil) = %v (go-cose's shape must not panic)", err)
	}
	if _, err := key.SignMessage(nil, msg, nil); err == nil {
		t.Fatal("ECDSA SignMessage with nil opts accepted")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := newWebCryptoKey(priv, &other.PublicKey); !errors.Is(err, errKeyMismatch) {
		t.Fatalf("P-256 key against a P-384 public key: %v", err)
	}
}

// goCredential mints a key in Go plus a certificate the test identity's
// template shape, as PEM, so import can be exercised for every key type.
func goCredential(t *testing.T, key crypto.Signer, sec1 bool) (keyPEM, certPEM string) {
	t.Helper()
	tmpl, err := credential.SelfSignedTemplate("Imported "+t.Name(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SignatureAlgorithm = 0 // let x509 pick per key type
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	var kb *pem.Block
	if ec, ok := key.(*ecdsa.PrivateKey); ok && sec1 {
		d, _ := x509.MarshalECPrivateKey(ec)
		kb = &pem.Block{Type: "EC PRIVATE KEY", Bytes: d}
	} else {
		d, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		kb = &pem.Block{Type: "PRIVATE KEY", Bytes: d}
	}
	return string(pem.EncodeToMemory(kb)), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func credentialFrom(t *testing.T, v js.Value) (key js.Value, certPEM string, summary credential.Summary) {
	t.Helper()
	key, certPEM = v.Get("key"), v.Get("certPEM").String()
	raw := js.Global().Get("JSON").Call("stringify", v.Get("summary")).String()
	if err := json.Unmarshal([]byte(raw), &summary); err != nil {
		t.Fatalf("summary: %v", err)
	}
	if key.Type() != js.TypeObject || key.Get("extractable").Bool() {
		t.Fatalf("key = %v (must be a non-extractable CryptoKey)", key)
	}
	return key, certPEM, summary
}

func signWith(t *testing.T, key js.Value, certPEM string, data []byte, action, title string) ([]byte, report.Result) {
	t.Helper()
	out, rep, err := signAsset(data, signOptions{key: key, certPEM: certPEM, title: title, action: action, digitalSourceType: "digitalCapture"})
	if err != nil {
		t.Fatalf("signAsset: %v", err)
	}
	return out, rep
}

func anchoredValid(t *testing.T, container c2pa.Container, data []byte, certPEM string) c2pa.ValidationResult {
	t.Helper()
	chain, err := credential.ParseChainPEM([]byte(certPEM))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(chain[len(chain)-1])
	res := c2pa.Validate(context.Background(), container, bytes.NewReader(data), c2pa.WithSigningTrust(pool), c2pa.WithOnlineRevocation(false))
	if !res.Valid {
		t.Fatalf("anchored validate: %v", res.FirstFailure())
	}
	return res
}

func TestCreateSignValidate(t *testing.T) {
	v, err := credentialCreate("CI test identity")
	if err != nil {
		t.Fatal(err)
	}
	key, certPEM, summary := credentialFrom(t, v)
	if summary.Kind != "test" || !summary.SelfSigned || summary.COSE != "ES256" || summary.Label != "CI test identity" {
		t.Fatalf("summary = %+v", summary)
	}

	for _, tc := range []struct {
		name      string
		container c2pa.Container
		data      []byte
	}{{"jpeg", c2pa.JPEG, unsignedJPEG(t)}, {"png", c2pa.PNG, unsignedPNG(t)}} {
		t.Run(tc.name, func(t *testing.T) {
			out, rep := signWith(t, key, certPEM, tc.data, "auto", "ci."+tc.name)
			// The page's honest verdict: bound and signed, signer untrusted.
			if rep.Valid || !rep.Has("claimSignature.validated") || !rep.Has("assertion.dataHash.match") || !rep.Has("signingCredential.untrusted") {
				t.Fatalf("report = %+v", rep)
			}
			if rep.Title != "ci."+tc.name || rep.ClaimGenerator == "" {
				t.Fatalf("claims = %q %q", rep.Title, rep.ClaimGenerator)
			}
			res := anchoredValid(t, tc.container, out, certPEM)
			if res.VerifiedSigner() != "CI test identity" || !res.Has(c2pa.StatusAssertionDataHashMatch) {
				t.Fatalf("anchored: signer %q", res.VerifiedSigner())
			}
			// Re-sign: auto becomes opened and the prior manifest is chained.
			again, rep2 := signWith(t, key, certPEM, out, "auto", "again")
			if !rep2.Has("claimSignature.validated") {
				t.Fatalf("re-sign report = %+v", rep2)
			}
			if !anchoredValid(t, tc.container, again, certPEM).Has(c2pa.StatusIngredientManifestValidated) {
				t.Fatal("re-sign did not chain the prior manifest")
			}
			_, _, err := signAsset(out, signOptions{key: key, certPEM: certPEM, action: "created"})
			if !errors.Is(err, credential.ErrAlreadySigned) {
				t.Fatalf("created on a signed asset: %v", err)
			}
			if code, _ := userError(err); code != "already-signed" {
				t.Fatalf("code = %s", code)
			}
		})
	}
}

func TestCredentialImport(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		key  crypto.Signer
		sec1 bool
		cose string
	}{
		{"p256 pkcs8", p256, false, "ES256"},
		{"p256 sec1", p256, true, "ES256"},
		{"p384", p384, false, "ES384"},
		{"ed25519", ed, false, "EdDSA"},
	}
	if !testing.Short() {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			name string
			key  crypto.Signer
			sec1 bool
			cose string
		}{"rsa", rsaKey, false, "PS256"})
	}
	jpg := unsignedJPEG(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyPEM, certPEM := goCredential(t, tc.key, tc.sec1)
			v, err := credentialImport(keyPEM, certPEM)
			if be, ok := errors.AsType[*browserError](err); ok {
				t.Skipf("this WebCrypto cannot import %s: %v", be.alg, be.err)
			}
			if err != nil {
				t.Fatal(err)
			}
			key, gotPEM, summary := credentialFrom(t, v)
			if gotPEM != certPEM || summary.Kind != "imported" || summary.COSE != tc.cose || !summary.SelfSigned {
				t.Fatalf("summary = %+v", summary)
			}
			out, rep := signWith(t, key, certPEM, jpg, "auto", "imported")
			if !rep.Has("claimSignature.validated") || !rep.Has("assertion.dataHash.match") {
				t.Fatalf("report = %+v", rep)
			}
			anchoredValid(t, c2pa.JPEG, out, certPEM)
		})
	}
}

func TestCredentialImport_Refusals(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	keyA, certA := goCredential(t, a, false)
	_, certB := goCredential(t, b, false)
	keyC, _ := goCredential(t, c, false)
	encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
	cases := []struct {
		name         string
		keyPEM, cert string
		want         error
		code         string
	}{
		{"same curve, other key", keyA, certB, errKeyMismatch, "key-mismatch"},
		{"other curve", keyC, certA, errKeyMismatch, "key-mismatch"},
		{"encrypted", encrypted, certA, credential.ErrEncryptedKey, "encrypted-key"},
		{"no key", certA, certA, credential.ErrNoPEM, "bad-input"},
		{"no cert", keyA, keyA, credential.ErrNoCertificate, "bad-input"},
		{"junk key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", certA, credential.ErrUnsupportedKey, "unsupported-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := credentialImport(tc.keyPEM, tc.cert)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if code, msg := userError(err); code != tc.code || msg == "" {
				t.Fatalf("code = %s (%s)", code, msg)
			}
		})
	}
}

func bmffBox(typ string, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	size := uint32(8 + len(payload))
	b[0], b[1], b[2], b[3] = byte(size>>24), byte(size>>16), byte(size>>8), byte(size)
	copy(b[4:], typ)
	return append(b, payload...)
}

func TestSignAsset_Refusals(t *testing.T) {
	v, err := credentialCreate("refusals")
	if err != nil {
		t.Fatal(err)
	}
	key, certPEM, _ := credentialFrom(t, v)
	// Media fragments with no initialization segment: no 'moov', so the library
	// cannot bind them here and says to use SignFragmented. It must NOT carry a
	// 'moov', which would make it the flat single-file fragmented arrangement
	// that c2pa v0.19.0 signs.
	fragmented := bytes.Join([][]byte{
		bmffBox("ftyp", []byte("isom\x00\x00\x02\x00isom")),
		bmffBox("moof", nil),
		bmffBox("mdat", []byte("media")),
	}, nil)
	cases := []struct {
		name string
		data []byte
		opts signOptions
		want error
		code string
	}{
		{"fragmented mp4", fragmented, signOptions{key: key, certPEM: certPEM}, c2pa.ErrFragmentedBMFF, "fragmented"},
		{"not an asset", []byte("hello world"), signOptions{key: key, certPEM: certPEM}, errUnsupportedFile, "unsupported-file"},
		{"bad action", unsignedJPEG(t), signOptions{key: key, certPEM: certPEM, action: "edited"}, credential.ErrBadAction, "bad-input"},
		{"bad source type", unsignedJPEG(t), signOptions{key: key, certPEM: certPEM, digitalSourceType: "madeUp"}, credential.ErrBadDigitalSourceType, "bad-input"},
		{"no chain", unsignedJPEG(t), signOptions{key: key}, credential.ErrNoCertificate, "bad-input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := signAsset(tc.data, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if code, _ := userError(err); code != tc.code {
				t.Fatalf("code = %s", code)
			}
		})
	}
}

func TestSignAsset_Fixture(t *testing.T) {
	data, err := os.ReadFile("../site/sample.jpg")
	if err != nil {
		t.Skip("fixture not present:", err)
	}
	v, err := credentialCreate("fixture")
	if err != nil {
		t.Fatal(err)
	}
	key, certPEM, _ := credentialFrom(t, v)
	if _, _, err := signAsset(data, signOptions{key: key, certPEM: certPEM, action: "created"}); !errors.Is(err, credential.ErrAlreadySigned) {
		t.Fatalf("created on the signed fixture: %v", err)
	}
	out, rep := signWith(t, key, certPEM, data, "auto", "re-signed fixture")
	if rep.Title != "re-signed fixture" || !rep.Has("claimSignature.validated") {
		t.Fatalf("report = %+v", rep)
	}
	if !bytes.Contains(out, []byte("c2pa-inspector")) {
		t.Fatal("claim generator not embedded")
	}
}

func TestGlobalsShape(t *testing.T) {
	g := js.Global()
	for _, name := range []string{"c2paInspect", "c2paManifest", "c2paLibVersion", "c2paCredentialCreate", "c2paCredentialImport", "c2paSign"} {
		if g.Get(name).Type() != js.TypeFunction {
			t.Errorf("%s is %v", name, g.Get(name).Type())
		}
	}
	jpg := unsignedJPEG(t)
	if r := g.Call("c2paInspect", toUint8Array(jpg)); r.Type() != js.TypeString {
		t.Fatalf("c2paInspect returned %v", r.Type())
	}
	cred, _, ok := settle(t, g.Call("c2paCredentialCreate", "Globals"))
	if !ok {
		t.Fatal("c2paCredentialCreate rejected")
	}
	opts := js.ValueOf(map[string]any{"key": cred.Get("key"), "certPEM": cred.Get("certPEM").String(), "title": "g.jpg", "action": "auto", "digitalSourceType": "digitalCapture"})
	res, reason, ok := settle(t, g.Call("c2paSign", toUint8Array(jpg), opts))
	if !ok {
		t.Fatalf("c2paSign rejected: %v", reason.Get("message"))
	}
	if !res.Get("bytes").InstanceOf(g.Get("Uint8Array")) {
		t.Fatal("bytes is not a Uint8Array")
	}
	var rep report.Result
	if err := json.Unmarshal([]byte(res.Get("report").String()), &rep); err != nil || !rep.Present || rep.Title != "g.jpg" {
		t.Fatalf("report: %v %+v", err, rep)
	}
	_, reason, ok = settle(t, g.Call("c2paSign", toUint8Array(jpg), js.ValueOf(map[string]any{})))
	if ok || reason.Get("code").Type() != js.TypeString {
		t.Fatalf("missing key should reject with a code: %v", reason)
	}
	_, reason, ok = settle(t, g.Call("c2paCredentialImport", "junk", "junk"))
	if ok || reason.Get("code").String() != "bad-input" {
		t.Fatalf("junk import: %v", reason.Get("code"))
	}
}
