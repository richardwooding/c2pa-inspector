package credential

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"strings"
	"testing"
	"time"

	"github.com/richardwooding/c2pa"
)

func mustPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func ecKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var rsaOnce *rsa.PrivateKey

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	if rsaOnce == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaOnce = k
	}
	return rsaOnce
}

func assertNoKeyLeak(t *testing.T, err error, der []byte) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "BEGIN") || (len(der) > 8 && strings.Contains(err.Error(), string(der[:8]))) {
		t.Fatalf("error carries key material: %v", err)
	}
}

func TestSniffPKCS8(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		key  any
		want Algorithm
	}{
		{"p256", ecKey(t, elliptic.P256()), ecdsaP256},
		{"p384", ecKey(t, elliptic.P384()), ecdsaP384},
		{"p521", ecKey(t, elliptic.P521()), ecdsaP521},
		{"rsa", rsaKey(t), Algorithm{Kind: "RSA-PSS", Bits: 2048, Hash: crypto.SHA256, COSE: "PS256"}},
		{"ed25519", ed, ed25519Alg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SniffPKCS8(mustPKCS8(t, tc.key))
			if err != nil || got != tc.want {
				t.Fatalf("SniffPKCS8 = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
	t.Run("rsassa-pss identifier", func(t *testing.T) {
		der, _ := asn1.Marshal(pkcs8{Algo: pkixAlg(oidPublicKeyRSAPSS), PrivateKey: []byte{0x30, 0x00}})
		_, err := SniffPKCS8(der)
		if !errors.Is(err, ErrUnsupportedKey) || !strings.Contains(err.Error(), "openssl rsa") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("small rsa", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SniffPKCS8(mustPKCS8(t, k)); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("1024-bit RSA accepted: %v", err)
		}
	})
	for name, der := range map[string][]byte{"empty": nil, "truncated": mustPKCS8(t, ecKey(t, elliptic.P256()))[:20], "junk": []byte("not der at all")} {
		if _, err := SniffPKCS8(der); !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func pkixAlg(oid asn1.ObjectIdentifier) (a struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}) {
	a.Algorithm = oid
	return a
}

func TestSEC1ToPKCS8(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key := ecKey(t, curve)
		sec1, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		out, alg, err := SEC1ToPKCS8(sec1)
		if err != nil {
			t.Fatalf("%s: %v", curve.Params().Name, err)
		}
		// The canonical form: byte-identical to Go's own PKCS#8 encoding, which
		// is also what OpenSSL writes and what WebCrypto imports.
		if !bytes.Equal(out, mustPKCS8(t, key)) {
			t.Fatalf("%s: re-wrapped PKCS#8 differs from x509.MarshalPKCS8PrivateKey", curve.Params().Name)
		}
		back, err := x509.ParsePKCS8PrivateKey(out)
		if err != nil || !back.(*ecdsa.PrivateKey).Equal(key) {
			t.Fatalf("%s: round trip: %v", curve.Params().Name, err)
		}
		if want, _ := AlgorithmForPublicKey(&key.PublicKey); alg != want {
			t.Fatalf("%s: alg %+v want %+v", curve.Params().Name, alg, want)
		}
	}
	// A SEC 1 key without its [0] curve cannot be placed.
	key := ecKey(t, elliptic.P256())
	var ec ecPrivateKey
	sec1, _ := x509.MarshalECPrivateKey(key)
	if _, err := asn1.Unmarshal(sec1, &ec); err != nil {
		t.Fatal(err)
	}
	noCurve, _ := asn1.Marshal(ecPrivateKey{Version: 1, PrivateKey: ec.PrivateKey, PublicKey: ec.PublicKey})
	if _, _, err := SEC1ToPKCS8(noCurve); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("curve-less SEC 1 accepted: %v", err)
	}
	if _, _, err := SEC1ToPKCS8([]byte("junk")); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("junk accepted: %v", err)
	}
}

func TestPKCS1ToPKCS8(t *testing.T) {
	key := rsaKey(t)
	out, alg, err := PKCS1ToPKCS8(x509.MarshalPKCS1PrivateKey(key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, mustPKCS8(t, key)) {
		t.Fatal("re-wrapped PKCS#8 differs from x509.MarshalPKCS8PrivateKey")
	}
	if alg.Kind != "RSA-PSS" || alg.Bits != 2048 || alg.COSE != "PS256" {
		t.Fatalf("alg = %+v", alg)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, _, err := PKCS1ToPKCS8(x509.MarshalPKCS1PrivateKey(small)); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("1024-bit accepted: %v", err)
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	pkcs8 := mustPKCS8(t, key)
	sec1, _ := x509.MarshalECPrivateKey(key)
	cert := selfSigned(t, key)
	block := func(typ string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }

	cases := []struct {
		name string
		pem  []byte
		want []byte
		err  error
	}{
		{"pkcs8", block("PRIVATE KEY", pkcs8), pkcs8, nil},
		{"sec1", block("EC PRIVATE KEY", sec1), pkcs8, nil},
		{"rsa pkcs1", block("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey(t))), mustPKCS8(t, rsaKey(t)), nil},
		{"cert then key", append(block("CERTIFICATE", cert.Raw), block("PRIVATE KEY", pkcs8)...), pkcs8, nil},
		{"encrypted pkcs8", block("ENCRYPTED PRIVATE KEY", []byte{0x30, 0x00}), nil, ErrEncryptedKey},
		{"encrypted legacy", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}, Bytes: sec1}), nil, ErrEncryptedKey},
		{"cert only", block("CERTIFICATE", cert.Raw), nil, ErrNoPEM},
		{"not pem", []byte("hello"), nil, ErrNoPEM},
		{"empty", nil, nil, ErrNoPEM},
		{"junk key", block("PRIVATE KEY", []byte("junk")), nil, ErrUnsupportedKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := ParsePrivateKeyPEM(tc.pem)
			assertNoKeyLeak(t, err, pkcs8)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("got %d bytes, err %v", len(got), err)
			}
		})
	}
}

func TestParseChainPEM(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	cert := selfSigned(t, key)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	chain, err := ParseChainPEM(data)
	if err != nil || len(chain) != 1 || !chain[0].Equal(cert) {
		t.Fatalf("chain = %d, %v", len(chain), err)
	}
	if _, err := ParseChainPEM([]byte("nothing")); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("err = %v", err)
	}
	if _, err := ParseChainPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("err = %v", err)
	}
	if EncodeChainPEM(chain) != string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})) {
		t.Fatal("EncodeChainPEM differs")
	}
}

func TestRawToDER(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key := ecKey(t, curve)
		size := (curve.Params().BitSize + 7) / 8
		digest := make([]byte, 32)
		for i := range 200 {
			digest[0], digest[1] = byte(i), byte(i>>8)
			r, s, err := ecdsa.Sign(rand.Reader, key, digest)
			if err != nil {
				t.Fatal(err)
			}
			raw := make([]byte, 2*size)
			r.FillBytes(raw[:size])
			s.FillBytes(raw[size:])
			der, err := RawToDER(raw)
			if err != nil {
				t.Fatalf("%s: %v", curve.Params().Name, err)
			}
			if !ecdsa.VerifyASN1(&key.PublicKey, digest, der) {
				t.Fatalf("%s: DER does not verify", curve.Params().Name)
			}
			back, err := DERToRaw(der, size)
			if err != nil || !bytes.Equal(back, raw) {
				t.Fatalf("%s: DERToRaw round trip: %v", curve.Params().Name, err)
			}
		}
	}
	for name, raw := range map[string][]byte{"empty": nil, "odd": {1, 2, 3}, "zero r": make([]byte, 64)} {
		if _, err := RawToDER(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestAlgorithmParams(t *testing.T) {
	if _, err := ecdsaP256.SignParams(nil); err == nil {
		t.Error("ECDSA with nil opts accepted")
	}
	p, err := ecdsaP384.SignParams(crypto.SHA384)
	if err != nil || p["hash"].(map[string]any)["name"] != "SHA-384" {
		t.Errorf("ECDSA params = %v, %v", p, err)
	}
	if _, err := ecdsaP256.SignParams(crypto.MD5); err == nil {
		t.Error("ECDSA with MD5 accepted")
	}
	p, err = rsaPSS.SignParams(&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil || p["saltLength"] != 32 {
		t.Errorf("RSA-PSS params = %v, %v", p, err)
	}
	if _, err := rsaPSS.SignParams(crypto.SHA256); err == nil {
		t.Error("RSA PKCS#1 v1.5 request accepted for an RSA-PSS key")
	}
	if _, err := rsaPSS.SignParams(&rsa.PSSOptions{Hash: crypto.SHA512}); err == nil {
		t.Error("RSA-PSS with a foreign hash accepted")
	}
	if _, err := ed25519Alg.SignParams(nil); err != nil {
		t.Errorf("Ed25519 nil opts: %v", err)
	}
	if _, err := ed25519Alg.SignParams(crypto.Hash(0)); err != nil {
		t.Errorf("Ed25519 Hash(0): %v", err)
	}
	if _, err := ed25519Alg.SignParams(crypto.SHA256); err == nil {
		t.Error("Ed25519 with a digest accepted")
	}
	if ecdsaP256.ImportParams()["namedCurve"] != "P-256" || rsaPSS.ImportParams()["hash"] != "SHA-256" || ed25519Alg.ImportParams()["name"] != "Ed25519" {
		t.Error("import params")
	}
	if ecdsaP256.String() != "ECDSA P-256" || (Algorithm{Kind: "RSA-PSS", Bits: 3072}).String() != "RSA-PSS 3072" || ed25519Alg.String() != "Ed25519" {
		t.Error("String")
	}
	if !ecdsaP256.Same(ecdsaP256) || ecdsaP256.Same(ecdsaP384) || !rsaPSS.Same(Algorithm{Kind: "RSA-PSS", Bits: 2048}) {
		t.Error("Same")
	}
}

func TestDigitalSourceTypeURL(t *testing.T) {
	cases := map[string]string{
		"":                                     "",
		"empty":                                c2pa.DigitalSourceTypeEmpty,
		"digitalCapture":                       c2pa.DigitalSourceTypeDigitalCapture,
		"trainedAlgorithmicMedia":              c2pa.DigitalSourceTypeTrainedAlgorithmicMedia,
		"compositeWithTrainedAlgorithmicMedia": iptcDigitalSourceTypePrefix + "compositeWithTrainedAlgorithmicMedia",
		" print ":                              iptcDigitalSourceTypePrefix + "print",
		"https://example.com/x":                "https://example.com/x",
	}
	for in, want := range cases {
		if got, err := DigitalSourceTypeURL(in); err != nil || got != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := DigitalSourceTypeURL("madeUp"); !errors.Is(err, ErrBadDigitalSourceType) {
		t.Errorf("madeUp: %v", err)
	}
}

func TestBuildManifest(t *testing.T) {
	agent := c2pa.GeneratorInfo{Name: "c2pa-inspector", Version: "test"}
	cases := []struct {
		action  string
		present bool
		want    string
		err     error
	}{
		{"auto", false, c2pa.ActionCreated, nil},
		{"", true, c2pa.ActionOpened, nil},
		{"created", false, c2pa.ActionCreated, nil},
		{"created", true, "", ErrAlreadySigned},
		{"opened", false, c2pa.ActionOpened, nil},
		{"opened", true, c2pa.ActionOpened, nil},
		{"edited", false, "", ErrBadAction},
	}
	for _, tc := range cases {
		m, err := BuildManifest(SignRequest{Title: " t ", Action: tc.action, DigitalSourceType: "digitalCapture"}, tc.present, agent)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("%s/%v: err = %v, want %v", tc.action, tc.present, err, tc.err)
			}
			continue
		}
		if err != nil || m.Title != "t" || len(m.Actions) != 1 || m.Actions[0].Action != tc.want ||
			m.Actions[0].SoftwareAgent != agent || m.Actions[0].DigitalSourceType != c2pa.DigitalSourceTypeDigitalCapture {
			t.Errorf("%s/%v: %+v, %v", tc.action, tc.present, m, err)
		}
	}
	if _, err := BuildManifest(SignRequest{DigitalSourceType: "nope"}, false, agent); !errors.Is(err, ErrBadDigitalSourceType) {
		t.Errorf("bad dst: %v", err)
	}
}

// selfSigned mints the test-identity certificate with an in-memory key.
func selfSigned(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl, err := SelfSignedTemplate("Native Test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func unsignedJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 24, 24))
	for x := range 24 {
		for y := range 24 {
			img.Set(x, y, color.RGBA{uint8(x * 10), uint8(y * 10), 90, 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestSelfSignedTemplate_EndToEnd: the template the page issues is accepted by
// the c2pa library, signs a file that validates against itself — and, against
// the default trust list, is honestly untrusted. That last fact is what the
// page's trust box states.
func TestSelfSignedTemplate_EndToEnd(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	cert := selfSigned(t, key)
	if cert.Subject.CommonName != "Native Test" || cert.IsCA || cert.Subject.Organization[0] != TestIdentityOrganization {
		t.Fatalf("cert = %v", cert.Subject)
	}
	if _, err := SelfSignedTemplate("  ", time.Now()); err != nil {
		t.Fatal(err)
	}
	signer, err := c2pa.NewSigner(key, []*x509.Certificate{cert}, c2pa.WithClaimGenerator("c2pa-inspector", "test"))
	if err != nil {
		t.Fatalf("NewSigner rejects the template: %v", err)
	}
	m, err := BuildManifest(SignRequest{Title: "native.jpg", DigitalSourceType: "digitalCapture"}, false, c2pa.GeneratorInfo{Name: "c2pa-inspector", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	ctx := context.Background()
	if err := signer.Sign(ctx, c2pa.JPEG, bytes.NewReader(unsignedJPEG(t)), &out, m); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	own := c2pa.Validate(ctx, c2pa.JPEG, bytes.NewReader(out.Bytes()), c2pa.WithSigningTrust(pool), c2pa.WithMaxIngredientDepth(0), c2pa.WithOnlineRevocation(false))
	if !own.Valid || !own.Has(c2pa.StatusAssertionDataHashMatch) || own.VerifiedSigner() != "Native Test" {
		t.Fatalf("anchored validate: valid=%v signer=%q", own.Valid, own.VerifiedSigner())
	}
	def := c2pa.Validate(ctx, c2pa.JPEG, bytes.NewReader(out.Bytes()))
	if def.Valid || !def.Has(c2pa.StatusSigningCredentialUntrusted) || !def.Has(c2pa.StatusClaimSignatureValidated) {
		t.Fatalf("default validate should be signature-valid but untrusted; got valid=%v", def.Valid)
	}
	s := Summarize([]*x509.Certificate{cert}, ecdsaP256, "test", "")
	if !s.SelfSigned || s.ChainLength != 1 || s.Label != "Native Test" || s.COSE != "ES256" || len(s.Fingerprint) != 64 {
		t.Fatalf("summary = %+v", s)
	}
}
