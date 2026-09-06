//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"syscall/js"
	"time"

	"github.com/richardwooding/c2pa"

	"github.com/richardwooding/c2pa-inspector/internal/credential"
	"github.com/richardwooding/c2pa-inspector/internal/report"
)

var (
	errUnsupportedFile = errors.New(report.UnsupportedMessage)
	errTimeout         = errors.New("signing took too long and was stopped")
	errInternal        = errors.New("the signed output did not validate — nothing was produced")
)

// signOptions are c2paSign's second argument.
type signOptions struct {
	key                                               js.Value
	certPEM, title, action, digitalSourceType, tsaURL string
}

func parseSignOptions(v js.Value) (signOptions, error) {
	if v.Type() != js.TypeObject {
		return signOptions{}, errors.New("c2paSign needs an options object")
	}
	str := func(name string) string {
		f := v.Get(name)
		if f.Type() != js.TypeString {
			return ""
		}
		return f.String()
	}
	o := signOptions{key: v.Get("key"), certPEM: str("certPEM"), title: str("title"), action: str("action"),
		digitalSourceType: str("digitalSourceType"), tsaURL: strings.TrimSpace(str("tsaURL"))}
	if o.key.Type() != js.TypeObject {
		return signOptions{}, errors.New("no signing identity: create or import one first")
	}
	return o, nil
}

// signAsset embeds a manifest into data with the WebCrypto key and returns the
// signed bytes plus the inspector's own verdict on them — the default trust
// list, so a self-signed identity reads as untrusted here exactly as it will
// everywhere else.
func signAsset(data []byte, o signOptions) ([]byte, report.Result, error) {
	container, name, ok := report.Sniff(data)
	if !ok {
		return nil, report.Result{}, errUnsupportedFile
	}
	chain, err := credential.ParseChainPEM([]byte(o.certPEM))
	if err != nil {
		return nil, report.Result{}, err
	}
	key, err := newWebCryptoKey(o.key, chain[0].PublicKey)
	if err != nil {
		return nil, report.Result{}, err
	}
	opts := []c2pa.SignerOption{c2pa.WithClaimGenerator(claimGenerator, inspectorVersion())}
	deadline := report.Deadline
	if o.tsaURL != "" {
		// The request goes out through fetch, so the TSA must allow CORS.
		opts = append(opts, c2pa.WithTimestampAuthority(o.tsaURL), c2pa.WithTimestampHTTPClient(&http.Client{Timeout: 20 * time.Second}))
		deadline = 60 * time.Second
	}
	signer, err := c2pa.NewSigner(key, chain, opts...)
	if err != nil {
		return nil, report.Result{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	// ExtractStore reads as far as Sign does; Read's triage cap would miss a
	// store at the end of a large file and make "auto" choose created.
	store, _ := c2pa.ExtractStore(ctx, container, bytes.NewReader(data))
	m, err := credential.BuildManifest(credential.SignRequest{Title: o.title, Action: o.action, DigitalSourceType: o.digitalSourceType},
		len(store) > 0, c2pa.GeneratorInfo{Name: claimGenerator, Version: inspectorVersion()})
	if err != nil {
		return nil, report.Result{}, err
	}
	var out bytes.Buffer
	if err := signer.Sign(ctx, container, bytes.NewReader(data), &out, m); err != nil {
		if ctx.Err() != nil {
			return nil, report.Result{}, errTimeout
		}
		return nil, report.Result{}, err
	}
	rep := report.FromValidation(name, c2pa.Validate(ctx, container, bytes.NewReader(out.Bytes())))
	if ctx.Err() != nil {
		return nil, report.Result{}, errTimeout
	}
	return out.Bytes(), rep, nil
}

// inspectorVersion is the page's own revision from the build info — the same
// no-ldflags principle as c2paLibVersion — or "dev".
func inspectorVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

// userError maps an error to the code sign.js switches on and the sentence
// it shows.
func userError(err error) (code, msg string) {
	var be *browserError
	switch {
	case errors.Is(err, credential.ErrAlreadySigned),
		errors.Is(err, c2pa.ErrManifestInvalid) && strings.Contains(err.Error(), "already carries"):
		return "already-signed", "This file already has Content Credentials. Choose the \"opened\" action to add a manifest that chains to the existing one."
	case errors.Is(err, c2pa.ErrFragmentedBMFF):
		return "fragmented", "This MP4 is fragmented (streaming-style). Fragmented video cannot be signed in this release."
	case errors.Is(err, errKeyMismatch):
		return "key-mismatch", "The private key does not belong to the first certificate in the chain."
	case errors.Is(err, c2pa.ErrSignerChain) && strings.Contains(err.Error(), "not valid now"):
		return "expired", "This identity's certificate is not valid right now — it may have expired. Create a new test identity or import a current chain."
	case errors.Is(err, c2pa.ErrSignerChain):
		return "chain-rejected", "The certificate chain was rejected: " + strings.TrimPrefix(err.Error(), "c2pa: signing certificate chain unusable: ")
	case errors.Is(err, credential.ErrEncryptedKey):
		return "encrypted-key", "The key is password-protected. Decrypt it first (openssl pkey -in key.pem -out plain.pem) — the password never needs to reach this page."
	case errors.Is(err, credential.ErrUnsupportedKey), errors.Is(err, c2pa.ErrSignerKey):
		return "unsupported-key", "Use an ECDSA P-256/384/521, RSA (2048 bits or more) or Ed25519 key as PKCS#8, SEC 1 or PKCS#1 PEM. " + err.Error()
	case errors.As(err, &be):
		return "browser-unsupported", fmt.Sprintf("This browser's WebCrypto cannot %s %s (%v). Ed25519 needs Chrome 137+, Firefox 130+ or Safari 17+.", be.op, be.alg, be.err)
	case errors.Is(err, c2pa.ErrTimestamp):
		return "tsa", "The timestamp authority could not be used from a browser: it must be https and allow cross-origin (CORS) requests. Nothing was written — sign without a timestamp or choose a CORS-enabled TSA."
	case errors.Is(err, c2pa.ErrAssetTooLarge):
		return "too-large", "The file exceeds the signing size cap."
	case errors.Is(err, c2pa.ErrMalformedAsset):
		return "malformed", "The file could not be parsed as its container type: " + err.Error()
	case errors.Is(err, errUnsupportedFile), errors.Is(err, c2pa.ErrUnsupportedContainer):
		return "unsupported-file", report.UnsupportedMessage
	case errors.Is(err, errTimeout), errors.Is(err, context.DeadlineExceeded):
		return "timeout", "Signing took too long and was stopped."
	case errors.Is(err, errNoWebCrypto):
		return "no-webcrypto", "Signing needs WebCrypto, which browsers enable only on https or localhost."
	case errors.Is(err, credential.ErrNoPEM), errors.Is(err, credential.ErrNoCertificate),
		errors.Is(err, credential.ErrBadAction), errors.Is(err, credential.ErrBadDigitalSourceType):
		return "bad-input", strings.TrimPrefix(err.Error(), "credential: ")
	case errors.Is(err, c2pa.ErrSelfCheckFailed), errors.Is(err, errDigestSigning), errors.Is(err, errInternal):
		return "internal", "The signed output did not validate, so nothing was produced. Please report this with the file type. (" + err.Error() + ")"
	}
	return "error", err.Error()
}
