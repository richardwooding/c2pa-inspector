# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`c2pa-inspector` is a static GitHub Pages site that verifies — and, since v0.5.0, signs — C2PA /
Content Credentials entirely in the browser. The whole validator and signer is
[`github.com/richardwooding/c2pa`](https://github.com/richardwooding/c2pa) (pure Go) compiled to
WebAssembly; this repo is the thin wrapper around it plus the page. When a change concerns C2PA
semantics rather than plumbing or presentation, it belongs upstream in the library.

## Commands

```sh
go vet ./... && go test -race ./internal/...                                  # native half
GOOS=js GOARCH=wasm go vet ./... && GOOS=js GOARCH=wasm go fix -diff ./...     # must print nothing
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o site/c2pa.wasm ./wasm
GOOS=js GOARCH=wasm go test -exec "$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./wasm   # under Node 24
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" site/ && python3 -m http.server -d site 8080
```

`.github/workflows/ci.yml` runs all of that on pull requests (plus `node --check site/*.js` and a
wasm size report in the job summary); `deploy.yml` builds and ships `site/` on push to main.
Merge only when both CI jobs are green — the check must be a positive "all SUCCESS", never a grep
for the absence of "fail". A tag `vX.Y.Z` makes `release.yml` attach the wasm to a release that
names the c2pa engine version.

## Architecture

- **`wasm/`** (`//go:build js && wasm`) — the browser boundary. Two kinds of globals, and the
  difference is load-bearing: `c2paInspect`, `c2paManifest`, `c2paLibVersion` are **synchronous**
  and return JSON strings (app.js calls them inline); `c2paCredentialCreate`, `c2paCredentialImport`,
  `c2paSign` return **Promises**, because they await WebCrypto, and a promise cannot settle while the
  goroutine servicing a synchronous JS callback is still running — so `promisify` runs the work on
  its own goroutine and `await` blocks there. Arguments are copied out of JS before the goroutine
  starts. Every `js.FuncOf` is released (`await` releases both handlers whichever fires; the
  executor releases itself). Rejections are `Error`s with a `.code` from `userError` that `sign.js`
  switches on; a panic becomes a rejection, never a dead runtime.
- **`wasm/webcrypto.go`** — `webCryptoKey` wraps a non-extractable `CryptoKey` as `crypto.Signer` +
  `crypto.MessageSigner`. **WebCrypto only signs whole messages**, so `Sign(digest)` returns an error
  (nil-opts safe: go-cose passes `nil` for ECDSA) and all real signing goes through `SignMessage`.
  Encoding contract, the standard library's: DER for ECDSA (WebCrypto's raw `r‖s` converted by
  `credential.RawToDER`), raw for RSA-PSS and Ed25519. `x509.CreateCertificate` and c2pa v0.16+ both
  call `SignMessage`, so one key type mints its own certificate (x509 verifies the DER right there)
  and signs manifests. The hash comes from `opts`, never the curve.
- **`internal/credential`** — everything that needs no `syscall/js`, so it is tested natively:
  `Algorithm` (key → WebCrypto import/sign params and COSE name), PEM/PKCS#8 handling that **never
  decodes key material** (SEC 1 and PKCS#1 are re-wrapped as PKCS#8 by pure ASN.1, byte-identical to
  OpenSSL's output — asserted against `x509.MarshalPKCS8PrivateKey`), `RawToDER`, the test-identity
  template (`SelfSignedTemplate`, ECDSA-only: x509 would sign an RSA template with PKCS#1 v1.5, which
  an RSA-PSS CryptoKey cannot produce), `BuildManifest`. Errors never echo PEM.
- **`internal/report`** — the container sniff and the JSON shapes `app.js` renders (field names are a
  contract with it). `FromValidation` is used by inspection AND by the sign report, so a signed file
  is described exactly as a dropped file would be.
- **`site/`** — `app.js` (boot, drop zone, result cards, share links), `sign.js` (identity state,
  IndexedDB, sign form, the Signed card), `index.html` (page-specific CSS lives in its inline
  `<style>`). **`gloam.css`/`gloam.js` are vendored by `sync-gloam.sh` — never edit them.**

## Things to know before editing

- **On import, `Public()` is borrowed from the leaf certificate** — a non-extractable private key
  cannot export its public half — so nothing in `NewSigner`'s key↔leaf check could catch a wrong
  key. `credentialImport` therefore PROVES the match with a test signature over a nonce, verified in
  Go, before anything else. Keep it non-optional.
- **created/opened is decided through `c2pa.ExtractStore`, not `c2pa.Read`.** `Read` stops at a
  16 MiB triage cap; a store at the end of a larger file (PDF incremental update, BMFF box after
  `mdat`) would look absent and `created` would then be refused as already signed. `ExtractStore`
  reads as far as `Validate` since c2pa v0.16.1.
- **The card must not let a green tick answer a question the validator did not.** `Result.Binding`
  (c2pa v0.19.0's `ValidationResult.Binding`, passed through verbatim) says whether THESE bytes are
  the signed ones: `verified`, `failed`, `unevaluated` or `none`. A valid result with an
  `unevaluated` binding — a PDF manifest attached to an object the file carries (§A.4.3), a file
  past the scan cap, a fragmented video without its fragments — renders as the neutral verdict
  "Signed, but not bound to this file", NOT as "Verified"; `bindingSentence` in `app.js` is the one
  place that words it, and the FAQ (both the `<details>` and the JSON-LD copy of it) explains the
  phrase. `sign.js` derives its `bound` row from `report.binding` too, rather than matching
  `assertion.dataHash.match`/`bmffHash.match` by hand as it used to — that hand-rolled test missed
  `boxesHash` and the merkle paths entirely. Never reconstruct the state from `statuses`: the
  library records it at the decision point because an update manifest's binding statuses carry the
  PARENT manifest's label and `general.unsupported` is overloaded.
- **The sign report is the page's own default-trust verdict.** A self-signed test identity must read
  `signingCredential.untrusted` in the Signed card in the same words the inspector uses — that is
  the honest outcome, and `internal/credential`'s end-to-end test pins it. Do not anchor the report
  at the signer's own certificate to make it look green.
- **IndexedDB has no test.** Node has WebCrypto but no `indexedDB`, so `sign.js`'s persistence path
  is browser-only: check Chrome, Firefox and Safari (private windows too) by hand when touching it.
  Safari evicts script-writable storage after 7 days without interaction; Firefox private mode may
  reject `indexedDB.open` — the toggle disables itself on error.
- **Timestamps go through fetch and need CORS.** Go's js `http` transport is `fetch`; the POST has a
  custom content type, so it preflights, and most public TSAs send no CORS headers. Under Node, fetch
  has no CORS, so a TSA test there would prove nothing about browsers — there is none.
- **Size is watched, not budgeted.** The signing paths added ≈ +0.98 MiB raw / +211 KiB gzipped
  (13.70 → 14.68 MiB; 3.56 → 3.77 MiB gzipped) — more than the library-only estimate because the
  x509 writer, Promise plumbing and TSA client are linked too. CI prints both numbers on every PR.
- **Large files freeze the main thread** while Go hashes and validates (Sign runs one Validate
  internally and the report runs another). `sign.js` caps input at 64 MiB, paints its status before
  calling in, and re-enables the button after 35 s. A Worker is the real fix (a `CryptoKey` is
  structured-cloneable, so `postMessage` carries it) — tracked as a follow-up.
- The test identity's certificate lasts a year; a remembered one past that fails `NewSigner` with
  "not valid now", surfaced as code `expired` with "create a new test identity".
