# c2pa-inspector

**Verify — and sign — C2PA / Content Credentials entirely in your browser** —
[richardwooding.github.io/c2pa-inspector](https://richardwooding.github.io/c2pa-inspector/)

Drop a JPEG, PNG, HEIC, AVIF, MP4, MOV, or PDF on the page and get the full C2PA validation
result: the COSE signature,
the certificate chain against the official C2PA trust list, assertion and hard-binding
hashes (`c2pa.hash.data` for JPEG/PNG, `c2pa.hash.bmff.v2`/`.v3` for BMFF assets), and the
RFC 3161 timestamp — with every C2PA §15 status code the validator
recorded. Nothing is uploaded; the validator is
[richardwooding/c2pa](https://github.com/richardwooding/c2pa) (pure Go, no cgo) compiled to
WebAssembly and running in the page.

The card answers two questions separately, because they come apart on real files: whether the
signature and the signer check out, and whether **these bytes** are the ones that were signed. A
credential can be perfectly valid while nothing here proves it describes the file you dropped — a
PDF manifest attached to an image the document carries, a fragmented video inspected without its
fragments — and that reads as "Signed, but not bound to this file" rather than as a green tick.

## Signing in the browser

The page can also embed Content Credentials into a file. The private key is created (or
imported) into the browser's WebCrypto store as **non-extractable** and never leaves it: the Go
code builds the manifest, hashes the file and asks WebCrypto for each signature. Only the signed
file leaves the browser, as a download.

- **Test identity** — one click makes a P-256 key and a self-signed certificate that satisfies the
  C2PA profile. Files signed with it verify everywhere (signature and content hash), and every
  verifier — this page included — reports the signer as `signingCredential.untrusted`. That is the
  honest outcome: the certificate proves the file has not changed since you signed it, not who you
  are. The Signed card says so in those words.
- **Import** — paste or pick a PEM private key (PKCS#8, `EC PRIVATE KEY` or `RSA PRIVATE KEY`,
  unencrypted) and a PEM chain, leaf first. The key is re-wrapped as PKCS#8 without being decoded,
  imported non-extractable, and proven to belong to the leaf with a test signature before the
  library's chain and profile checks run. ECDSA P-256/384/521, RSA (2048+, signed as PS256) and
  Ed25519 where the browser supports it. A chain issued by a CA on the C2PA trust list gives a
  trusted result.
- **Remember in this browser** — opt-in; IndexedDB stores the `CryptoKey` (still non-extractable)
  and the chain. On by default for a test identity, off for an imported key. Safari may evict it
  after seven days without a visit.
- **Timestamps** — the optional RFC 3161 field only works with an authority that allows
  cross-origin requests over https, which most public ones do not; a failure writes nothing.
- Signing an asset that already carries credentials keeps them: the existing manifest becomes the
  new one's `parentOf` ingredient (the `auto` action picks `opened`; `created` is refused).

Under the hood this needs one thing of the library: a key that can only sign whole messages —
WebCrypto's `SubtleCrypto.sign` — implements Go's standard `crypto.MessageSigner`, which
`x509.CreateCertificate` and `c2pa` (v0.16+) both honour. WebCrypto returns ECDSA signatures as raw
`r‖s`; the bridge converts them to the DER the contract asks for, and x509 verifies the result when
the test identity signs its own certificate.

## Why this can exist

The reference C2PA implementation is Rust with C bindings. Because
`richardwooding/c2pa` is pure Go — CBOR, COSE, X.509, CMS/RFC 3161, all in Go with the
official trust lists embedded — the *entire* validator compiles to a single `.wasm` binary
with `GOOS=js GOARCH=wasm go build`. The browser wrapper is ~150 lines
([`wasm/main.go`](wasm/main.go)); everything else is the library, unchanged.

## Layout

- `wasm/` — the Go→WASM wrapper. Synchronous globals `c2paInspect(Uint8Array) -> JSON`,
  `c2paManifest`, `c2paLibVersion`; Promise-returning `c2paCredentialCreate`, `c2paCredentialImport`,
  `c2paSign` (`webcrypto.go` is the `crypto.MessageSigner` over a `CryptoKey`; `promise.go` the
  await/promisify plumbing). Tested under Node, which has the same WebCrypto.
- `internal/report` — the container sniff and the JSON shapes the page renders; `internal/credential`
  — PEM/PKCS#8 handling that never decodes a key, the ECDSA encoding conversion, the test-identity
  template, manifest building. Plain Go, tested natively.
- `site/` — the static page (GitHub Pages): [gloam](https://github.com/richardwooding/gloam)-styled
  UI, drop zone, result rendering (`app.js`), the signing panel (`sign.js`). `c2pa.wasm` and
  `wasm_exec.js` are built by CI, not committed. `gloam.css`/`gloam.js` are vendored by
  `sync-gloam.sh` — do not edit them.
- `.github/workflows/ci.yml` — the pull-request gate (native and wasm tests, wasm size);
  `deploy.yml` builds the WASM and deploys `site/` to Pages on push to main.

## Build locally

```sh
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o site/c2pa.wasm ./wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" site/
python3 -m http.server -d site 8080   # then open http://localhost:8080 (localhost counts as secure for WebCrypto)

go test -race ./internal/...                                                   # native
GOOS=js GOARCH=wasm go test -exec "$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./wasm   # needs node
```

## The samples

`site/sample.jpg` (`CA.jpg`) and `site/sample.mp4` (`video1.mp4`) are from
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs)'s test fixtures
(Apache-2.0 / MIT). Both are signed by a **test** PKI, so they demonstrate the validator
being honest: the signatures and every hash binding (data hash for the JPEG, BMFF hash for
the MP4) verify, but the chains do not reach a real C2PA trust anchor —
`signingCredential.untrusted`, exactly as it should be.

## Sponsor

If this saves you time, you can [sponsor its maintenance](https://github.com/sponsors/richardwooding).
Sponsorship pays for the unglamorous half — triage, dependency bumps, release plumbing — and is
never a condition of getting help here.

## License

MIT — see [LICENSE](LICENSE).
