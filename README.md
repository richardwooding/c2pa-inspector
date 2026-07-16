# c2pa-inspector

**Verify C2PA / Content Credentials entirely in your browser** —
[richardwooding.github.io/c2pa-inspector](https://richardwooding.github.io/c2pa-inspector/)

Drop a JPEG, PNG, HEIC, AVIF, MP4, or MOV on the page and get the full C2PA validation
result: the COSE signature,
the certificate chain against the official C2PA trust list, assertion and hard-binding
hashes (`c2pa.hash.data` for JPEG/PNG, `c2pa.hash.bmff.v2`/`.v3` for BMFF assets), and the
RFC 3161 timestamp — with every C2PA §15 status code the validator
recorded. Nothing is uploaded; the validator is
[richardwooding/c2pa](https://github.com/richardwooding/c2pa) (pure Go, no cgo) compiled to
WebAssembly and running in the page.

## Why this can exist

The reference C2PA implementation is Rust with C bindings. Because
`richardwooding/c2pa` is pure Go — CBOR, COSE, X.509, CMS/RFC 3161, all in Go with the
official trust lists embedded — the *entire* validator compiles to a single `.wasm` binary
with `GOOS=js GOARCH=wasm go build`. The browser wrapper is ~150 lines
([`wasm/main.go`](wasm/main.go)); everything else is the library, unchanged.

## Layout

- `wasm/` — the Go→WASM wrapper: exposes `c2paInspect(Uint8Array) -> JSON` on `window`.
- `site/` — the static page (GitHub Pages): [gloam](https://github.com/richardwooding/gloam)-styled
  UI, drop zone, result rendering. `c2pa.wasm` and `wasm_exec.js` are built by CI, not committed.
- `.github/workflows/deploy.yml` — builds the WASM and deploys `site/` to Pages on push.

## Build locally

```sh
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o site/c2pa.wasm ./wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" site/
python3 -m http.server -d site 8080   # then open http://localhost:8080
```

## The samples

`site/sample.jpg` (`CA.jpg`) and `site/sample.mp4` (`video1.mp4`) are from
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs)'s test fixtures
(Apache-2.0 / MIT). Both are signed by a **test** PKI, so they demonstrate the validator
being honest: the signatures and every hash binding (data hash for the JPEG, BMFF hash for
the MP4) verify, but the chains do not reach a real C2PA trust anchor —
`signingCredential.untrusted`, exactly as it should be.

## License

MIT — see [LICENSE](LICENSE).
