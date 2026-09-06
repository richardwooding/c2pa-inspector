//go:build js && wasm

// Command wasm exposes the pure-Go c2pa reader, validator and signer to the
// browser as global functions:
//
//	c2paInspect(bytes Uint8Array) -> JSON string
//	c2paManifest(bytes Uint8Array) -> JSON string
//	c2paLibVersion() -> string
//	c2paCredentialCreate(name) -> Promise<{key: CryptoKey, certPEM, summary}>
//	c2paCredentialImport(keyPEM, chainPEM) -> Promise<{key, certPEM, summary}>
//	c2paSign(bytes, {key, certPEM, title, action, digitalSourceType, tsaURL})
//	    -> Promise<{bytes: Uint8Array, report: JSON string}>
//
// The inspection result carries the unverified claims (what Read surfaces),
// the full validation outcome with per-step C2PA status codes, and a summary
// of the signer certificate chain. Signing keys live in WebCrypto,
// non-extractable; Go only ever sees the public key and the signatures. All
// work happens in-page; no bytes leave the browser unless a timestamp
// authority is asked for.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"syscall/js"

	"github.com/richardwooding/c2pa"

	"github.com/richardwooding/c2pa-inspector/internal/report"
)

// inspect runs the validator over data and shapes the result for the page.
func inspect(data []byte) report.Result {
	container, name, ok := report.Sniff(data)
	if !ok {
		return report.Result{Error: report.UnsupportedMessage}
	}
	ctx, cancel := context.WithTimeout(context.Background(), report.Deadline)
	defer cancel()
	r := c2pa.Validate(ctx, container, bytes.NewReader(data))
	if ctx.Err() != nil {
		return report.Result{Container: name,
			Error: "validation took too long and was stopped — the file may be malformed"}
	}
	return report.FromValidation(name, r)
}

// boxJSON is one leaf of the JUMBF box tree, as the manifest viewer renders it.
// Payload is set only when the box decodes as JSON; everything else reports its
// size and a short hex preview, so a binary box is legible without shipping it.
type boxJSON struct {
	Label   string `json:"label"`
	Type    string `json:"type"`
	Size    int    `json:"size"`
	Payload any    `json:"payload,omitempty"`
	Preview string `json:"preview,omitempty"`
}

type manifestJSON struct {
	Container string    `json:"container"`
	StoreSize int       `json:"storeSize"`
	Boxes     []boxJSON `json:"boxes"`
	Error     string    `json:"error,omitempty"`
}

// maxBoxPreview caps the hex preview of a non-JSON box.
const maxBoxPreview = 64

// rawManifest returns the JUMBF box tree of the store embedded in data. This is
// the byte-level view: every box the store carries, including assertions Info
// does not model.
func rawManifest(data []byte) manifestJSON {
	container, name, ok := report.Sniff(data)
	if !ok {
		return manifestJSON{Error: "unsupported file type"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), report.Deadline)
	defer cancel()
	store, err := c2pa.ExtractStore(ctx, container, bytes.NewReader(data))
	if err != nil {
		return manifestJSON{Container: name, Error: err.Error()}
	}
	if len(store) == 0 {
		return manifestJSON{Container: name}
	}

	out := manifestJSON{Container: name, StoreSize: len(store), Boxes: []boxJSON{}}
	c2pa.WalkBoxes(ctx, store, func(label, tbox string, content []byte) {
		box := boxJSON{Label: label, Type: tbox, Size: len(content)}
		var v any
		if json.Unmarshal(content, &v) == nil {
			box.Payload = v
		} else {
			box.Preview = hex.EncodeToString(content[:min(len(content), maxBoxPreview)])
		}
		out.Boxes = append(out.Boxes, box)
	})
	return out
}

// c2paLibVersion reports the version of the c2pa library this binary was built
// against, read from the embedded build info rather than injected at build
// time so it cannot drift from go.mod.
func c2paLibVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, d := range info.Deps {
		if d.Path == "github.com/richardwooding/c2pa" {
			if d.Replace != nil {
				return d.Replace.Version
			}
			return d.Version
		}
	}
	return ""
}

// registerGlobals installs the page's entry points. The three inspection
// functions are synchronous and return JSON strings, as app.js expects. The
// three signing functions return Promises: they await WebCrypto, which can
// only settle once the JS event loop turns, so their work runs on a goroutine
// and the arguments are copied out of JS before it starts.
func registerGlobals() {
	js.Global().Set("c2paLibVersion", js.FuncOf(func(js.Value, []js.Value) any {
		return c2paLibVersion()
	}))
	js.Global().Set("c2paManifest", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			b, _ := json.Marshal(manifestJSON{Error: "c2paManifest requires a Uint8Array argument"})
			return string(b)
		}
		src := args[0]
		data := make([]byte, src.Get("length").Int())
		js.CopyBytesToGo(data, src)

		b, err := json.Marshal(rawManifest(data))
		if err != nil {
			eb, _ := json.Marshal(manifestJSON{Error: "internal: " + err.Error()})
			return string(eb)
		}
		return string(b)
	}))
	js.Global().Set("c2paInspect", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			b, _ := json.Marshal(report.Result{Error: "c2paInspect requires a Uint8Array argument"})
			return string(b)
		}
		src := args[0]
		data := make([]byte, src.Get("length").Int())
		js.CopyBytesToGo(data, src)

		res := inspect(data)
		b, err := json.Marshal(res)
		if err != nil {
			eb, _ := json.Marshal(report.Result{Error: "internal: " + err.Error()})
			return string(eb)
		}
		return string(b)
	}))

	// c2paCredentialCreate(name) -> Promise<{key, certPEM, summary}>
	js.Global().Set("c2paCredentialCreate", js.FuncOf(func(_ js.Value, args []js.Value) any {
		name := ""
		if len(args) > 0 && args[0].Type() == js.TypeString {
			name = args[0].String()
		}
		return promisify(func() (any, error) { return credentialCreate(name) })
	}))
	// c2paCredentialImport(keyPEM, chainPEM) -> Promise<{key, certPEM, summary}>
	js.Global().Set("c2paCredentialImport", js.FuncOf(func(_ js.Value, args []js.Value) any {
		var keyPEM, chainPEM string
		if len(args) > 0 && args[0].Type() == js.TypeString {
			keyPEM = args[0].String()
		}
		if len(args) > 1 && args[1].Type() == js.TypeString {
			chainPEM = args[1].String()
		}
		return promisify(func() (any, error) { return credentialImport(keyPEM, chainPEM) })
	}))
	// c2paSign(bytes, {key, certPEM, title, action, digitalSourceType, tsaURL})
	//   -> Promise<{bytes: Uint8Array, report: string}>
	js.Global().Set("c2paSign", js.FuncOf(func(_ js.Value, args []js.Value) any {
		var data []byte
		var opts signOptions
		var argErr error
		if len(args) < 2 {
			argErr = errors.New("c2paSign requires a Uint8Array and an options object")
		} else {
			data, argErr = fromUint8Array(args[0])
			if argErr == nil {
				opts, argErr = parseSignOptions(args[1])
			}
		}
		return promisify(func() (any, error) {
			if argErr != nil {
				return nil, argErr
			}
			out, rep, err := signAsset(data, opts)
			if err != nil {
				return nil, err
			}
			b, err := json.Marshal(rep)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", errInternal, err)
			}
			return map[string]any{"bytes": toUint8Array(out), "report": string(b)}, nil
		})
	}))
}

func main() {
	registerGlobals()
	select {} // keep the Go runtime alive for future calls
}
