//go:build js && wasm

// Command wasm exposes the pure-Go c2pa reader/validator to the browser as a
// single global function:
//
//	c2paInspect(bytes Uint8Array) -> JSON string
//
// The result carries the unverified claims (what Read surfaces), the full
// validation outcome with per-step C2PA status codes, and a summary of the
// signer certificate chain. All work happens in-page; no bytes leave the
// browser.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
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

func main() {
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

	select {} // keep the Go runtime alive for future calls
}
