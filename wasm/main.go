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
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"runtime/debug"
	"strings"
	"syscall/js"
	"time"

	"github.com/richardwooding/c2pa"
)

type certSummary struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	Algorithm string `json:"algorithm"`
}

type statusJSON struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	URI         string `json:"uri,omitempty"`
	Explanation string `json:"explanation"`
}

type resultJSON struct {
	Container           string        `json:"container"`
	Present             bool          `json:"present"`
	ClaimGenerator      string        `json:"claimGenerator,omitempty"`
	Title               string        `json:"title,omitempty"`
	Format              string        `json:"format,omitempty"`
	AIGenerated         bool          `json:"aiGenerated"`
	SoftwareAgent       string        `json:"softwareAgent,omitempty"`
	Attribution         string        `json:"attribution,omitempty"`
	SignedBy            string        `json:"signedBy,omitempty"`
	ClaimedSignedAt     string        `json:"claimedSignedAt,omitempty"`
	Valid               bool          `json:"valid"`
	VerifiedSignedAt    string        `json:"verifiedSignedAt,omitempty"`
	ActiveManifestLabel string        `json:"activeManifestLabel,omitempty"`
	FirstFailure        string        `json:"firstFailure,omitempty"`
	Statuses            []statusJSON  `json:"statuses"`
	SignerChain         []certSummary `json:"signerChain"`
	Error               string        `json:"error,omitempty"`
}

func severityString(s c2pa.Severity) string {
	switch s {
	case c2pa.SeveritySuccess:
		return "success"
	case c2pa.SeverityFailure:
		return "failure"
	default:
		return "informational"
	}
}

func sniffContainer(data []byte) (c2pa.Container, string, bool) {
	head := data[:min(len(data), 1024)]
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xD8:
		return c2pa.JPEG, "JPEG", true
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return c2pa.PNG, "PNG", true
	case len(data) >= 12 && string(data[4:8]) == "ftyp":
		return c2pa.BMFF, bmffLabel(string(data[8:12])), true
	case len(data) >= 12 && string(data[:4]) == "RIFF":
		return c2pa.RIFF, riffLabel(string(data[8:12])), true
	case len(data) >= 4 && (string(data[:4]) == "II*\x00" || string(data[:4]) == "MM\x00*"):
		return c2pa.TIFF, "TIFF", true
	case len(data) >= 6 && string(data[:3]) == "GIF":
		return c2pa.GIF, "GIF", true
	case len(data) >= 3 && string(data[:3]) == "ID3":
		return c2pa.MP3, "MP3", true
	// Matches the parser's own tolerance: %PDF- anywhere in the first 1 KiB,
	// not just at offset 0, since producers prepend bytes.
	case bytes.Contains(head, []byte("%PDF-")):
		return c2pa.PDF, "PDF", true
	case bytes.Contains(head, []byte("<svg")) || bytes.Contains(head, []byte("<?xml")):
		return c2pa.SVG, "SVG", true
	default:
		return "", "", false
	}
}

// riffLabel names the RIFF form type, which is where WebP, WAV and AVI differ.
func riffLabel(form string) string {
	switch form {
	case "WEBP":
		return "WebP"
	case "WAVE":
		return "WAV"
	case "AVI ":
		return "AVI"
	default:
		return "RIFF (" + strings.TrimSpace(form) + ")"
	}
}

// bmffLabel maps an ftyp major brand to a human-readable container name.
func bmffLabel(brand string) string {
	switch brand {
	case "heic", "heix", "hevc", "hevx", "mif1", "msf1":
		return "HEIC"
	case "avif", "avis":
		return "AVIF"
	case "qt  ":
		return "QuickTime MOV"
	case "M4A ":
		return "M4A"
	case "isom", "iso2", "iso3", "iso4", "iso5", "iso6", "mp41", "mp42", "M4V ", "dash":
		return "MP4"
	default:
		return "BMFF (" + strings.TrimSpace(brand) + ")"
	}
}

func summarizeChain(chain []*x509.Certificate) []certSummary {
	out := make([]certSummary, 0, len(chain))
	for _, cert := range chain {
		out = append(out, certSummary{
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
			Algorithm: cert.SignatureAlgorithm.String(),
		})
	}
	return out
}

func inspect(data []byte) resultJSON {
	container, name, ok := sniffContainer(data)
	if !ok {
		return resultJSON{Error: "unsupported file type — drop a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF"}
	}

	r := c2pa.Validate(context.Background(), container, bytes.NewReader(data))

	out := resultJSON{
		Container:           name,
		Present:             r.Info.Present,
		ClaimGenerator:      r.Info.ClaimGenerator,
		Title:               r.Info.Title,
		Format:              r.Info.Format,
		AIGenerated:         r.Info.AIGenerated,
		SoftwareAgent:       r.Info.SoftwareAgent,
		Attribution:         string(r.Info.Attribution),
		SignedBy:            r.Info.SignedBy,
		Valid:               r.Valid,
		ActiveManifestLabel: r.ActiveManifestLabel,
		Statuses:            make([]statusJSON, 0, len(r.Statuses)),
		SignerChain:         summarizeChain(r.SignerChain),
	}
	if !r.Info.SignedAt.IsZero() {
		out.ClaimedSignedAt = r.Info.SignedAt.UTC().Format(time.RFC3339)
	}
	if !r.SignedAt.IsZero() {
		out.VerifiedSignedAt = r.SignedAt.UTC().Format(time.RFC3339)
	}
	if f := r.FirstFailure(); f != nil {
		out.FirstFailure = string(f.Code)
	}
	for _, s := range r.Statuses {
		out.Statuses = append(out.Statuses, statusJSON{
			Code:        string(s.Code),
			Severity:    severityString(s.Severity),
			URI:         s.URI,
			Explanation: s.Explanation,
		})
	}
	return out
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
	container, name, ok := sniffContainer(data)
	if !ok {
		return manifestJSON{Error: "unsupported file type"}
	}
	store, err := c2pa.ExtractStore(context.Background(), container, bytes.NewReader(data))
	if err != nil {
		return manifestJSON{Container: name, Error: err.Error()}
	}
	if len(store) == 0 {
		return manifestJSON{Container: name}
	}

	out := manifestJSON{Container: name, StoreSize: len(store), Boxes: []boxJSON{}}
	c2pa.WalkBoxes(context.Background(), store, func(label, tbox string, content []byte) {
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
			b, _ := json.Marshal(resultJSON{Error: "c2paInspect requires a Uint8Array argument"})
			return string(b)
		}
		src := args[0]
		data := make([]byte, src.Get("length").Int())
		js.CopyBytesToGo(data, src)

		res := inspect(data)
		b, err := json.Marshal(res)
		if err != nil {
			eb, _ := json.Marshal(resultJSON{Error: "internal: " + err.Error()})
			return string(eb)
		}
		return string(b)
	}))

	select {} // keep the Go runtime alive for future calls
}
