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
	"encoding/json"
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
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xD8:
		return c2pa.JPEG, "JPEG", true
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return c2pa.PNG, "PNG", true
	case len(data) >= 12 && string(data[4:8]) == "ftyp":
		return c2pa.BMFF, bmffLabel(string(data[8:12])), true
	default:
		return "", "", false
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
		return resultJSON{Error: "unsupported file type — drop a JPEG, PNG, HEIC, AVIF, MP4, or MOV"}
	}

	r := c2pa.Validate(context.Background(), container, bytes.NewReader(data))

	out := resultJSON{
		Container:           name,
		Present:             r.Info.Present,
		ClaimGenerator:      r.Info.ClaimGenerator,
		Title:               r.Info.Title,
		Format:              r.Info.Format,
		AIGenerated:         r.Info.AIGenerated,
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

func main() {
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
