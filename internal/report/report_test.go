package report

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/richardwooding/c2pa"
)

func TestSniff(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		want  c2pa.Container
		label string
	}{
		{"jpeg", "\xFF\xD8\xFF\xE0", c2pa.JPEG, "JPEG"},
		{"png", "\x89PNG\r\n\x1a\n........", c2pa.PNG, "PNG"},
		{"mp4", "\x00\x00\x00\x18ftypisom....", c2pa.BMFF, "MP4"},
		{"heic", "\x00\x00\x00\x18ftypheic....", c2pa.BMFF, "HEIC"},
		{"avif", "\x00\x00\x00\x18ftypavif....", c2pa.BMFF, "AVIF"},
		{"mov", "\x00\x00\x00\x14ftypqt  ....", c2pa.BMFF, "QuickTime MOV"},
		{"odd brand", "\x00\x00\x00\x14ftypzzzz....", c2pa.BMFF, "BMFF (zzzz)"},
		{"webp", "RIFF\x00\x00\x00\x00WEBPVP8 ", c2pa.RIFF, "WebP"},
		{"wav", "RIFF\x00\x00\x00\x00WAVEfmt ", c2pa.RIFF, "WAV"},
		{"avi", "RIFF\x00\x00\x00\x00AVI LIST", c2pa.RIFF, "AVI"},
		{"tiff le", "II*\x00\x08\x00\x00\x00", c2pa.TIFF, "TIFF"},
		{"tiff be", "MM\x00*\x00\x00\x00\x08", c2pa.TIFF, "TIFF"},
		{"gif", "GIF89a......", c2pa.GIF, "GIF"},
		{"mp3", "ID3\x04\x00\x00\x00\x00\x00\x00", c2pa.MP3, "MP3"},
		{"pdf at 0", "%PDF-1.7\n", c2pa.PDF, "PDF"},
		{"pdf offset", "junk junk\n%PDF-1.4\n", c2pa.PDF, "PDF"},
		{"svg", `<svg xmlns="http://www.w3.org/2000/svg"/>`, c2pa.SVG, "SVG"},
		{"xml prolog", `<?xml version="1.0"?><svg/>`, c2pa.SVG, "SVG"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, label, ok := Sniff([]byte(tc.data))
			if !ok || c != tc.want || label != tc.label {
				t.Fatalf("Sniff = %q %q %v, want %q %q", c, label, ok, tc.want, tc.label)
			}
		})
	}
	for _, bad := range []string{"", "PK\x03\x04", "\xFF", "RIFF"} {
		if _, _, ok := Sniff([]byte(bad)); ok {
			t.Errorf("Sniff(%q) accepted", bad)
		}
	}
}

func TestFromValidation_Fixture(t *testing.T) {
	data, err := os.ReadFile("../../site/sample.jpg")
	if err != nil {
		t.Skip("sample fixture not present:", err)
	}
	c, label, ok := Sniff(data)
	if !ok || c != c2pa.JPEG {
		t.Fatalf("sniff: %q %v", c, ok)
	}
	res := FromValidation(label, c2pa.Validate(context.Background(), c, bytes.NewReader(data)))
	if !res.Present || res.Valid || res.Container != "JPEG" {
		t.Fatalf("result = %+v", res)
	}
	// The c2pa-rs test PKI: signature and hashes verify, the signer does not
	// chain to a trust anchor — the honest verdict the page explains. (Its
	// DigiCert timestamp is untrusted against the embedded TSA list too, and
	// that failure is recorded first.)
	if res.FirstFailure == "" || !res.Has("signingCredential.untrusted") || !res.Has("claimSignature.validated") || !res.Has("assertion.dataHash.match") {
		t.Fatalf("firstFailure = %q, statuses %+v", res.FirstFailure, res.Statuses)
	}
	if res.VerifiedSigner != "" || res.SignedBy == "" || len(res.SignerChain) == 0 {
		t.Fatalf("signer fields: verified=%q claimed=%q chain=%d", res.VerifiedSigner, res.SignedBy, len(res.SignerChain))
	}
	// The JSON contract with app.js: these keys must exist under these names.
	raw, _ := json.Marshal(res)
	for _, key := range []string{`"container"`, `"present"`, `"valid"`, `"statuses"`, `"signerChain"`, `"claimGenerator"`, `"firstFailure"`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Errorf("JSON lacks %s", key)
		}
	}
}

func TestFromValidation_NoManifest(t *testing.T) {
	res := FromValidation("PNG", c2pa.Validate(context.Background(), c2pa.PNG, bytes.NewReader([]byte("\x89PNG\r\n\x1a\n"))))
	if res.Present || res.Valid || res.Statuses == nil || res.SignerChain == nil {
		t.Fatalf("result = %+v", res)
	}
}
