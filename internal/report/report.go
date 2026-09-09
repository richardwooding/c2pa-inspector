// Package report is the inspector's result vocabulary: the container sniff, the
// JSON shapes the page renders, and the mapping from a c2pa.ValidationResult
// onto them. It is plain Go so it can be tested natively; the wasm wrapper only
// adds the browser plumbing around it. The JSON field names are a contract with
// site/app.js — change one and change the other.
package report

import (
	"bytes"
	"crypto/x509"
	"strings"
	"time"

	"github.com/richardwooding/c2pa"
)

// Deadline bounds every call into the validator. The browser gives WASM no
// other way to interrupt a pathological file — the PDF repair-pass review
// measured 27s of main-thread freeze from a crafted 3.5 MB input before its
// bound landed, and this is the insurance against the next such case.
const Deadline = 30 * time.Second

// UnsupportedMessage is what the page says about a file it cannot read.
const UnsupportedMessage = "unsupported file type — drop a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF"

// CertSummary is one certificate of the signer chain as the page shows it.
type CertSummary struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	Algorithm string `json:"algorithm"`
}

// Identity is one CAWG identity assertion as the page shows it: a named actor
// who signed over this manifest's content with their own credential.
//
// Name is who was PROVEN and is empty unless Trusted, exactly as
// Result.VerifiedSigner is. PresentedAs, Issuer and VerifiedIdentities are what
// the file SAYS, populated whether or not anything vouched for them.
//
// None of it conveys attribution or ownership: the assertion means this actor
// vouched for these assertions, and an aggregation credential means an
// aggregator says the actor showed it these signals and this asset.
type Identity struct {
	Label   string `json:"label"`
	SigType string `json:"sigType,omitempty"`
	// URI is where this identity's statuses live, "<manifest>/<label>". They are
	// not the claim's, even where the codes are the same ones.
	URI string `json:"uri,omitempty"`
	// Roles and Referenced are the actor's declared roles and the assertions
	// they signed over, in payload order. The hard binding is always among the
	// latter, which is what makes the actor vouch for the content itself.
	Roles      []string `json:"roles,omitempty"`
	Referenced []string `json:"referenced,omitempty"`
	Valid      bool     `json:"valid"`
	Trusted    bool     `json:"trusted"`
	Name       string   `json:"name,omitempty"`
	// PresentedAs is the identity certificate's subject, a claim until Trusted.
	// Empty for an aggregation credential, which carries no certificate.
	PresentedAs string `json:"presentedAs,omitempty"`
	// Issuer is the aggregator's DID, as presented.
	Issuer string `json:"issuer,omitempty"`
	// VerifiedIdentities are the signals an aggregator says it checked — its
	// word, proven only as far as that aggregator is trusted.
	VerifiedIdentities []VerifiedIdentity `json:"verifiedIdentities,omitempty"`
	SignedAt           string             `json:"signedAt,omitempty"`
}

// VerifiedIdentity is one signal an aggregator vouched for, as presented by it.
type VerifiedIdentity struct {
	Type         string `json:"type,omitempty"`
	Name         string `json:"name,omitempty"`
	Username     string `json:"username,omitempty"`
	URI          string `json:"uri,omitempty"`
	VerifiedAt   string `json:"verifiedAt,omitempty"`
	ProviderName string `json:"providerName,omitempty"`
}

// Status is one C2PA §15 status entry.
type Status struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	URI         string `json:"uri,omitempty"`
	Explanation string `json:"explanation"`
}

// Result is the inspection outcome for one file: the unverified claims, the
// validation verdict with every status, and the signer chain as presented.
type Result struct {
	Container       string `json:"container"`
	Present         bool   `json:"present"`
	ClaimGenerator  string `json:"claimGenerator,omitempty"`
	Title           string `json:"title,omitempty"`
	Format          string `json:"format,omitempty"`
	AIGenerated     bool   `json:"aiGenerated"`
	SoftwareAgent   string `json:"softwareAgent,omitempty"`
	Attribution     string `json:"attribution,omitempty"`
	SignedBy        string `json:"signedBy,omitempty"`
	VerifiedSigner  string `json:"verifiedSigner,omitempty"`
	ClaimedSignedAt string `json:"claimedSignedAt,omitempty"`
	Valid           bool   `json:"valid"`
	// Binding is what the hard binding proved about THESE bytes — "verified",
	// "failed", "unevaluated" or "none" — which is not the same question as
	// Valid. A PDF whose manifest is attached to an object it carries is valid
	// with an unevaluated binding: nothing hashed the document. The page says so
	// rather than letting a green tick imply it.
	Binding             string        `json:"binding"`
	VerifiedSignedAt    string        `json:"verifiedSignedAt,omitempty"`
	ActiveManifestLabel string        `json:"activeManifestLabel,omitempty"`
	FirstFailure        string        `json:"firstFailure,omitempty"`
	Statuses            []Status      `json:"statuses"`
	SignerChain         []CertSummary `json:"signerChain"`
	// Identities are the active manifest's CAWG identity assertions — who
	// vouched for the content, as against which tool made it. Identities of
	// ingredient manifests are validated but not listed.
	Identities []Identity `json:"identities,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// SeverityString names a severity the way the page's CSS classes expect.
func SeverityString(s c2pa.Severity) string {
	switch s {
	case c2pa.SeveritySuccess:
		return "success"
	case c2pa.SeverityFailure:
		return "failure"
	default:
		return "informational"
	}
}

// Sniff maps a file's leading bytes to the c2pa container and a label for the
// page. %PDF- is accepted anywhere in the first 1 KiB, matching the parser's
// own tolerance, since producers prepend bytes.
func Sniff(data []byte) (c2pa.Container, string, bool) {
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

// SummarizeChain renders the signer chain as PRESENTED — a claim until the
// verdict says otherwise.
func SummarizeChain(chain []*x509.Certificate) []CertSummary {
	out := make([]CertSummary, 0, len(chain))
	for _, cert := range chain {
		out = append(out, CertSummary{
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
			Algorithm: cert.SignatureAlgorithm.String(),
		})
	}
	return out
}

// SummarizeIdentities renders the named actors who vouched for the content.
// Name comes from the library and is empty unless the actor was proven;
// everything else is as presented.
func SummarizeIdentities(ids []c2pa.Identity) []Identity {
	out := make([]Identity, 0, len(ids))
	for _, id := range ids {
		e := Identity{
			Label:      id.Label,
			SigType:    id.SigType,
			URI:        id.URI,
			Roles:      id.Roles,
			Referenced: id.Referenced,
			Valid:      id.Valid,
			Trusted:    id.Trusted,
			Name:       id.Name(),
			Issuer:     id.Issuer,
		}
		// No certificate on an aggregation credential, nor on an X.509 identity
		// whose COSE carried no x5chain.
		if len(id.Chain) > 0 && id.Chain[0] != nil {
			e.PresentedAs = id.Chain[0].Subject.String()
		}
		if !id.SignedAt.IsZero() {
			e.SignedAt = id.SignedAt.UTC().Format(time.RFC3339)
		}
		for _, vi := range id.VerifiedIdentities {
			v := VerifiedIdentity{
				Type:         vi.Type,
				Name:         vi.Name,
				Username:     vi.Username,
				URI:          vi.URI,
				ProviderName: vi.Provider.Name,
			}
			if !vi.VerifiedAt.IsZero() {
				v.VerifiedAt = vi.VerifiedAt.UTC().Format(time.RFC3339)
			}
			e.VerifiedIdentities = append(e.VerifiedIdentities, v)
		}
		out = append(out, e)
	}
	return out
}

// FromValidation shapes a validator result for the page. container is the
// label Sniff produced.
func FromValidation(container string, r c2pa.ValidationResult) Result {
	out := Result{
		Container:      container,
		Present:        r.Info.Present,
		ClaimGenerator: r.Info.ClaimGenerator,
		Title:          r.Info.Title,
		Format:         r.Info.Format,
		AIGenerated:    r.Info.AIGenerated,
		SoftwareAgent:  r.Info.SoftwareAgent,
		Attribution:    string(r.Info.Attribution),
		SignedBy:       r.Info.SignedBy,
		// Empty unless the identity was actually proven — the signature verified
		// AND the chain reached a trust anchor. SignerChain below is the chain as
		// PRESENTED, which is a claim.
		VerifiedSigner:      r.VerifiedSigner(),
		Valid:               r.Valid,
		Binding:             r.Binding.String(),
		ActiveManifestLabel: r.ActiveManifestLabel,
		Statuses:            make([]Status, 0, len(r.Statuses)),
		SignerChain:         SummarizeChain(r.SignerChain),
		Identities:          SummarizeIdentities(r.Identities),
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
		out.Statuses = append(out.Statuses, Status{
			Code:        string(s.Code),
			Severity:    SeverityString(s.Severity),
			URI:         s.URI,
			Explanation: s.Explanation,
		})
	}
	return out
}

// Has reports whether the result carries a status code.
func (r Result) Has(code string) bool {
	for _, s := range r.Statuses {
		if s.Code == code {
			return true
		}
	}
	return false
}
