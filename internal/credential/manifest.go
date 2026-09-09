package credential

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/richardwooding/c2pa"
)

// ErrAlreadySigned is returned when a created action is requested for an
// asset that already carries a manifest — the library would refuse too, but
// with a message about manifests rather than about the choice to make.
var ErrAlreadySigned = errors.New("credential: the asset already carries Content Credentials; use the opened action to chain to them")

// ErrBadAction is returned for an action other than auto, created or opened.
var ErrBadAction = errors.New(`credential: action must be "auto", "created" or "opened"`)

// ErrBadDigitalSourceType is returned for a source type that is neither a
// known IPTC term nor a URL.
var ErrBadDigitalSourceType = errors.New("credential: digital source type must be an IPTC term or a URL")

// KnownDigitalSourceTypes are the IPTC NewsCodes digital source type terms the
// page offers, plus C2PA's own "empty".
var KnownDigitalSourceTypes = []string{
	"digitalCapture", "trainedAlgorithmicMedia", "compositeWithTrainedAlgorithmicMedia",
	"algorithmicMedia", "compositeCapture", "compositeSynthetic", "digitalArt",
	"dataDrivenMedia", "minorHumanEdits", "algorithmicallyEnhanced", "screenCapture",
	"virtualRecording", "negativeFilm", "positiveFilm", "print", "empty",
}

const iptcDigitalSourceTypePrefix = "http://cv.iptc.org/newscodes/digitalsourcetype/"

// DigitalSourceTypeURL completes a bare IPTC term to its NewsCodes URL. ""
// stays empty (the field is optional), "empty" is C2PA's own type, a URL
// passes through, anything else is an error rather than a guess.
func DigitalSourceTypeURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", nil
	case s == "empty":
		return c2pa.DigitalSourceTypeEmpty, nil
	case strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://"):
		return s, nil
	}
	if slices.Contains(KnownDigitalSourceTypes, s) {
		return iptcDigitalSourceTypePrefix + s, nil
	}
	return "", fmt.Errorf("%w: %q", ErrBadDigitalSourceType, s)
}

// SignRequest is what the page asks for one signing.
type SignRequest struct {
	Title             string
	Action            string // "auto", "created" or "opened"
	DigitalSourceType string
	TSAURL            string
	// IdentityRoles are the roles a named actor declares in producing the
	// asset — "cawg.creator", "cawg.editor", … Setting any makes the signer
	// write a cawg.identity assertion, which needs an identity credential; the
	// library refuses the combination otherwise, so BuildManifest only fills
	// Manifest.Identity when the caller asked for it.
	IdentityRoles []string
	// IdentityReferences names further assertions of this manifest the actor
	// signs over. The content itself always is, and must not be listed.
	IdentityReferences []string
}

// BuildManifest turns a request into the library's Manifest. present says
// whether the asset already carries a manifest: auto then picks opened, and an
// explicit created is refused with ErrAlreadySigned. agent names the software
// on the action.
func BuildManifest(req SignRequest, present bool, agent c2pa.GeneratorInfo) (c2pa.Manifest, error) {
	var action string
	switch strings.TrimSpace(req.Action) {
	case "", "auto":
		action = c2pa.ActionCreated
		if present {
			action = c2pa.ActionOpened
		}
	case "created", c2pa.ActionCreated:
		if present {
			return c2pa.Manifest{}, ErrAlreadySigned
		}
		action = c2pa.ActionCreated
	case "opened", c2pa.ActionOpened:
		action = c2pa.ActionOpened
	default:
		return c2pa.Manifest{}, fmt.Errorf("%w: got %q", ErrBadAction, req.Action)
	}
	dst, err := DigitalSourceTypeURL(req.DigitalSourceType)
	if err != nil {
		return c2pa.Manifest{}, err
	}
	m := c2pa.Manifest{
		Title: strings.TrimSpace(req.Title),
		Actions: []c2pa.Action{{
			Action:            action,
			DigitalSourceType: dst,
			SoftwareAgent:     agent,
		}},
	}
	// Only when asked: Manifest.Identity set without an identity signer is
	// ErrManifestInvalid, so an empty IdentityInfo must stay empty.
	if len(req.IdentityRoles) > 0 || len(req.IdentityReferences) > 0 {
		m.Identity = c2pa.IdentityInfo{Roles: req.IdentityRoles, References: req.IdentityReferences}
	}
	return m, nil
}
