package credential

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// RawToDER converts WebCrypto's ECDSA signature — r‖s, each padded to the
// curve's byte width (IEEE P1363) — to the ASN.1 SEQUENCE{r, s} that
// crypto.MessageSigner must return for an ECDSA key: x509.CreateCertificate
// verifies it with ecdsa.VerifyASN1, and the c2pa library converts it back to
// raw for COSE. big.Int drops the padding and asn1 re-adds the sign byte.
func RawToDER(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("credential: ECDSA signature of %d bytes is not r‖s", len(raw))
	}
	half := len(raw) / 2
	r, s := new(big.Int).SetBytes(raw[:half]), new(big.Int).SetBytes(raw[half:])
	if r.Sign() == 0 || s.Sign() == 0 {
		return nil, errors.New("credential: ECDSA signature has a zero component")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// DERToRaw is RawToDER's inverse for a curve of size bytes per coordinate.
func DERToRaw(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, errors.New("credential: not a DER ECDSA signature")
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > size*8 || sig.S.BitLen() > size*8 {
		return nil, errors.New("credential: ECDSA signature component out of range")
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}
