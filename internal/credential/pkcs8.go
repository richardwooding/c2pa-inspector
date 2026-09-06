package credential

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

var (
	oidPublicKeyECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyRSAPSS  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidPublicKeyEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidNamedCurveP256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384   = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521   = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// pkcs8 is RFC 5208 PrivateKeyInfo with the key carried as opaque bytes.
// Attributes ([0]) and publicKey ([1]) may follow; Go's decoder allows them.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// ecPrivateKey is RFC 5915 ECPrivateKey with the scalar carried as opaque bytes.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// SniffPKCS8 reads only the AlgorithmIdentifier of a PKCS#8 PrivateKeyInfo —
// enough to choose subtle.importKey's parameters — and never decodes the key.
func SniffPKCS8(der []byte) (Algorithm, error) {
	var k pkcs8
	if _, err := asn1.Unmarshal(der, &k); err != nil {
		return Algorithm{}, fmt.Errorf("%w: not a PKCS#8 PrivateKeyInfo", ErrUnsupportedKey)
	}
	switch {
	case k.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		var curve asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(k.Algo.Parameters.FullBytes, &curve); err != nil {
			return Algorithm{}, fmt.Errorf("%w: EC key without a named curve", ErrUnsupportedKey)
		}
		return curveAlgorithm(curve)
	case k.Algo.Algorithm.Equal(oidPublicKeyRSA):
		bits, err := rsaModulusBits(k.PrivateKey)
		if err != nil {
			return Algorithm{}, err
		}
		a := rsaPSS
		a.Bits = bits
		return a, nil
	case k.Algo.Algorithm.Equal(oidPublicKeyRSAPSS):
		return Algorithm{}, fmt.Errorf("%w: the key uses the id-RSASSA-PSS identifier, which WebCrypto cannot import; re-export it as a plain RSA key (openssl rsa -in key.pem -out key-rsa.pem)", ErrUnsupportedKey)
	case k.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		return ed25519Alg, nil
	}
	return Algorithm{}, fmt.Errorf("%w: algorithm %s", ErrUnsupportedKey, k.Algo.Algorithm)
}

// curveAlgorithm maps a named-curve OID to its algorithm.
func curveAlgorithm(oid asn1.ObjectIdentifier) (Algorithm, error) {
	switch {
	case oid.Equal(oidNamedCurveP256):
		return ecdsaP256, nil
	case oid.Equal(oidNamedCurveP384):
		return ecdsaP384, nil
	case oid.Equal(oidNamedCurveP521):
		return ecdsaP521, nil
	}
	return Algorithm{}, fmt.Errorf("%w: EC curve %s (P-256, P-384 and P-521 are supported)", ErrUnsupportedKey, oid)
}

// rsaModulusBits reads the modulus size out of a PKCS#1 RSAPrivateKey —
// SEQUENCE{version, modulus, ...} — without decoding anything else.
func rsaModulusBits(der []byte) (int, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return 0, fmt.Errorf("%w: not an RSAPrivateKey", ErrUnsupportedKey)
	}
	var version, modulus asn1.RawValue
	rest, err := asn1.Unmarshal(seq.Bytes, &version)
	if err != nil {
		return 0, fmt.Errorf("%w: not an RSAPrivateKey", ErrUnsupportedKey)
	}
	if _, err := asn1.Unmarshal(rest, &modulus); err != nil || modulus.Tag != asn1.TagInteger {
		return 0, fmt.Errorf("%w: not an RSAPrivateKey", ErrUnsupportedKey)
	}
	bits := new(big.Int).SetBytes(modulus.Bytes).BitLen()
	if bits < 2048 {
		return 0, fmt.Errorf("%w: RSA key is %d bits; the C2PA profile needs 2048", ErrUnsupportedKey, bits)
	}
	return bits, nil
}

// SEC1ToPKCS8 re-wraps an RFC 5915 "EC PRIVATE KEY" as PKCS#8: the curve moves
// into the AlgorithmIdentifier and the inner ECPrivateKey keeps the scalar and
// public key but drops its own [0] curve — byte for byte what OpenSSL and Go
// emit, and the form WebCrypto imports. The scalar is copied, never decoded.
func SEC1ToPKCS8(der []byte) ([]byte, Algorithm, error) {
	var ec ecPrivateKey
	if _, err := asn1.Unmarshal(der, &ec); err != nil {
		return nil, Algorithm{}, fmt.Errorf("%w: not a SEC 1 ECPrivateKey", ErrUnsupportedKey)
	}
	if len(ec.NamedCurveOID) == 0 {
		return nil, Algorithm{}, fmt.Errorf("%w: the EC key names no curve (PKCS#8 form needed)", ErrUnsupportedKey)
	}
	alg, err := curveAlgorithm(ec.NamedCurveOID)
	if err != nil {
		return nil, Algorithm{}, err
	}
	inner, err := asn1.Marshal(ecPrivateKey{Version: 1, PrivateKey: ec.PrivateKey, PublicKey: ec.PublicKey})
	if err != nil {
		return nil, Algorithm{}, fmt.Errorf("%w: %v", ErrUnsupportedKey, err)
	}
	params, err := asn1.Marshal(ec.NamedCurveOID)
	if err != nil {
		return nil, Algorithm{}, fmt.Errorf("%w: %v", ErrUnsupportedKey, err)
	}
	out, err := asn1.Marshal(pkcs8{
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyECDSA, Parameters: asn1.RawValue{FullBytes: params}},
		PrivateKey: inner,
	})
	if err != nil {
		return nil, Algorithm{}, fmt.Errorf("%w: %v", ErrUnsupportedKey, err)
	}
	return out, alg, nil
}

// PKCS1ToPKCS8 wraps an "RSA PRIVATE KEY" verbatim in PKCS#8 under the
// rsaEncryption identifier, after checking the modulus is at least 2048 bits.
func PKCS1ToPKCS8(der []byte) ([]byte, Algorithm, error) {
	bits, err := rsaModulusBits(der)
	if err != nil {
		return nil, Algorithm{}, err
	}
	out, err := asn1.Marshal(pkcs8{
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA, Parameters: asn1.NullRawValue},
		PrivateKey: der,
	})
	if err != nil {
		return nil, Algorithm{}, fmt.Errorf("%w: %v", ErrUnsupportedKey, err)
	}
	a := rsaPSS
	a.Bits = bits
	return out, a, nil
}
