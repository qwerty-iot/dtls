package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
)

type eccCurve uint16

type eccKeypair struct {
	curve      eccCurve
	publicKey  []byte
	privateKey []byte
}

const (
	EccCurve_P256 eccCurve = 0x0017
)

func eccGetKeypair(ec eccCurve) (*eccKeypair, error) {
	switch ec { //nolint:golint
	case EccCurve_P256:
		privateKey, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &eccKeypair{ec, elliptic.Marshal(elliptic.P256(), x, y), privateKey}, nil
	default:
		return nil, errors.New("dtls: invalid ecc curve")
	}
}

func eccGetKeyMessage(clientRandom, serverRandom, publicKey []byte, ec eccCurve) []byte {
	w := newByteWriter()
	w.PutBytes(clientRandom)
	w.PutBytes(serverRandom)
	w.PutUint8(3)
	w.PutUint16(uint16(ec))
	w.PutUint8(uint8(len(publicKey)))
	w.PutBytes(publicKey)

	return w.Bytes()
}

func eccGetKeySignature(clientRandom, serverRandom, publicKey []byte, ec eccCurve, privateKey crypto.PrivateKey) ([]byte, error) {

	msg := eccGetKeyMessage(clientRandom, serverRandom, publicKey, ec)

	hashed := sha256.Sum256(msg)
	return privateKey.(*ecdsa.PrivateKey).Sign(rand.Reader, hashed[:], crypto.SHA256)
}

type ecdsaSignature struct {
	R, S *big.Int
}

func eccVerifySignature(hash []byte, sig []byte, certs [][]byte) error {
	if len(certs) == 0 {
		return errors.New("dtls: no certificates")
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return err
	}

	switch p := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		ecdsaSig := &ecdsaSignature{}
		if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("dtls: invalid ecdsa signature")
		}
		if !ecdsa.Verify(p, hash, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("dtls: signature mismatch")
		}
		return nil
	}
	return errors.New("dtls: unsupported certificate type")
}
