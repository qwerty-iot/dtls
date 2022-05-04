// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	AadAuthLen int = 13
)

func newNonce(iv []byte, epoch uint16, seq uint64) []byte {
	nonce := new(bytes.Buffer)
	nonce.Write(iv)
	seq += uint64(epoch) << 48
	binary.Write(nonce, binary.BigEndian, seq)
	return nonce.Bytes()
}
func newNonceFromBytes(iv []byte, data []byte) []byte {
	nonce := new(bytes.Buffer)
	nonce.Write(iv)
	nonce.Write(data)
	return nonce.Bytes()
}

func newAad(epoch uint16, seq uint64, msgType uint8, cid []byte, dataLen uint16) []byte {
	w := newByteWriter()
	if cid != nil {
		// placeholder
		w.PutUint8(uint8(ContentType_Appdata_Cid))
		w.PutUint8(uint8(len(cid)))
		w.PutUint8(uint8(ContentType_Appdata_Cid))
		w.PutUint16(DtlsVersion12)
		w.PutUint16(epoch)
		w.PutUint48(seq)
		w.PutBytes(cid)
		w.PutUint16(dataLen)
	} else {
		w.PutUint16(epoch)
		w.PutUint48(seq)
		w.PutUint8(msgType)
		w.PutUint16(DtlsVersion12)
		w.PutUint16(dataLen)
	}

	return w.Bytes()
}

type KeyBlock struct {
	MasterSecret   []byte `json:"masterSecret"`
	ClientMac      []byte `json:"clientMac"`
	ServerMac      []byte `json:"serverMac"`
	ClientWriteKey []byte `json:"clientWriteKey"`
	ServerWriteKey []byte `json:"serverWriteKey"`
	ClientIV       []byte `json:"clientIV"`
	ServerIV       []byte `json:"serverIV"`
}

func (kb *KeyBlock) Print() string {
	return fmt.Sprintf("ClientWriteKey[%X], ServerWriteKey[%X], ClientIV[%X], ServerIV[%X]", kb.ClientWriteKey, kb.ServerWriteKey, kb.ClientIV, kb.ServerIV)
}

func generatePskPreMasterSecret(psk []byte) []byte {

	zeroBuffer := make([]byte, len(psk))

	w := newByteWriter()

	w.PutUint16(uint16(len(psk)))
	w.PutBytes(zeroBuffer)
	w.PutUint16(uint16(len(psk)))
	w.PutBytes(psk)

	return w.Bytes()
}

func generateEccPreMasterSecret(publicKey []byte, privateKey []byte) []byte {

	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)

	result, _ := elliptic.P256().ScalarMult(x, y, privateKey)
	preMasterSecret := make([]byte, (elliptic.P256().Params().BitSize+7)>>3)
	resultBytes := result.Bytes()
	copy(preMasterSecret[len(preMasterSecret)-len(resultBytes):], resultBytes)

	return resultBytes
}

func generatePrf(key, random1, random2 []byte, label string, keyLen int) []byte {

	buf := make([]byte, 0, keyLen)

	seed := hmac.New(sha256.New, key)
	seed.Write([]byte(label))
	seed.Write(random1)
	seed.Write(random2)
	seedHash := seed.Sum(nil)

	hash := hmac.New(sha256.New, key)

	for len(buf)+len(seedHash) < keyLen {

		hash.Reset()
		hash.Write(seedHash)
		hash.Write([]byte(label))
		hash.Write(random1)
		hash.Write(random2)

		tmp := hash.Sum(nil)

		buf = append(buf, tmp...)

		seed.Reset()
		seed.Write(seedHash)
		seedHash = seed.Sum(nil)
	}

	hash.Reset()
	hash.Write(seedHash)
	hash.Write([]byte(label))
	hash.Write(random1)
	hash.Write(random2)

	tmp := hash.Sum(nil)

	buf = append(buf, tmp...)

	return buf[:keyLen]
}
