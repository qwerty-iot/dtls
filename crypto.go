package dtls

import (
	"bytes"
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

func newAad(epoch uint16, seq uint64, msgType uint8, dataLen uint16) []byte {
	w := newByteWriter()
	w.PutUint16(epoch)
	w.PutUint48(seq)
	w.PutUint8(msgType)
	w.PutUint16(DtlsVersion12)
	w.PutUint16(dataLen)
	return w.Bytes()
}

type keyBlock struct {
	MasterSecret   []byte
	ClientMac      []byte
	ServerMac      []byte
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientIV       []byte
	ServerIV       []byte
}

func (kb *keyBlock) Print() string {
	return fmt.Sprintf("ClientWriteKey[%X], ServerWriteKey[%X], ClientIV[%X], ServerIV[%X]", kb.ClientWriteKey, kb.ServerWriteKey, kb.ClientIV, kb.ServerIV)
}

//dtls_psk_pre_master_secret(unsigned char *key, size_t keylen,unsigned char *result, size_t result_len)
func generatePskPreMasterSecret(psk []byte) []byte {

	zeroBuffer := make([]byte, len(psk))

	w := newByteWriter()

	w.PutUint16(uint16(len(psk)))
	w.PutBytes(zeroBuffer)
	w.PutUint16(uint16(len(psk)))
	w.PutBytes(psk)

	return w.Bytes()
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
