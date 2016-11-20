package dtls

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bocajim/dtls/ccm"
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
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientIV       []byte
	ServerIV       []byte
}

func (kb *keyBlock) Print() string {
	return fmt.Sprintf("ClientWriteKey[%X], ServerWriteKey[%X], ClientIV[%X], ServerIV[%X]", kb.ClientWriteKey, kb.ServerWriteKey, kb.ClientIV, kb.ServerIV)
}

func newKeyBlock(identity []byte, psk, clientRandom, serverRandom []byte) (*keyBlock, error) {

	//generate pre-master secret
	preMasterSecret := generatePskPreMasterSecret(psk)

	//generate master secret
	masterSecret := generatePrf(preMasterSecret, clientRandom, serverRandom, "master secret", 48)

	//generate key block
	rawKeyBlock := generatePrf(masterSecret, serverRandom, clientRandom, "key expansion", 48)

	keyBlock := &keyBlock{MasterSecret: masterSecret, ClientWriteKey: rawKeyBlock[0:16], ServerWriteKey: rawKeyBlock[16:32], ClientIV: rawKeyBlock[32:36], ServerIV: rawKeyBlock[36:40]}

	return keyBlock, nil
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

func dataEncrypt(data []byte, nonce []byte, key []byte, aad []byte, peer string) ([]byte, error) {

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ccmCipher, err := ccm.NewCCM(cipher, 8, 12)
	if err != nil {
		return nil, err
	}

	if len(peer) > 0 {
		logDebug("dtls: [%s] encrypt nonce[%X] key[%X] aad[%X]", peer, nonce, key, aad)
		logDebug("dtls: [%s] encrypt clearText[%X][%d]", peer, data, len(data))
	}

	cipherTextLen := (len(data) / 16) * 16
	if len(data)%16 != 0 {
		cipherTextLen += 16
	}
	cipherText := make([]byte, 0, cipherTextLen)

	if len(nonce) != 12 {
		return nil, errors.New("dtls: invalid nonce length")
	}
	cipherText = ccmCipher.Seal(cipherText, nonce, data, aad)
	if len(peer) > 0 {
		logDebug("dtls: [%s] encrypt cipherText[%X][%d]", peer, cipherText, len(cipherText))
	}
	return cipherText, nil
}

func dataDecrypt(data []byte, nonce []byte, key []byte, aad []byte, peer string) ([]byte, error) {

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ccmCipher, err := ccm.NewCCM(cipher, 8, 12)
	if err != nil {
		return nil, err
	}

	if len(peer) > 0 {
		logDebug("dtls: [%s] decrypt nonce[%X] key[%X] aad[%X]", peer, nonce, key, aad)
		logDebug("stls: [%s] decrypt cipherText[%X][%d]", peer, data, len(data))
	}

	clearText := make([]byte, 0, len(data))

	clearText, err = ccmCipher.Open(clearText, nonce, data, aad)
	if err != nil {
		return nil, err
	}
	if len(peer) > 0 {
		logDebug("dtls: [%s] decrypt clearText[%X][%d]", peer, clearText, len(clearText))
	}
	return clearText, nil
}
