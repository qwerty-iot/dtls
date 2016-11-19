package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/bocajim/dtls/common"
)

const (
	AadAuthLen int = 13
)

func CreateNonce(iv []byte, epoch uint16, seq uint64) []byte {
	nonce := new(bytes.Buffer)
	nonce.Write(iv)
	seq += uint64(epoch) << 48
	binary.Write(nonce, binary.BigEndian, seq)
	return nonce.Bytes()
}

func CreateAad(epoch uint16, seq uint64, msgType uint8, dataLen uint16) []byte {
	w := common.NewWriter()
	w.PutUint16(epoch)
	w.PutUint48(seq)
	w.PutUint8(msgType)
	w.PutUint16(common.DtlsVersion12)
	w.PutUint16(dataLen)
	return w.Bytes()
}

type KeyBlock struct {
	MasterSecret   []byte
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientIV       []byte
	ServerIV       []byte
}

func (kb *KeyBlock) Print() string {
	return fmt.Sprintf("ClientWriteKey[%X], ServerWriteKey[%X], ClientIV[%X], ServerIV[%X]", kb.ClientWriteKey, kb.ServerWriteKey, kb.ClientIV, kb.ServerIV)
}

func CreateKeyBlock(identity []byte, psk, clientRandom, serverRandom []byte) (*KeyBlock, error) {

	//find PSK based on identity
	//psk := hackedPsk

	//generate pre-master secret
	preMasterSecret, err := generatePskPreMasterSecret(psk)
	if err != nil {
		return nil, err
	}

	//generate master secret
	masterSecret := GeneratePrf(preMasterSecret, clientRandom, serverRandom, "master secret", 48)

	//generate key block
	rawKeyBlock := GeneratePrf(masterSecret, serverRandom, clientRandom, "key expansion", 48)

	keyBlock := &KeyBlock{MasterSecret: masterSecret, ClientWriteKey: rawKeyBlock[0:16], ServerWriteKey: rawKeyBlock[16:32], ClientIV: rawKeyBlock[32:36], ServerIV: rawKeyBlock[36:40]}

	return keyBlock, nil
}

//dtls_psk_pre_master_secret(unsigned char *key, size_t keylen,unsigned char *result, size_t result_len)
func generatePskPreMasterSecret(psk []byte) ([]byte, error) {

	zeroBuffer := make([]byte, len(psk))

	w := common.NewWriter()

	w.PutUint16(uint16(len(psk)))
	w.PutBytes(zeroBuffer)
	w.PutUint16(uint16(len(psk)))
	w.PutBytes(psk)

	return w.Bytes(), nil
}

/*  dtls_prf(pre_master_secret, pre_master_len,
PRF_LABEL(master), PRF_LABEL_SIZE(master),
handshake->tmp.random.client, DTLS_RANDOM_LENGTH,
handshake->tmp.random.server, DTLS_RANDOM_LENGTH,
master_secret,
DTLS_MASTER_SECRET_LENGTH);
*/
func GeneratePrf(key, random1, random2 []byte, label string, keyLen int) []byte {

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
