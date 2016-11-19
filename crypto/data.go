package crypto

import (
	"crypto/aes"

	"github.com/bocajim/dtls/common"
	"github.com/bocajim/dtls/crypto/ccm"
)

func PayloadEncrypt(data []byte, nonce []byte, key []byte, aad []byte, peer string) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ccmCipher, err := ccm.NewCCM(cipher, 8, 12)
	if err != nil {
		return nil, err
	}

	if len(peer) > 0 {
		common.LogDebug("dtls: [%s] encrypt nonce[%X] key[%X] aad[%X]", peer, nonce, key, aad)
		common.LogDebug("dtls: [%s] encrypt clearText[%X][%d]", peer, data, len(data))
	}

	cipherTextLen := (len(data) / 16) * 16
	if len(data)%16 != 0 {
		cipherTextLen += 16
	}
	cipherText := make([]byte, 0, cipherTextLen)

	cipherText = ccmCipher.Seal(cipherText, nonce, data, aad)
	if len(peer) > 0 {
		common.LogDebug("dtls: [%s] encrypt cipherText[%X][%d]", peer, cipherText, len(cipherText))
	}
	return cipherText, nil
}

func PayloadDecrypt(data []byte, nonce []byte, key []byte, aad []byte, peer string) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ccmCipher, err := ccm.NewCCM(cipher, 8, 12)
	if err != nil {
		return nil, err
	}

	if len(peer) > 0 {
		common.LogDebug("dtls: [%s] decrypt nonce[%X] key[%X] aad[%X]", peer, nonce, key, aad)
		common.LogDebug("stls: [%s] decrypt cipherText[%X][%d]", peer, data, len(data))
	}

	clearText := make([]byte, 0, len(data))

	clearText, err = ccmCipher.Open(clearText, nonce, data, aad)
	if err != nil {
		return nil, err
	}
	if len(peer) > 0 {
		common.LogDebug("dtls: [%s] decrypt clearText[%X][%d]", peer, clearText, len(clearText))
	}
	return clearText, nil
}
