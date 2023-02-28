// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type CipherCBC struct {
	peer *Peer
}

func (c CipherCBC) GetPrfSize() int {
	return 128
}

func (c CipherCBC) GenerateKeyBlock(masterSecret []byte, rawKeyBlock []byte) *KeyBlock {
	return &KeyBlock{
		MasterSecret:   masterSecret,
		ClientMac:      rawKeyBlock[0:32],
		ServerMac:      rawKeyBlock[32:64],
		ClientWriteKey: rawKeyBlock[64:80],
		ServerWriteKey: rawKeyBlock[80:96],
		ClientIV:       rawKeyBlock[96:112],
		ServerIV:       rawKeyBlock[112:128]}
}

func newMac(s *session, epoch uint16, seq uint64, msgType uint8, data []byte, key []byte, cid []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)

	// TODO-CID: implement
	aad := newAad(s, epoch, seq, msgType, nil, uint16(len(data)))

	if _, err := h.Write(aad); err != nil {
		return nil, err
	} else if _, err := h.Write(data); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (c CipherCBC) Encrypt(s *session, rec *record, key []byte, iv []byte, mac []byte) ([]byte, error) {

	clearText := rec.Data

	cbcCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(cbcCipher, iv).(cbcMode)
	blockSize := cbc.BlockSize()

	MAC, err := newMac(s, rec.Epoch, rec.Sequence, uint8(rec.ContentType), clearText, mac, s.peerCid)
	if err != nil {
		return nil, err
	}
	clearText = append(clearText, MAC...)

	// Generate + Append padding
	padding := make([]byte, blockSize-len(clearText)%blockSize)
	paddingLen := len(padding)
	for i := 0; i < paddingLen; i++ {
		padding[i] = byte(paddingLen - 1)
	}
	clearText = append(clearText, padding...)

	if DebugEncryption && c.peer != nil {
		logDebug(c.peer, rec, "encrypt mac[%X] paddingLen[%d]", MAC, paddingLen)
		logDebug(c.peer, rec, "encrypt clearText[%X][%d]", clearText, len(clearText))
	}

	// Generate IV
	tiv := make([]byte, blockSize)
	if _, err := rand.Read(tiv); err != nil {
		return nil, err
	}

	// Set IV + Encrypt + Prepend IV
	cbc.SetIV(tiv)
	cipherText := make([]byte, len(clearText))
	cbc.CryptBlocks(cipherText, clearText)
	cipherText = append(tiv, cipherText...)

	if DebugEncryption && c.peer != nil {
		logDebug(c.peer, rec, "encrypt cipherText[%X][%d]", cipherText, len(cipherText))
	}
	return cipherText, nil
}

func (c CipherCBC) Decrypt(s *session, rec *record, key []byte, iv []byte, mac []byte) ([]byte, error) {

	cbcCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(cbcCipher, iv).(cbcMode)
	blockSize := cbc.BlockSize()
	macCalc := sha256.New()

	tiv := rec.Data[:blockSize]
	cipherText := rec.Data[blockSize:]

	if DebugEncryption && c.peer != nil {
		logDebug(c.peer, rec, "decrypt iv[%X] blockSize[%d] macSize[%d]", tiv, blockSize, macCalc.Size())
		logDebug(c.peer, rec, "decrypt cipherText[%X][%d]", cipherText, len(cipherText))
	}

	cbc.SetIV(tiv)
	clearText := make([]byte, len(cipherText))
	cbc.CryptBlocks(clearText, cipherText)

	// Padding+MAC needs to be checked in constant time
	// Otherwise we reveal information about the level of correctness
	paddingLen, paddingGood := examinePadding(clearText)

	macSize := macCalc.Size()
	if len(clearText) < macSize {
		return nil, errors.New("dtls: invalid mac")
	}

	dataEnd := len(clearText) - macSize - paddingLen

	expectedMAC := clearText[dataEnd : dataEnd+macSize]

	clearText = clearText[:dataEnd]

	actualMAC, err := newMac(s, rec.Epoch, rec.Sequence, uint8(rec.ContentType), clearText, mac, s.cid)
	if paddingGood != 255 || err != nil || !hmac.Equal(actualMAC, expectedMAC) {
		return nil, errors.New("dtls: mac invalid")
	}

	if DebugEncryption && c.peer != nil {
		logDebug(c.peer, rec, "decrypt clearText[%X][%d]", clearText, len(clearText))
	}

	return clearText, nil
}

func examinePadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	// if len(payload) >= (paddingLen - 1) then the MSB of t is zero
	good = byte(int32(^t) >> 31)

	// The maximum possible padding length plus the actual length field
	toCheck := 256
	// The length of the padded data is public, so we can use an if here
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	toRemove = int(paddingLen) + 1

	return toRemove, good
}
