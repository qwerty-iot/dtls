package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	dtls13UnifiedHeaderFixedBits byte = 0x20
	dtls13UnifiedHeaderCID       byte = 0x10
	dtls13UnifiedHeaderSeq16     byte = 0x08
	dtls13UnifiedHeaderLength    byte = 0x04
)

type dtls13Ciphertext struct {
	Epoch       uint64
	Sequence    uint64
	ContentType ContentType
	Data        []byte
}

func dtls13BuildHeader(epoch uint64, sequence uint64, length int) []byte {
	w := newByteWriter()
	w.PutUint8(dtls13UnifiedHeaderFixedBits | dtls13UnifiedHeaderSeq16 | dtls13UnifiedHeaderLength | byte(epoch&0x03))
	w.PutUint16(uint16(sequence))
	w.PutUint16(uint16(length))
	return w.Bytes()
}

func dtls13RecordNonce(iv []byte, sequence uint64) []byte {
	nonce := append([]byte(nil), iv...)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], sequence)
	for i := 0; i < len(seq); i++ {
		nonce[len(nonce)-len(seq)+i] ^= seq[i]
	}
	return nonce
}

func dtls13AEAD(cipherSuite CipherSuite, key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch cipherSuite {
	case CipherSuite_TLS_AES_128_GCM_SHA256:
		return cipher.NewGCM(block)
	case CipherSuite_TLS_AES_128_CCM_SHA256:
		return NewCCM(block, 16, 12)
	case CipherSuite_TLS_AES_128_CCM_8_SHA256:
		return NewCCM(block, 8, 12)
	default:
		return nil, errors.New("dtls: unsupported DTLS 1.3 cipher suite")
	}
}

func dtls13ProtectRecord(cipherSuite CipherSuite, keys dtls13TrafficKeys, epoch uint64, sequence uint64, contentType ContentType, plaintext []byte) ([]byte, error) {
	aead, err := dtls13AEAD(cipherSuite, keys.Key)
	if err != nil {
		return nil, err
	}
	inner := append([]byte(nil), plaintext...)
	inner = append(inner, byte(contentType))
	for len(inner)+aead.Overhead() < 16 {
		inner = append(inner, 0)
	}
	header := dtls13BuildHeader(epoch, sequence, len(inner)+aead.Overhead())
	nonce := dtls13RecordNonce(keys.IV, sequence)
	encrypted := aead.Seal(nil, nonce, inner, header)
	out := append([]byte(nil), header...)
	out = append(out, encrypted...)
	dtls13MaskSequenceNumber(keys.SNKey, out[:5], out[5:])
	return out, nil
}

func dtls13UnprotectRecord(cipherSuite CipherSuite, keys dtls13TrafficKeys, raw []byte) (*dtls13Ciphertext, error) {
	if len(raw) < 5 {
		return nil, errors.New("dtls: DTLS 1.3 record too small")
	}
	header := append([]byte(nil), raw[:5]...)
	encrypted := append([]byte(nil), raw[5:]...)
	dtls13MaskSequenceNumber(keys.SNKey, header, encrypted)
	if header[0]&0xE0 != dtls13UnifiedHeaderFixedBits {
		return nil, errors.New("dtls: invalid DTLS 1.3 unified header")
	}
	if header[0]&dtls13UnifiedHeaderCID != 0 || header[0]&dtls13UnifiedHeaderSeq16 == 0 || header[0]&dtls13UnifiedHeaderLength == 0 {
		return nil, errors.New("dtls: unsupported DTLS 1.3 record header variant")
	}
	epoch := uint64(header[0] & 0x03)
	sequence := uint64(binary.BigEndian.Uint16(header[1:3]))
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length != len(encrypted) {
		return nil, errors.New("dtls: DTLS 1.3 record length mismatch")
	}
	aead, err := dtls13AEAD(cipherSuite, keys.Key)
	if err != nil {
		return nil, err
	}
	nonce := dtls13RecordNonce(keys.IV, sequence)
	inner, err := aead.Open(nil, nonce, encrypted, header)
	if err != nil {
		return nil, err
	}
	for len(inner) > 0 && inner[len(inner)-1] == 0 {
		inner = inner[:len(inner)-1]
	}
	if len(inner) == 0 {
		return nil, errors.New("dtls: DTLS 1.3 inner plaintext missing content type")
	}
	contentType := ContentType(inner[len(inner)-1])
	inner = inner[:len(inner)-1]
	return &dtls13Ciphertext{Epoch: epoch, Sequence: sequence, ContentType: contentType, Data: inner}, nil
}

func dtls13MaskSequenceNumber(snKey []byte, header []byte, encrypted []byte) {
	if len(encrypted) < 16 || len(header) < 3 {
		return
	}
	block, err := aes.NewCipher(snKey)
	if err != nil {
		return
	}
	var mask [16]byte
	block.Encrypt(mask[:], encrypted[:16])
	header[1] ^= mask[0]
	header[2] ^= mask[1]
}
