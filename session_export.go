package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

var storeKey []byte
var storeIv []byte

func SetExportSecret(key string) {
	hash := sha256.Sum256([]byte(key + ":dtls"))
	storeKey = hash[:16]
	storeIv = hash[16:]
}

type SessionStore struct {
	Id                  []byte      `json:"id"`
	Type                string      `json:"type"`
	RemoteAddr          string      `json:"remoteAddr"`
	Epoch               uint16      `json:"epoch"`
	SequenceNumber      uint64      `json:"sequenceNumber"`
	KeyBlock            *KeyBlock   `json:"KeyBlock"`
	SelectedCipherSuite CipherSuite `json:"selectedCipherSuite"`
}

func (s *session) export() string {

	if len(storeKey) == 0 {
		return ""
	}

	ss := SessionStore{
		Id:                  s.Id,
		Type:                s.Type,
		RemoteAddr:          s.peer.RemoteAddr(),
		Epoch:               s.epoch,
		SequenceNumber:      s.sequenceNumber,
		KeyBlock:            s.keyBlock,
		SelectedCipherSuite: s.selectedCipherSuite,
	}

	b, _ := json.Marshal(ss)

	block, err := aes.NewCipher(storeKey)
	if err != nil {
		return ""
	}
	stream := cipher.NewCFBEncrypter(block, storeIv)

	stream.XORKeyStream(b, b)

	return base64.StdEncoding.EncodeToString(b)
}

func (s *session) restore(raw string) {
	if len(storeKey) == 0 {
		return
	}

	if len(raw) == 0 {
		return
	}

	block, _ := aes.NewCipher(storeKey)
	stream := cipher.NewCFBDecrypter(block, storeIv)

	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return
	}

	stream.XORKeyStream(b, b)

	var ss SessionStore
	err = json.Unmarshal(b, &ss)
	if err != nil {
		return
	}
	s.Id = ss.Id
	s.Type = ss.Type
	s.epoch = ss.Epoch
	s.sequenceNumber = ss.SequenceNumber
	s.keyBlock = ss.KeyBlock
	s.selectedCipherSuite = ss.SelectedCipherSuite
	s.cipher = getCipher(s.peer, s.selectedCipherSuite)
	s.encrypt = true
	s.decrypt = true
	s.handshake.state = "finished"
	return
}
