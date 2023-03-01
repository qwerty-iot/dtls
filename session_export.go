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
	PeerIdentity        []byte      `json:"peerIdentity"`
	Cid                 []byte      `json:"cid"`
	PeerCid             []byte      `json:"peerCid"`
	CidVersion          uint16      `json:"cidVersion"`
	Epoch               uint16      `json:"epoch"`
	SequenceNumber0     uint64      `json:"sequenceNumber0"`
	SequenceNumber1     uint64      `json:"sequenceNumber1"`
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
		PeerIdentity:        s.peerIdentity,
		Cid:                 s.cid,
		PeerCid:             s.peerCid,
		CidVersion:          s.cidVersion,
		Epoch:               s.epoch,
		SequenceNumber0:     s.sequenceNumber0,
		SequenceNumber1:     s.sequenceNumber1,
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
	s.peerIdentity = ss.PeerIdentity
	s.cid = ss.Cid
	s.peerCid = ss.PeerCid
	s.cidVersion = ss.CidVersion
	s.epoch = ss.Epoch
	s.sequenceNumber0 = ss.SequenceNumber0
	s.sequenceNumber1 = ss.SequenceNumber1
	s.keyBlock = ss.KeyBlock
	s.selectedCipherSuite = ss.SelectedCipherSuite
	s.cipher = getCipher(s.peer, s.selectedCipherSuite)
	s.handshake.state = "finished"
	return
}
