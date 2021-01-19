// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"crypto/sha256"
	"hash"
	"time"
)

const (
	SessionType_Server string = "server"
	SessionType_Client string = "client"
)

type session struct {
	Id                  []byte
	Type                string
	peer                *Peer
	listener            *Listener
	started             time.Time
	peerIdentity        []byte
	peerPublicKey       []byte
	epoch               uint16
	sequenceNumber      uint64
	keyBlock            *KeyBlock
	handshake           *sessionHandshake
	cipher              Cipher
	selectedCipherSuite CipherSuite
	encrypt             bool
	decrypt             bool
}

type sessionHandshake struct {
	hash         hash.Hash
	state        string
	resumed      bool
	cookie       []byte
	savedHash    []byte
	seq          uint16
	err          error
	certs        [][]byte
	psk          []byte
	eccCurve     eccCurve
	eccKeypair   *eccKeypair
	verifySum    []byte
	firstDecrypt bool
	done         chan error
	client       struct {
		RandomTime time.Time
		Random     []byte
	}
	server struct {
		RandomTime time.Time
		Random     []byte
	}
}

func newSessionHandshake(ts time.Time) *sessionHandshake {
	sh := sessionHandshake{hash: sha256.New(), done: make(chan error)}
	sh.client.RandomTime = ts
	sh.server.RandomTime = ts

	//write full random buffer
	w := newByteWriter()
	w.PutUint32(uint32(ts.Unix()))
	w.PutBytes(randomBytes(28))
	sh.client.Random = w.Bytes()
	sh.server.Random = w.Bytes()
	return &sh
}

func newClientSession(peer *Peer) *session {
	now := time.Now()
	session := &session{Type: SessionType_Client, started: now, handshake: newSessionHandshake(now), peer: peer}
	return session
}

func newServerSession(peer *Peer) *session {
	now := time.Now()
	session := &session{Type: SessionType_Server, started: now, peer: peer, handshake: newSessionHandshake(now), Id: randomBytes(32)}
	return session
}

func (s *session) updateHash(data []byte) {
	if DebugHandshakeHash {
		logDebug(s.peer, nil, "updating hash with [%X]", data)
	}
	if s.handshake != nil {
		s.handshake.hash.Write(data)
	}
}

func (s *session) reset() {
	if DebugHandshakeHash {
		logDebug(s.peer, nil, "reset session state")
	}
	s.decrypt = false
	s.encrypt = false
	s.epoch = 0
	s.sequenceNumber = 0
	s.handshake = newSessionHandshake(time.Now())
}

func (s *session) resetHash() {
	if DebugHandshakeHash {
		logDebug(s.peer, nil, "reset hash")
	}
	s.handshake.hash.Reset()
}

func (s *session) getHash() []byte {
	sum := s.handshake.hash.Sum(nil)
	if DebugHandshakeHash {
		logDebug(s.peer, nil, "generating hash [%X]", sum)
	}
	return sum
}

func (s *session) getEpoch() uint16 {
	return s.epoch
}

func (s *session) incEpoch() {
	s.epoch += uint16(1)
	s.sequenceNumber = 0
	return
}

func (s *session) getNextSequence() uint64 {
	seq := s.sequenceNumber
	s.sequenceNumber += 1
	return seq
}

func (s *session) getSequence() uint64 {
	seq := s.sequenceNumber
	return seq
}

func (s *session) initKeyBlock() {

	//generate pre-master secret
	var preMasterSecret []byte
	if len(s.handshake.psk) != 0 {
		preMasterSecret = generatePskPreMasterSecret(s.handshake.psk)
	} else {
		preMasterSecret = generateEccPreMasterSecret(s.peerPublicKey, s.handshake.eccKeypair.privateKey)
	}

	//generate master secret
	masterSecret := generatePrf(preMasterSecret, s.handshake.client.Random, s.handshake.server.Random, "master secret", 48)

	//generate key block
	rawKeyBlock := generatePrf(masterSecret, s.handshake.server.Random, s.handshake.client.Random, "key expansion", s.cipher.GetPrfSize())

	s.keyBlock = s.cipher.GenerateKeyBlock(masterSecret, rawKeyBlock)

	if DebugEncryption {
		if len(s.peerIdentity) != 0 {
			logDebug(s.peer, nil, "identity[%s] psk[%X] clientRandom[%X] serverRandom[%X]", string(s.peerIdentity), s.handshake.psk, s.handshake.client.Random, s.handshake.server.Random)
		} else {
			logDebug(s.peer, nil, "publicKey[%X] clientRandom[%X] serverRandom[%X]", s.peerPublicKey, s.handshake.client.Random, s.handshake.server.Random)
		}
		logDebug(s.peer, nil, "%s", s.keyBlock.Print())
	}

	return
}

func (s *session) isHandshakeDone() bool {
	if s.handshake == nil || s.handshake.state == "finished" || s.handshake.state == "failed" {
		return true
	} else {
		return false
	}
}
