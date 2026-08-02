// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"crypto/sha256"
	"crypto/x509"
	"hash"
	"sync"
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
	peerCert            *x509.Certificate
	peerPublicKey       []byte
	peerCid             []byte
	cid                 []byte
	cidVersion          uint16
	epoch               uint16
	sequenceNumber0     uint64
	sequenceNumber1     uint64
	keyBlock            *KeyBlock
	handshake           *sessionHandshake
	cipher              Cipher
	selectedCipherSuite CipherSuite
	sequenceMu          sync.Mutex
	flightWriteMu       sync.Mutex
	datagramReplayMu    sync.Mutex
	deferFlightReplay   bool
	pendingFlightReplay *pendingHandshakeReplay
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
	masterSecret []byte
	verifySum    []byte
	firstDecrypt bool
	cidEnabled   bool
	dedup        map[uint16]bool
	done         chan error
	client       struct {
		RandomTime time.Time
		Random     []byte
	}
	server struct {
		RandomTime time.Time
		Random     []byte
	}
	completed           time.Time
	fragmentedData      []byte
	retransmitMu        sync.Mutex
	flightCapture       *handshakeFlightCapture
	activeFlight        *handshakeFlight
	retainedFinalFlight *handshakeFlight
	flightGeneration    uint64
}

func newSessionHandshake(ts time.Time, sessionType string) *sessionHandshake {
	sh := sessionHandshake{hash: sha256.New(), done: make(chan error), dedup: map[uint16]bool{}}
	sh.client.RandomTime = ts
	sh.server.RandomTime = ts

	//write full random buffer
	w := newByteWriter()
	w.PutUint32(uint32(ts.Unix()))
	w.PutBytes(randomBytes(28))
	if sessionType == SessionType_Client {
		sh.client.Random = w.Bytes()
	} else {
		sh.server.Random = w.Bytes()
	}
	return &sh
}

func newClientSession(peer *Peer) *session {
	now := time.Now()
	sess := &session{Type: SessionType_Client, started: now, handshake: newSessionHandshake(now, SessionType_Client), peer: peer}
	return sess
}

func newServerSession(peer *Peer) *session {
	now := time.Now()
	sess := &session{Type: SessionType_Server, started: now, peer: peer, handshake: newSessionHandshake(now, SessionType_Server), Id: randomBytes(32)}
	return sess
}

func (s *session) updateHash(rec *record, hs *handshake, data []byte) {
	if !hs.IsHashable() {
		return
	}
	if DebugHandshakeHash {
		logDebug(s.peer, rec, "updating hash with [%X]", data)
	}
	if s.handshake != nil {
		s.handshake.hash.Write(data)
	}
}

func (s *session) reset(rec *record) {
	if DebugHandshakeHash {
		logDebug(s.peer, rec, "reset session state")
	}
	s.stopHandshakeFlights()
	s.sequenceMu.Lock()
	s.epoch = 0
	s.sequenceNumber0 = 0
	s.sequenceNumber1 = 0
	s.sequenceMu.Unlock()
	s.handshake = newSessionHandshake(s.now(), s.Type)
	s.handshake.dedup[0] = true
}

func (s *session) resetHash(rec *record) {
	if DebugHandshakeHash {
		logDebug(s.peer, rec, "reset hash")
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
	s.sequenceMu.Lock()
	defer s.sequenceMu.Unlock()
	s.epoch += uint16(1)
	s.sequenceNumber1 = 0
	return
}

func (s *session) getNextSequence() uint64 {
	return s.getNextSequenceForEpoch(s.epoch)
}

func (s *session) getNextSequenceForEpoch(epoch uint16) uint64 {
	return s.getRecordSequence(epoch, nil)
}

func (s *session) getRecordSequence(epoch uint16, requested *uint64) uint64 {
	s.sequenceMu.Lock()
	defer s.sequenceMu.Unlock()

	if requested != nil {
		next := *requested + 1
		if epoch == 0 {
			if s.sequenceNumber0 < next {
				s.sequenceNumber0 = next
			}
		} else if s.sequenceNumber1 < next {
			s.sequenceNumber1 = next
		}
		return *requested
	}

	if epoch == 0 {
		seq := s.sequenceNumber0
		s.sequenceNumber0 += 1
		return seq
	}
	seq := s.sequenceNumber1
	s.sequenceNumber1 += 1
	return seq
}

func (s *session) getSequence() uint64 {
	if s.epoch == 0 {
		seq := s.sequenceNumber0
		return seq
	} else {
		seq := s.sequenceNumber1
		return seq
	}
}

func (s *session) getPeerCid() []byte {
	return s.peerCid
}

func (s *session) initKeyBlock() {

	if !s.handshake.resumed {
		//generate pre-master secret
		var preMasterSecret []byte
		if len(s.handshake.psk) != 0 {
			preMasterSecret = generatePskPreMasterSecret(s.handshake.psk)
		} else {
			preMasterSecret = generateEccPreMasterSecret(s.peerPublicKey, s.handshake.eccKeypair.privateKey)
		}

		//generate master secret
		s.handshake.masterSecret = generatePrf(preMasterSecret, s.handshake.client.Random, s.handshake.server.Random, "master secret", 48)

	}

	//generate key block
	rawKeyBlock := generatePrf(s.handshake.masterSecret, s.handshake.server.Random, s.handshake.client.Random, "key expansion", s.cipher.GetPrfSize())

	s.keyBlock = s.cipher.GenerateKeyBlock(s.handshake.masterSecret, rawKeyBlock)

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
