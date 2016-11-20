package dtls

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"time"
)

const (
	SessionType_Server string = "server"
	SessionType_Client string = "client"
)

type session struct {
	Id     []byte
	Type   string
	peer   TransportPeer
	Client struct {
		Identity   string
		RandomTime time.Time
		Random     []byte
	}
	Server struct {
		Identity   string
		RandomTime time.Time
		Random     []byte
	}
	Psk            []byte
	epoch          uint16
	sequenceNumber uint64
	hash           hash.Hash
	KeyBlock       *keyBlock
	handshake      struct {
		state     string
		cookie    []byte
		savedHash []byte
		seq       uint16
		err       error
		done      chan error
	}
	encrypt bool
	decrypt bool
}

func newClientSession(peer TransportPeer) *session {
	session := &session{Type: SessionType_Client, peer: peer, hash: sha256.New()}
	session.handshake.done = make(chan error)
	session.Client.RandomTime = time.Now()
	randBytes := randomBytes(28)

	//write full random buffer
	w := newByteWriter()
	w.PutUint32(uint32(session.Client.RandomTime.Unix()))
	w.PutBytes(randBytes)
	session.Client.Random = w.Bytes()
	return session
}

func newServerSession(peer TransportPeer) *session {
	session := &session{Type: SessionType_Server, peer: peer, hash: sha256.New(), Id: randomBytes(32)}
	session.handshake.done = make(chan error)
	session.Server.RandomTime = time.Now()
	randBytes := randomBytes(28)

	//write full random buffer
	w := newByteWriter()
	w.PutUint32(uint32(session.Server.RandomTime.Unix()))
	w.PutBytes(randBytes)
	session.Server.Random = w.Bytes()
	return session
}

func (s *session) updateHash(data []byte) {
	logDebug("dtls: [%s] updating hash with [%X]", s.peer.String(), data)
	s.hash.Write(data)
}

func (s *session) resetHash() {
	logDebug("dtls: [%s] reset hash", s.peer.String())
	s.hash.Reset()
}

func (s *session) getHash() []byte {
	sum := s.hash.Sum(nil)
	logDebug("dtls: [%s] generating hash [%X]", s.peer.String(), sum)
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

func (s *session) initKeyBlock() error {
	var err error
	logDebug("dtls: [%s] identity[%s] psk[%X] clientRandom[%X] serverRandom[%X]", s.peer.String(), s.Client.Identity, s.Psk, s.Client.Random, s.Server.Random)
	s.KeyBlock, err = newKeyBlock([]byte(s.Client.Identity), s.Psk, s.Client.Random, s.Server.Random)

	logDebug("dtls: [%s] %s", s.peer.String(), s.KeyBlock.Print())
	return err
}

func (s *session) initSecurity(clientId, serverId, psk string) {
	if len(clientId) > 0 {
		s.Client.Identity = clientId
	}
	if len(serverId) > 0 {
		s.Server.Identity = serverId
	}
	if len(psk) > 0 {
		s.Psk, _ = hex.DecodeString(psk)
	}
}

func (s *session) isHandshakeDone() bool {
	if s.handshake.state == "finished" || s.handshake.state == "failed" {
		return true
	} else {
		return false
	}
}
