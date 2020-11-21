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
	Id       []byte
	Type     string
	peer     *Peer
	listener *Listener
	started  time.Time
	client   struct {
		RandomTime time.Time
		Random     []byte
	}
	server struct {
		RandomTime time.Time
		Random     []byte
	}
	Identity       string
	Psk            []byte
	epoch          uint16
	sequenceNumber uint64
	hash           hash.Hash
	keyBlock       *keyBlock
	handshake      struct {
		state        string
		cookie       []byte
		savedHash    []byte
		seq          uint16
		err          error
		firstDecrypt bool
		done         chan error
	}
	cipher              Cipher
	selectedCipherSuite CipherSuite
	encrypt             bool
	decrypt             bool
	resumed             bool
}

func newClientSession(peer *Peer) *session {
	session := &session{Type: SessionType_Client, started: time.Now(), peer: peer, hash: sha256.New()}
	session.handshake.done = make(chan error)
	session.client.RandomTime = session.started
	randBytes := randomBytes(28)

	//write full random buffer
	w := newByteWriter()
	w.PutUint32(uint32(session.client.RandomTime.Unix()))
	w.PutBytes(randBytes)
	session.client.Random = w.Bytes()
	return session
}

func newServerSession(peer *Peer) *session {
	session := &session{Type: SessionType_Server, started: time.Now(), peer: peer, hash: sha256.New(), Id: randomBytes(32)}
	session.handshake.done = make(chan error)
	session.server.RandomTime = session.started
	randBytes := randomBytes(28)

	//write full random buffer
	w := newByteWriter()
	w.PutUint32(uint32(session.server.RandomTime.Unix()))
	w.PutBytes(randBytes)
	session.server.Random = w.Bytes()
	return session
}

func (s *session) updateHash(data []byte) {
	if DebugHandshakeHash {
		logDebug(s.peer, "dtls: updating hash with [%X]", data)
	}
	s.hash.Write(data)
}

func (s *session) reset() {
	if DebugHandshakeHash {
		logDebug(s.peer, "dtls: reset session state")
	}
	s.decrypt = false
	s.encrypt = false
	s.resumed = false
	s.epoch = 0
	s.sequenceNumber = 0
	s.handshake.state = ""
	s.handshake.cookie = nil
	s.handshake.savedHash = nil
	s.handshake.seq = 0
	s.hash.Reset()
}

func (s *session) resetHash() {
	if DebugHandshakeHash {
		logDebug(s.peer, "dtls: reset hash")
	}
	s.hash.Reset()
}

func (s *session) getHash() []byte {
	sum := s.hash.Sum(nil)
	if DebugHandshakeHash {
		logDebug(s.peer, "dtls: generating hash [%X]", sum)
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

func (s *session) initKeyBlock() {

	//generate pre-master secret
	preMasterSecret := generatePskPreMasterSecret(s.Psk)

	//generate master secret
	masterSecret := generatePrf(preMasterSecret, s.client.Random, s.server.Random, "master secret", 48)

	//generate key block
	rawKeyBlock := generatePrf(masterSecret, s.server.Random, s.client.Random, "key expansion", s.cipher.GetPrfSize())

	s.keyBlock = s.cipher.GenerateKeyBlock(masterSecret, rawKeyBlock)

	if DebugEncryption {
		logDebug(s.peer, "dtls: identity[%s] psk[%X] clientRandom[%X] serverRandom[%X]", s.Identity, s.Psk, s.client.Random, s.server.Random)
		logDebug(s.peer, "dtls: %s", s.keyBlock.Print())
	}

	return
}

func (s *session) isHandshakeDone() bool {
	if s.handshake.state == "finished" || s.handshake.state == "failed" {
		return true
	} else {
		return false
	}
}
