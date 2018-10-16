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
		state        string
		cookie       []byte
		savedHash    []byte
		seq          uint16
		err          error
		firstDecrypt bool
		done         chan error
	}
	cipherSuites       []CipherSuite
	compressionMethods []CompressionMethod
	encrypt            bool
	decrypt            bool
}

func newClientSession(peer TransportPeer) *session {
	session := &session{Type: SessionType_Client, peer: peer, hash: sha256.New(),
		cipherSuites: []CipherSuite{CipherSuite_TLS_PSK_WITH_AES_128_CCM_8}, compressionMethods: []CompressionMethod{CompressionMethod_Null}}
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
	session := &session{Type: SessionType_Server, peer: peer, hash: sha256.New(), Id: randomBytes(32),
		cipherSuites: []CipherSuite{CipherSuite_TLS_PSK_WITH_AES_128_CCM_8}, compressionMethods: []CompressionMethod{CompressionMethod_Null}}
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
	if DebugHandshakeHash {
		logDebug(s.peer.String(), "dtls: updating hash with [%X]", data)
	}
	s.hash.Write(data)
}

func (s *session) reset() {
	if DebugHandshakeHash {
		logDebug(s.peer.String(), "dtls: reset session state")
	}
	s.decrypt = false
	s.encrypt = false
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
		logDebug(s.peer.String(), "dtls: reset hash")
	}
	s.hash.Reset()
}

func (s *session) getHash() []byte {
	sum := s.hash.Sum(nil)
	if DebugHandshakeHash {
		logDebug(s.peer.String(), "dtls: generating hash [%X]", sum)
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

func (s *session) initKeyBlock() error {
	var err error

	s.KeyBlock, err = newKeyBlock([]byte(s.Client.Identity), s.Psk, s.Client.Random, s.Server.Random)

	if DebugEncryption {
		logDebug(s.peer.String(), "dtls: identity[%s] psk[%X] clientRandom[%X] serverRandom[%X]", s.Client.Identity, s.Psk, s.Client.Random, s.Server.Random)
		logDebug(s.peer.String(), "dtls: %s", s.KeyBlock.Print())
	}

	return err
}

func (s *session) isHandshakeDone() bool {
	if s.handshake.state == "finished" || s.handshake.state == "failed" {
		return true
	} else {
		return false
	}
}
