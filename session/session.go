package session

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"time"

	"github.com/bocajim/dtls/common"
	"github.com/bocajim/dtls/crypto"
	"github.com/bocajim/dtls/transport"
)

const (
	TypeServer string = "server"
	TypeClient string = "client"
)

type Session struct {
	Id     []byte
	Type   string
	peer   transport.Peer
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
	KeyBlock       *crypto.KeyBlock
	handshake      struct {
		state     string
		cookie    []byte
		savedHash []byte
		seq       uint16
		done      chan bool
	}
	encrypt bool
	decrypt bool
}

func NewClientSession(peer transport.Peer) *Session {
	session := &Session{Type: TypeClient, peer: peer, hash: sha256.New()}
	session.Client.RandomTime = time.Now()
	randBytes := common.RandomBytes(28)

	//write full random buffer
	w := common.NewWriter()
	w.PutUint32(uint32(session.Client.RandomTime.Unix()))
	w.PutBytes(randBytes)
	session.Client.Random = w.Bytes()
	return session
}

func NewServerSession(peer transport.Peer) *Session {
	session := &Session{Type: TypeServer, peer: peer, hash: sha256.New(), Id: common.RandomBytes(32)}
	session.Server.RandomTime = time.Now()
	randBytes := common.RandomBytes(28)

	//write full random buffer
	w := common.NewWriter()
	w.PutUint32(uint32(session.Server.RandomTime.Unix()))
	w.PutBytes(randBytes)
	session.Server.Random = w.Bytes()
	return session
}

func (s *Session) UpdateHash(data []byte) {
	common.LogDebug("dtls: [%s] updating hash with [%X]", s.peer.String(), data)
	s.hash.Write(data)
}

func (s *Session) ResetHash() {
	common.LogDebug("dtls: [%s] reset hash", s.peer.String())
	s.hash.Reset()
}

func (s *Session) GetHash() []byte {
	sum := s.hash.Sum(nil)
	common.LogDebug("dtls: [%s] generating hash [%X]", s.peer.String(), sum)
	return sum
}

func (s *Session) GetEpoch() uint16 {
	return s.epoch
}

func (s *Session) IncEpoch() {
	s.epoch += uint16(1)
	s.sequenceNumber = 0
	return
}

func (s *Session) GetNextSequence() uint64 {
	seq := s.sequenceNumber
	s.sequenceNumber += 1
	return seq
}

func (s *Session) InitKeyBlock() error {
	var err error
	common.LogDebug("dtls: [%s] identity[%s] psk[%X] clientRandom[%X] serverRandom[%X]", s.peer.String(), s.Client.Identity, s.Psk, s.Client.Random, s.Server.Random)
	s.KeyBlock, err = crypto.CreateKeyBlock([]byte(s.Client.Identity), s.Psk, s.Client.Random, s.Server.Random)

	common.LogDebug("dtls: [%s] %s", s.peer.String(), s.KeyBlock.Print())
	return err
}

func (s *Session) InitSecurity(clientId, serverId, psk string) {
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

func (s *Session) IsHandshakeDone() bool {
	if s.handshake.state == "finished" || s.handshake.state == "failed" {
		return true
	} else {
		return false
	}
}
