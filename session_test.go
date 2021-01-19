package dtls

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type nilPeer struct {
}

func (p *nilPeer) String() string {
	return "nil"
}
func (p *nilPeer) WritePacket(data []byte) error {
	return nil
}

func TestSessionSuite(t *testing.T) {
	suite.Run(t, new(SessionSuite))
}

type SessionSuite struct {
	suite.Suite
}

func (s *SessionSuite) Log(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}

func (s *SessionSuite) TestTypeToString() {

	peer := newClientSession(&Peer{transport: &nilPeer{}})
	peer.peerIdentity = []byte("peerIdentity")
	peer.handshake.client.Random, _ = hex.DecodeString("00000001E68D63E65CDEF492AA9877330CA7EEB5C786487F31DAE89452104156")
	peer.handshake.server.Random, _ = hex.DecodeString("5823185CF999576643D2E838C4FCAEAC6AE89C12C9E25517D95FE115C50BF080")
	peer.handshake.psk, _ = hex.DecodeString("0011223344")
	peer.cipher = CipherCcm{peer: peer.peer}
	peer.initKeyBlock()

	peer.keyBlock.Print()

	assert.Equal(s.T(), "CE3DB22CD0931C3E752176B43EB1939A", strings.ToUpper(hex.EncodeToString(peer.keyBlock.ClientWriteKey)))
	assert.Equal(s.T(), "3501B84CF54E2654090E82ABEFCDCCBD", strings.ToUpper(hex.EncodeToString(peer.keyBlock.ServerWriteKey)))
	assert.Equal(s.T(), "F21CE4E5", strings.ToUpper(hex.EncodeToString(peer.keyBlock.ClientIV)))
	assert.Equal(s.T(), "235A077A", strings.ToUpper(hex.EncodeToString(peer.keyBlock.ServerIV)))
}
