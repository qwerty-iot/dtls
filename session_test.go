package dtls

import (
	"encoding/hex"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

type nilPeer struct {
}

func (p *nilPeer) String() string {
	return "nil"
}
func (p *nilPeer) WritePacket(data []byte) error {
	return nil
}

func SessionTest(t *testing.T) { TestingT(t) }

var _ = Suite(&SessionSuite{})

type SessionSuite struct{}

func (s *SessionSuite) SetUpSuite(c *C) {
}

func (s *SessionSuite) TestTypeToString(c *C) {

	peer := newClientSession(&nilPeer{})
	peer.Client.Identity = "Identity"
	peer.Client.Random, _ = hex.DecodeString("00000001E68D63E65CDEF492AA9877330CA7EEB5C786487F31DAE89452104156")
	peer.Server.Identity = "Identity"
	peer.Server.Random, _ = hex.DecodeString("5823185CF999576643D2E838C4FCAEAC6AE89C12C9E25517D95FE115C50BF080")
	peer.Psk, _ = hex.DecodeString("0011223344")

	peer.initKeyBlock()

	peer.KeyBlock.Print()

	c.Assert(strings.ToUpper(hex.EncodeToString(peer.KeyBlock.ClientWriteKey)), Equals, "CE3DB22CD0931C3E752176B43EB1939A")
	c.Assert(strings.ToUpper(hex.EncodeToString(peer.KeyBlock.ServerWriteKey)), Equals, "3501B84CF54E2654090E82ABEFCDCCBD")
	c.Assert(strings.ToUpper(hex.EncodeToString(peer.KeyBlock.ClientIV)), Equals, "F21CE4E5")
	c.Assert(strings.ToUpper(hex.EncodeToString(peer.KeyBlock.ServerIV)), Equals, "235A077A")
}
