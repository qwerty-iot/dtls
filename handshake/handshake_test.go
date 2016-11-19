package handshake

import (
	"encoding/hex"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/bocajim/dtls/common"
)

func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&HandshakeSuite{})

type HandshakeSuite struct{}

func (s *HandshakeSuite) SetUpSuite(c *C) {
}

func (s *HandshakeSuite) TestClientHelloDecode(c *C) {
	hb, _ := hex.DecodeString("0100002a000000000000002afefd00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db600000002c0a80100")
	handshake, err := ParseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientHello, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_ClientHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x2a))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x2a))

	c.Assert(handshake.ClientHello.version, Equals, common.DtlsVersion12)
	c.Assert(handshake.ClientHello.randomTime, Equals, uint32(1))
	c.Assert(hex.EncodeToString(handshake.ClientHello.randomBytes), Equals, "00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db6")
	c.Assert(hex.EncodeToString(handshake.ClientHello.sessionId), Equals, "")
	c.Assert(hex.EncodeToString(handshake.ClientHello.cookie), Equals, "")
	c.Assert(handshake.ClientHello.cipherSuites[0], Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)

	hb, _ = hex.DecodeString("0100004a000100000000004afefd00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db60020d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d80002c0a80100")
	handshake, err = ParseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientHello, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_ClientHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x4a))
	c.Assert(handshake.Header.Sequence, Equals, uint16(1))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x4a))

	c.Assert(handshake.ClientHello.version, Equals, common.DtlsVersion12)
	c.Assert(handshake.ClientHello.randomTime, Equals, uint32(1))
	c.Assert(hex.EncodeToString(handshake.ClientHello.randomBytes), Equals, "00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db6")
	c.Assert(hex.EncodeToString(handshake.ClientHello.sessionId), Equals, "")
	c.Assert(hex.EncodeToString(handshake.ClientHello.cookie), Equals, "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
	c.Assert(handshake.ClientHello.cipherSuites[0], Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)

}

func (s *HandshakeSuite) TestClientHelloEncode(c *C) {

	randTime := time.Now()
	randBytes := common.RandomBytes(28)
	w := common.NewWriter()
	w.PutUint32(uint32(randTime.Unix()))
	w.PutBytes(randBytes)

	hs := New(Type_ClientHello)
	hs.ClientHello.Init(w.Bytes(), nil)
	hsbytes := hs.Bytes()

	handshake, err := ParseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientHello, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_ClientHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x2a))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x2a))

	c.Assert(handshake.ClientHello.version, Equals, common.DtlsVersion12)
	c.Assert(handshake.ClientHello.randomTime, Equals, uint32(randTime.Unix()))
	c.Assert(hex.EncodeToString(handshake.ClientHello.randomBytes), Equals, hex.EncodeToString(w.Bytes()))
	c.Assert(hex.EncodeToString(handshake.ClientHello.sessionId), Equals, "")
	c.Assert(hex.EncodeToString(handshake.ClientHello.cookie), Equals, "")
	c.Assert(handshake.ClientHello.cipherSuites[0], Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
}

func (s *HandshakeSuite) TestHelloVerifyRequestDecode(c *C) {
	hb, _ := hex.DecodeString("030000230000000000000023fefd20d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
	handshake, err := ParseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.HelloVerifyRequest, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_HelloVerifyRequest)
	c.Assert(handshake.Header.Length, Equals, uint32(0x23))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x23))

	c.Assert(handshake.HelloVerifyRequest.version, Equals, common.DtlsVersion12)
	c.Assert(hex.EncodeToString(handshake.HelloVerifyRequest.cookie), Equals, "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
}

func (s *HandshakeSuite) TestHelloVerifyRequestEncode(c *C) {

	cookie := common.RandomBytes(32)

	hs := New(Type_HelloVerifyRequest)
	hs.HelloVerifyRequest.Init(cookie)
	hsbytes := hs.Bytes()

	handshake, err := ParseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.HelloVerifyRequest, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_HelloVerifyRequest)
	c.Assert(handshake.Header.Length, Equals, uint32(0x23))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x23))

	c.Assert(handshake.HelloVerifyRequest.version, Equals, common.DtlsVersion12)
	c.Assert(handshake.HelloVerifyRequest.cookieLen, Equals, uint8(32))
	c.Assert(hex.EncodeToString(handshake.HelloVerifyRequest.cookie), Equals, hex.EncodeToString(cookie))
}

func (s *HandshakeSuite) TestServerHelloDecode(c *C) {
	hb, _ := hex.DecodeString("020000460001000000000046fefd58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e892058218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85c0a800")
	handshake, err := ParseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerHello, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_ServerHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x46))
	c.Assert(handshake.Header.Sequence, Equals, uint16(1))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x46))

	c.Assert(handshake.ServerHello.version, Equals, common.DtlsVersion12)
	c.Assert(handshake.ServerHello.randomTime, Equals, uint32(0x58218d54))
	c.Assert(hex.EncodeToString(handshake.ServerHello.randomBytes), Equals, "58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e89")
	c.Assert(hex.EncodeToString(handshake.ServerHello.sessionId), Equals, "58218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85")
	c.Assert(handshake.ServerHello.cipherSuite, Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	c.Assert(handshake.ServerHello.compressionMethod, Equals, CompressionMethod_Null)
}

func (s *HandshakeSuite) TestServerHelloEncode(c *C) {

	randTime := time.Now()
	randBytes := common.RandomBytes(28)
	w := common.NewWriter()
	w.PutUint32(uint32(randTime.Unix()))
	w.PutBytes(randBytes)

	sessionId := common.RandomBytes(32)

	hs := New(Type_ServerHello)
	hs.ServerHello.Init(w.Bytes(), sessionId)
	hsbytes := hs.Bytes()

	handshake, err := ParseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerHello, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_ServerHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x46))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x46))

	c.Assert(handshake.ServerHello.version, Equals, common.DtlsVersion12)
	c.Assert(handshake.ServerHello.randomTime, Equals, uint32(randTime.Unix()))
	c.Assert(hex.EncodeToString(handshake.ServerHello.randomBytes), Equals, hex.EncodeToString(w.Bytes()))
	c.Assert(hex.EncodeToString(handshake.ServerHello.sessionId), Equals, hex.EncodeToString(sessionId))
	c.Assert(handshake.ServerHello.cipherSuite, Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
}

func (s *HandshakeSuite) TestServerHelloDoneDecode(c *C) {
	hb, _ := hex.DecodeString("0e0000000002000000000000")
	handshake, err := ParseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerHelloDone, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_ServerHelloDone)
	c.Assert(handshake.Header.Length, Equals, uint32(0))
	c.Assert(handshake.Header.Sequence, Equals, uint16(2))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0))
}

func (s *HandshakeSuite) TestServerHelloDoneEncode(c *C) {

	hs := New(Type_ServerHelloDone)
	hs.ServerHelloDone.Init()
	hsbytes := hs.Bytes()

	handshake, err := ParseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerHelloDone, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_ServerHelloDone)
	c.Assert(handshake.Header.Length, Equals, uint32(0))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0))
}

func (s *HandshakeSuite) TestClientKeyExchangeDecode(c *C) {
	hb, _ := hex.DecodeString("1000000a000200000000000a00084964656e74697479")
	handshake, err := ParseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientKeyExchange, NotNil)
}

func (s *HandshakeSuite) TestClientKeyExchangeEncode(c *C) {

	identity := common.RandomBytes(20)

	hs := New(Type_ClientKeyExchange)
	hs.ClientKeyExchange.Init(identity)
	hsbytes := hs.Bytes()

	handshake, err := ParseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientKeyExchange, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, Type_ClientKeyExchange)
	c.Assert(handshake.Header.Length, Equals, uint32(0x16))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x16))

	c.Assert(hex.EncodeToString(handshake.ClientKeyExchange.identity), Equals, hex.EncodeToString(identity))
}
