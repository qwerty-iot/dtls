package dtls

import (
	"encoding/hex"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func HandshakeTest(t *testing.T) { TestingT(t) }

var _ = Suite(&HandshakeSuite{})

type HandshakeSuite struct{}

func (s *HandshakeSuite) SetUpSuite(c *C) {
}

func (s *HandshakeSuite) TestTypeToString(c *C) {
	c.Assert(typeToString(handshakeType_ClientHello), Equals, "ClientHello(1)")
	c.Assert(typeToString(handshakeType_ServerHello), Equals, "ServerHello(2)")
	c.Assert(typeToString(handshakeType_HelloVerifyRequest), Equals, "HelloVerifyRequest(3)")
	c.Assert(typeToString(handshakeType_ServerKeyExchange), Equals, "ServerKeyExchange(12)")
	c.Assert(typeToString(handshakeType_ServerHelloDone), Equals, "ServerHelloDone(14)")
	c.Assert(typeToString(handshakeType_ClientKeyExchange), Equals, "ClientKeyExchange(16)")
	c.Assert(typeToString(handshakeType_Finished), Equals, "Finished(20)")
	c.Assert(typeToString(handshakeType(40)), Equals, "Unknown(40)")
}

func (s *HandshakeSuite) TestCipherSuiteToString(c *C) {
	c.Assert(cipherSuiteToString(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8), Equals, "TLS_PSK_WITH_AES_128_CCM_8(0xC0A8)")
	c.Assert(cipherSuiteToString(CipherSuite(0x1234)), Equals, "Unknown(0x1234)")
}

func (s *HandshakeSuite) TestClientHelloDecode(c *C) {
	hb, _ := hex.DecodeString("0100002a000000000000002afefd00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db600000002c0a80100")
	handshake, err := parseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientHello, NotNil)

	handshake.Print()

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ClientHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x2a))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x2a))

	c.Assert(handshake.ClientHello.version, Equals, DtlsVersion12)
	c.Assert(handshake.ClientHello.randomTime, Equals, uint32(1))
	c.Assert(hex.EncodeToString(handshake.ClientHello.randomBytes), Equals, "00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db6")
	c.Assert(hex.EncodeToString(handshake.ClientHello.sessionId), Equals, "")
	c.Assert(hex.EncodeToString(handshake.ClientHello.cookie), Equals, "")
	c.Assert(handshake.ClientHello.cipherSuites[0], Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	c.Assert(handshake.ClientHello.GetCookie(), IsNil)

	hb, _ = hex.DecodeString("0100004a000100000000004afefd00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db60020d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d80002c0a80100")
	handshake, err = parseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientHello, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ClientHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x4a))
	c.Assert(handshake.Header.Sequence, Equals, uint16(1))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x4a))

	c.Assert(handshake.ClientHello.version, Equals, DtlsVersion12)
	c.Assert(handshake.ClientHello.randomTime, Equals, uint32(1))
	c.Assert(hex.EncodeToString(handshake.ClientHello.randomBytes), Equals, "00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db6")
	c.Assert(hex.EncodeToString(handshake.ClientHello.sessionId), Equals, "")
	c.Assert(hex.EncodeToString(handshake.ClientHello.cookie), Equals, "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
	c.Assert(handshake.ClientHello.cipherSuites[0], Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	c.Assert(hex.EncodeToString(handshake.ClientHello.GetCookie()), Equals, "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
	randTime, randBytes := handshake.ClientHello.GetRandom()
	c.Assert(randTime, Equals, time.Unix(1, 0))
	c.Assert(hex.EncodeToString(randBytes), Equals, "00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db6")

}

func (s *HandshakeSuite) TestClientHelloEncode(c *C) {

	randTime := time.Now()
	randBytes := randomBytes(28)
	w := newByteWriter()
	w.PutUint32(uint32(randTime.Unix()))
	w.PutBytes(randBytes)
	cookie := randomBytes(16)

	hs := newHandshake(handshakeType_ClientHello)
	hs.ClientHello.Init(nil, w.Bytes(), cookie, []CipherSuite{CipherSuite_TLS_PSK_WITH_AES_128_CCM_8}, []CompressionMethod{CompressionMethod_Null})
	hs.ClientHello.sessionId = randomBytes(24)
	hs.ClientHello.sessionIdLen = 24
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientHello, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ClientHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x52))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x52))

	c.Assert(handshake.ClientHello.version, Equals, DtlsVersion12)
	c.Assert(handshake.ClientHello.randomTime, Equals, uint32(randTime.Unix()))
	c.Assert(hex.EncodeToString(handshake.ClientHello.randomBytes), Equals, hex.EncodeToString(w.Bytes()))
	c.Assert(hex.EncodeToString(handshake.ClientHello.sessionId), Equals, hex.EncodeToString(hs.ClientHello.sessionId))
	c.Assert(hex.EncodeToString(handshake.ClientHello.cookie), Equals, hex.EncodeToString(cookie))
	c.Assert(handshake.ClientHello.cipherSuites[0], Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	c.Assert(handshake.ClientHello.GetCipherSuites(), DeepEquals, []CipherSuite{CipherSuite_TLS_PSK_WITH_AES_128_CCM_8})
	c.Assert(handshake.ClientHello.GetCompressionMethods(), DeepEquals, []CompressionMethod{CompressionMethod_Null})
}

func (s *HandshakeSuite) TestHelloVerifyRequestDecode(c *C) {
	hb, _ := hex.DecodeString("030000230000000000000023fefd20d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
	handshake, err := parseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.HelloVerifyRequest, NotNil)

	handshake.Print()

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_HelloVerifyRequest)
	c.Assert(handshake.Header.Length, Equals, uint32(0x23))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x23))

	c.Assert(handshake.HelloVerifyRequest.version, Equals, DtlsVersion12)
	c.Assert(hex.EncodeToString(handshake.HelloVerifyRequest.cookie), Equals, "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
	c.Assert(hex.EncodeToString(handshake.HelloVerifyRequest.GetCookie()), Equals, "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
}

func (s *HandshakeSuite) TestHelloVerifyRequestEncode(c *C) {

	cookie := randomBytes(32)

	hs := newHandshake(handshakeType_HelloVerifyRequest)
	hs.HelloVerifyRequest.Init(cookie)
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.HelloVerifyRequest, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_HelloVerifyRequest)
	c.Assert(handshake.Header.Length, Equals, uint32(0x23))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x23))

	c.Assert(handshake.HelloVerifyRequest.version, Equals, DtlsVersion12)
	c.Assert(handshake.HelloVerifyRequest.cookieLen, Equals, uint8(32))
	c.Assert(hex.EncodeToString(handshake.HelloVerifyRequest.cookie), Equals, hex.EncodeToString(cookie))
}

func (s *HandshakeSuite) TestServerHelloDecode(c *C) {
	hb, _ := hex.DecodeString("020000460001000000000046fefd58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e892058218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85c0a800")
	handshake, err := parseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerHello, NotNil)

	handshake.Print()

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ServerHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x46))
	c.Assert(handshake.Header.Sequence, Equals, uint16(1))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x46))

	c.Assert(handshake.ServerHello.version, Equals, DtlsVersion12)
	c.Assert(handshake.ServerHello.randomTime, Equals, uint32(0x58218d54))
	c.Assert(hex.EncodeToString(handshake.ServerHello.randomBytes), Equals, "58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e89")
	c.Assert(hex.EncodeToString(handshake.ServerHello.sessionId), Equals, "58218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85")
	c.Assert(handshake.ServerHello.cipherSuite, Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	c.Assert(handshake.ServerHello.compressionMethod, Equals, CompressionMethod_Null)
	randTime, randBytes := handshake.ServerHello.GetRandom()
	c.Assert(randTime, Equals, time.Unix(0x58218d54, 0))
	c.Assert(hex.EncodeToString(randBytes), Equals, "58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e89")
	c.Assert(hex.EncodeToString(handshake.ServerHello.GetSessionId()), Equals, "58218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85")
}

func (s *HandshakeSuite) TestServerHelloEncode(c *C) {

	randTime := time.Now()
	randBytes := randomBytes(28)
	w := newByteWriter()
	w.PutUint32(uint32(randTime.Unix()))
	w.PutBytes(randBytes)

	sessionId := randomBytes(32)

	hs := newHandshake(handshakeType_ServerHello)
	hs.ServerHello.Init(w.Bytes(), sessionId)
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerHello, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ServerHello)
	c.Assert(handshake.Header.Length, Equals, uint32(0x46))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x46))

	c.Assert(handshake.ServerHello.version, Equals, DtlsVersion12)
	c.Assert(handshake.ServerHello.randomTime, Equals, uint32(randTime.Unix()))
	c.Assert(hex.EncodeToString(handshake.ServerHello.randomBytes), Equals, hex.EncodeToString(w.Bytes()))
	c.Assert(hex.EncodeToString(handshake.ServerHello.sessionId), Equals, hex.EncodeToString(sessionId))
	c.Assert(handshake.ServerHello.cipherSuite, Equals, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
}

func (s *HandshakeSuite) TestServerHelloDoneDecode(c *C) {
	hb, _ := hex.DecodeString("0e0000000002000000000000")
	handshake, err := parseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerHelloDone, NotNil)

	handshake.Print()

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ServerHelloDone)
	c.Assert(handshake.Header.Length, Equals, uint32(0))
	c.Assert(handshake.Header.Sequence, Equals, uint16(2))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0))
}

func (s *HandshakeSuite) TestServerHelloDoneEncode(c *C) {

	hs := newHandshake(handshakeType_ServerHelloDone)
	hs.ServerHelloDone.Init()
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerHelloDone, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ServerHelloDone)
	c.Assert(handshake.Header.Length, Equals, uint32(0))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0))
}

func (s *HandshakeSuite) TestClientKeyExchangeDecode(c *C) {
	hb, _ := hex.DecodeString("1000000a000200000000000a00084964656e74697479")
	handshake, err := parseHandshake(hb)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientKeyExchange, NotNil)
	c.Assert(string(handshake.ClientKeyExchange.GetIdentity()), Equals, "Identity")

	handshake.Print()
}

func (s *HandshakeSuite) TestClientKeyExchangeEncode(c *C) {

	identity := randomBytes(20)

	hs := newHandshake(handshakeType_ClientKeyExchange)
	hs.ClientKeyExchange.Init(identity)
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ClientKeyExchange, NotNil)

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ClientKeyExchange)
	c.Assert(handshake.Header.Length, Equals, uint32(0x16))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x16))

	c.Assert(hex.EncodeToString(handshake.ClientKeyExchange.identity), Equals, hex.EncodeToString(identity))
}

func (s *HandshakeSuite) TestServerKeyExchangeEncode(c *C) {

	identity := randomBytes(20)

	hs := newHandshake(handshakeType_ServerKeyExchange)
	hs.ServerKeyExchange.Init(identity)
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.ServerKeyExchange, NotNil)

	hs.Print()

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_ServerKeyExchange)
	c.Assert(handshake.Header.Length, Equals, uint32(0x16))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x16))

	c.Assert(hex.EncodeToString(handshake.ServerKeyExchange.identity), Equals, hex.EncodeToString(identity))
	c.Assert(hex.EncodeToString(handshake.ServerKeyExchange.GetIdentity()), Equals, hex.EncodeToString(identity))
}

func (s *HandshakeSuite) TestFinishedEncode(c *C) {

	masterSecret, _ := hex.DecodeString("611FB682880654FF7D61BA0072FE8AD628462670E9277318DE1A22AECD52F551AEE1DE3D12A84F82A959B098D46B71A1")
	hash, _ := hex.DecodeString("8A9B2FAC572122376390E4952FD3780246380E89DDCBE1D2FF4290D0039D6557")
	digest, _ := hex.DecodeString("31749FF769AA0444EE8F02B2")

	hs := newHandshake(handshakeType_Finished)
	hs.Finished.Init(masterSecret, hash, "client")
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.Finished, NotNil)

	hs.Print()

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType_Finished)
	c.Assert(handshake.Header.Length, Equals, uint32(0x0c))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x0c))

	c.Assert(hex.EncodeToString(handshake.Finished.data), Equals, hex.EncodeToString(digest))
	c.Assert(handshake.Finished.Match(masterSecret, hash, "client"), Equals, true)
	c.Assert(handshake.Finished.Match(masterSecret, hash, "server"), Equals, false)
}

func (s *HandshakeSuite) TestUnknownEncode(c *C) {

	hs := newHandshake(handshakeType(0xF1))
	hs.Unknown.Init()
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	c.Assert(err, IsNil)
	c.Assert(handshake, NotNil)
	c.Assert(handshake.Unknown, NotNil)

	hs.Print()

	c.Assert(handshake.Header.HandshakeType, Equals, handshakeType(0xF1))
	c.Assert(handshake.Header.Length, Equals, uint32(0x00))
	c.Assert(handshake.Header.Sequence, Equals, uint16(0))
	c.Assert(handshake.Header.FragmentOfs, Equals, uint32(0))
	c.Assert(handshake.Header.FragmentLen, Equals, uint32(0x00))

}
