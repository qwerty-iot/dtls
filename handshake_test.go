package dtls

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

func TestHandshakeSuite(t *testing.T) {
	suite.Run(t, new(HandshakeSuite))
}

type HandshakeSuite struct {
	suite.Suite
}

func (s *HandshakeSuite) Log(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}

func (s *HandshakeSuite) TestTypeToString() {
	assert.Equal(s.T(), "ClientHello(1)", typeToString(handshakeType_ClientHello))
	assert.Equal(s.T(), "ServerHello(2)", typeToString(handshakeType_ServerHello))
	assert.Equal(s.T(), "HelloVerifyRequest(3)", typeToString(handshakeType_HelloVerifyRequest))
	assert.Equal(s.T(), "ServerKeyExchange(12)", typeToString(handshakeType_ServerKeyExchange))
	assert.Equal(s.T(), "ServerHelloDone(14)", typeToString(handshakeType_ServerHelloDone))
	assert.Equal(s.T(), "ClientKeyExchange(16)", typeToString(handshakeType_ClientKeyExchange))
	assert.Equal(s.T(), "Finished(20)", typeToString(handshakeType_Finished))
	assert.Equal(s.T(), "Unknown(40)", typeToString(handshakeType(40)))
}

func (s *HandshakeSuite) TestCipherSuiteToString() {
	assert.Equal(s.T(), "TLS_PSK_WITH_AES_128_CCM_8(0xC0A8)", cipherSuiteToString(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8))
	assert.Equal(s.T(), "Unknown(0x1234)", cipherSuiteToString(CipherSuite(0x1234)))
}

func (s *HandshakeSuite) TestClientHelloDecode() {
	hb, _ := hex.DecodeString("0100002a000000000000002afefd00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db600000002c0a80100")
	handshake, err := parseHandshake(hb)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ClientHello)

	handshake.Print()

	assert.Equal(s.T(), handshakeType_ClientHello, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x2a), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x2a), handshake.Header.FragmentLen)

	assert.Equal(s.T(), DtlsVersion12, handshake.ClientHello.version)
	assert.Equal(s.T(), uint32(1), handshake.ClientHello.randomTime)
	assert.Equal(s.T(), "00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db6", hex.EncodeToString(handshake.ClientHello.randomBytes))
	assert.Equal(s.T(), "", hex.EncodeToString(handshake.ClientHello.sessionId))
	assert.Equal(s.T(), "", hex.EncodeToString(handshake.ClientHello.cookie))
	assert.Equal(s.T(), CipherSuite_TLS_PSK_WITH_AES_128_CCM_8, handshake.ClientHello.cipherSuites[0])
	assert.Nil(s.T(), handshake.ClientHello.GetCookie())

	hb, _ = hex.DecodeString("0100004a000100000000004afefd00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db60020d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d80002c0a80100")
	handshake, err = parseHandshake(hb)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ClientHello)

	assert.Equal(s.T(), handshakeType_ClientHello, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x4a), handshake.Header.Length)
	assert.Equal(s.T(), uint16(1), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x4a), handshake.Header.FragmentLen)

	assert.Equal(s.T(), DtlsVersion12, handshake.ClientHello.version)
	assert.Equal(s.T(), uint32(1), handshake.ClientHello.randomTime)
	assert.Equal(s.T(), "00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db6", hex.EncodeToString(handshake.ClientHello.randomBytes))
	assert.Equal(s.T(), "", hex.EncodeToString(handshake.ClientHello.sessionId))
	assert.Equal(s.T(), "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8", hex.EncodeToString(handshake.ClientHello.cookie))
	assert.Equal(s.T(), CipherSuite_TLS_PSK_WITH_AES_128_CCM_8, handshake.ClientHello.cipherSuites[0])
	assert.Equal(s.T(), "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8", hex.EncodeToString(handshake.ClientHello.GetCookie()))
	randTime, randBytes := handshake.ClientHello.GetRandom()
	assert.Equal(s.T(), time.Unix(1, 0), randTime)
	assert.Equal(s.T(), "00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db6", hex.EncodeToString(randBytes))

}

func (s *HandshakeSuite) TestClientHelloEncode() {

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

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ClientHello)

	assert.Equal(s.T(), handshakeType_ClientHello, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x52), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x52), handshake.Header.FragmentLen)

	assert.Equal(s.T(), DtlsVersion12, handshake.ClientHello.version)
	assert.Equal(s.T(), uint32(randTime.Unix()), handshake.ClientHello.randomTime)
	assert.Equal(s.T(), hex.EncodeToString(w.Bytes()), hex.EncodeToString(handshake.ClientHello.randomBytes))
	assert.Equal(s.T(), hex.EncodeToString(hs.ClientHello.sessionId), hex.EncodeToString(handshake.ClientHello.sessionId))
	assert.Equal(s.T(), hex.EncodeToString(cookie), hex.EncodeToString(handshake.ClientHello.cookie))
	assert.Equal(s.T(), CipherSuite_TLS_PSK_WITH_AES_128_CCM_8, handshake.ClientHello.cipherSuites[0])
	assert.Equal(s.T(), []CipherSuite{CipherSuite_TLS_PSK_WITH_AES_128_CCM_8}, handshake.ClientHello.GetCipherSuites())
	assert.Equal(s.T(), []CompressionMethod{CompressionMethod_Null}, handshake.ClientHello.GetCompressionMethods())
}

func (s *HandshakeSuite) TestHelloVerifyRequestDecode() {
	hb, _ := hex.DecodeString("030000230000000000000023fefd20d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8")
	handshake, err := parseHandshake(hb)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.HelloVerifyRequest)

	handshake.Print()

	assert.Equal(s.T(), handshakeType_HelloVerifyRequest, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x23), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x23), handshake.Header.FragmentLen)

	assert.Equal(s.T(), DtlsVersion12, handshake.HelloVerifyRequest.version)
	assert.Equal(s.T(), "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8", hex.EncodeToString(handshake.HelloVerifyRequest.cookie))
	assert.Equal(s.T(), "d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d8", hex.EncodeToString(handshake.HelloVerifyRequest.GetCookie()))
}

func (s *HandshakeSuite) TestHelloVerifyRequestEncode() {

	cookie := randomBytes(32)

	hs := newHandshake(handshakeType_HelloVerifyRequest)
	hs.HelloVerifyRequest.Init(cookie)
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.HelloVerifyRequest)

	assert.Equal(s.T(), handshake.Header.HandshakeType, handshakeType_HelloVerifyRequest)
	assert.Equal(s.T(), uint32(0x23), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x23), handshake.Header.FragmentLen)

	assert.Equal(s.T(), DtlsVersion12, handshake.HelloVerifyRequest.version)
	assert.Equal(s.T(), uint8(32), handshake.HelloVerifyRequest.cookieLen)
	assert.Equal(s.T(), hex.EncodeToString(cookie), hex.EncodeToString(handshake.HelloVerifyRequest.cookie))
}

func (s *HandshakeSuite) TestServerHelloDecode() {
	hb, _ := hex.DecodeString("020000460001000000000046fefd58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e892058218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85c0a800")
	handshake, err := parseHandshake(hb)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ServerHello)

	handshake.Print()

	assert.Equal(s.T(), handshakeType_ServerHello, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x46), handshake.Header.Length)
	assert.Equal(s.T(), uint16(1), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x46), handshake.Header.FragmentLen)

	assert.Equal(s.T(), DtlsVersion12, handshake.ServerHello.version)
	assert.Equal(s.T(), uint32(0x58218d54), handshake.ServerHello.randomTime)
	assert.Equal(s.T(), "58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e89", hex.EncodeToString(handshake.ServerHello.randomBytes))
	assert.Equal(s.T(), "58218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85", hex.EncodeToString(handshake.ServerHello.sessionId))
	assert.Equal(s.T(), CipherSuite_TLS_PSK_WITH_AES_128_CCM_8, handshake.ServerHello.cipherSuite)
	assert.Equal(s.T(), CompressionMethod_Null, handshake.ServerHello.compressionMethod)
	randTime, randBytes := handshake.ServerHello.GetRandom()
	assert.Equal(s.T(), time.Unix(0x58218d54, 0), randTime)
	assert.Equal(s.T(), "58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e89", hex.EncodeToString(randBytes))
	assert.Equal(s.T(), "58218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85", hex.EncodeToString(handshake.ServerHello.GetSessionId()))
}

func (s *HandshakeSuite) TestServerHelloEncode() {

	randTime := time.Now()
	randBytes := randomBytes(28)
	w := newByteWriter()
	w.PutUint32(uint32(randTime.Unix()))
	w.PutBytes(randBytes)

	sessionId := randomBytes(32)

	hs := newHandshake(handshakeType_ServerHello)
	hs.ServerHello.Init(w.Bytes(), sessionId, CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ServerHello)

	assert.Equal(s.T(), handshakeType_ServerHello, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x46), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x46), handshake.Header.FragmentLen)

	assert.Equal(s.T(), DtlsVersion12, handshake.ServerHello.version)
	assert.Equal(s.T(), uint32(randTime.Unix()), handshake.ServerHello.randomTime)
	assert.Equal(s.T(), hex.EncodeToString(w.Bytes()), hex.EncodeToString(handshake.ServerHello.randomBytes))
	assert.Equal(s.T(), hex.EncodeToString(sessionId), hex.EncodeToString(handshake.ServerHello.sessionId))
	assert.Equal(s.T(), CipherSuite_TLS_PSK_WITH_AES_128_CCM_8, handshake.ServerHello.cipherSuite)
}

func (s *HandshakeSuite) TestServerHelloDoneDecode() {
	hb, _ := hex.DecodeString("0e0000000002000000000000")
	handshake, err := parseHandshake(hb)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ServerHelloDone)

	handshake.Print()

	assert.Equal(s.T(), handshakeType_ServerHelloDone, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0), handshake.Header.Length)
	assert.Equal(s.T(), uint16(2), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentLen)
}

func (s *HandshakeSuite) TestServerHelloDoneEncode() {

	hs := newHandshake(handshakeType_ServerHelloDone)
	hs.ServerHelloDone.Init()
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ServerHelloDone)

	assert.Equal(s.T(), handshake.Header.HandshakeType, handshakeType_ServerHelloDone)
	assert.Equal(s.T(), handshake.Header.Length, uint32(0))
	assert.Equal(s.T(), handshake.Header.Sequence, uint16(0))
	assert.Equal(s.T(), handshake.Header.FragmentOfs, uint32(0))
	assert.Equal(s.T(), handshake.Header.FragmentLen, uint32(0))
}

func (s *HandshakeSuite) TestClientKeyExchangeDecode() {
	hb, _ := hex.DecodeString("1000000a000200000000000a00084964656e74697479")
	handshake, err := parseHandshake(hb)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ClientKeyExchange)
	assert.Equal(s.T(), "Identity", string(handshake.ClientKeyExchange.GetIdentity()))

	handshake.Print()
}

func (s *HandshakeSuite) TestClientKeyExchangeEncode() {

	identity := randomBytes(20)

	hs := newHandshake(handshakeType_ClientKeyExchange)
	hs.ClientKeyExchange.Init(identity)
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ClientKeyExchange)

	assert.Equal(s.T(), handshakeType_ClientKeyExchange, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x16), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x16), handshake.Header.FragmentLen)

	assert.Equal(s.T(), hex.EncodeToString(identity), hex.EncodeToString(handshake.ClientKeyExchange.identity))
}

func (s *HandshakeSuite) TestServerKeyExchangeEncode() {

	identity := randomBytes(20)

	hs := newHandshake(handshakeType_ServerKeyExchange)
	hs.ServerKeyExchange.Init(identity)
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.ServerKeyExchange)

	hs.Print()

	assert.Equal(s.T(), handshakeType_ServerKeyExchange, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x16), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x16), handshake.Header.FragmentLen)

	assert.Equal(s.T(), hex.EncodeToString(identity), hex.EncodeToString(handshake.ServerKeyExchange.identity))
	assert.Equal(s.T(), hex.EncodeToString(identity), hex.EncodeToString(handshake.ServerKeyExchange.GetIdentity()))
}

func (s *HandshakeSuite) TestFinishedEncode() {

	masterSecret, _ := hex.DecodeString("611FB682880654FF7D61BA0072FE8AD628462670E9277318DE1A22AECD52F551AEE1DE3D12A84F82A959B098D46B71A1")
	hash, _ := hex.DecodeString("8A9B2FAC572122376390E4952FD3780246380E89DDCBE1D2FF4290D0039D6557")
	digest, _ := hex.DecodeString("31749FF769AA0444EE8F02B2")

	hs := newHandshake(handshakeType_Finished)
	hs.Finished.Init(masterSecret, hash, "client")
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.Finished)

	hs.Print()

	assert.Equal(s.T(), handshakeType_Finished, handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x0c), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x0c), handshake.Header.FragmentLen)

	assert.Equal(s.T(), hex.EncodeToString(digest), hex.EncodeToString(handshake.Finished.data))
	assert.Equal(s.T(), true, handshake.Finished.Match(masterSecret, hash, "client"))
	assert.Equal(s.T(), false, handshake.Finished.Match(masterSecret, hash, "server"))
}

func (s *HandshakeSuite) TestUnknownEncode() {

	hs := newHandshake(handshakeType(0xF1))
	hs.Unknown.Init()
	hsbytes := hs.Bytes()

	handshake, err := parseHandshake(hsbytes)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), handshake)
	assert.NotNil(s.T(), handshake.Unknown)

	hs.Print()

	assert.Equal(s.T(), handshakeType(0xF1), handshake.Header.HandshakeType)
	assert.Equal(s.T(), uint32(0x00), handshake.Header.Length)
	assert.Equal(s.T(), uint16(0), handshake.Header.Sequence)
	assert.Equal(s.T(), uint32(0), handshake.Header.FragmentOfs)
	assert.Equal(s.T(), uint32(0x00), handshake.Header.FragmentLen)

}
