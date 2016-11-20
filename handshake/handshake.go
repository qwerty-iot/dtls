package handshake

import (
	"bytes"
	"fmt"

	"github.com/bocajim/dtls/common"
)

type HandshakeType uint8

const (
	Type_ClientHello        HandshakeType = 1
	Type_ServerHello        HandshakeType = 2
	Type_HelloVerifyRequest HandshakeType = 3
	Type_ServerKeyExchange  HandshakeType = 12
	Type_ServerHelloDone    HandshakeType = 14
	Type_ClientKeyExchange  HandshakeType = 16
	Type_Finished           HandshakeType = 20
)

type CipherSuite uint16

const (
	CipherSuite_TLS_PSK_WITH_AES_128_CCM_8 CipherSuite = 0xC0A8
)

type CompressionMethod uint8

const (
	CompressionMethod_Null CompressionMethod = 0
)

type Payload interface {
	Parse(rdr *common.Reader) error
	Bytes() []byte
	Print() string
	//	Init()
}

type Handshake struct {
	Header             Header
	Payload            Payload
	ClientHello        *clientHello
	ServerHello        *serverHello
	HelloVerifyRequest *helloVerifyRequest
	ServerKeyExchange  *serverKeyExchange
	ServerHelloDone    *serverHelloDone
	ClientKeyExchange  *clientKeyExchange
	Finished           *finished
	Unknown            *unknown
}

func (h *Handshake) Print() string {
	return fmt.Sprintf("%s ||| %s", h.Header.Print(), h.Payload.Print())
}

func (h *Handshake) Bytes() []byte {
	buf := new(bytes.Buffer)
	payload := h.Payload.Bytes()
	h.Header.SetLength(len(payload))
	buf.Write(h.Header.Bytes())
	buf.Write(payload)
	return buf.Bytes()
}

func New(handshakeType HandshakeType) *Handshake {
	hs := &Handshake{}
	hs.Header.HandshakeType = handshakeType

	switch handshakeType {
	case Type_ClientHello:
		hs.ClientHello = &clientHello{}
		hs.Payload = hs.ClientHello
	case Type_HelloVerifyRequest:
		hs.HelloVerifyRequest = &helloVerifyRequest{}
		hs.Payload = hs.HelloVerifyRequest
	case Type_ServerHello:
		hs.ServerHello = &serverHello{}
		hs.Payload = hs.ServerHello
	case Type_ServerKeyExchange:
		hs.ServerKeyExchange = &serverKeyExchange{}
		hs.Payload = hs.ServerKeyExchange
	case Type_ServerHelloDone:
		hs.ServerHelloDone = &serverHelloDone{}
		hs.Payload = hs.ServerHelloDone
	case Type_ClientKeyExchange:
		hs.ClientKeyExchange = &clientKeyExchange{}
		hs.Payload = hs.ClientKeyExchange
	case Type_Finished:
		hs.Finished = &finished{}
		hs.Payload = hs.Finished
	default:
		hs.Unknown = &unknown{}
		hs.Payload = hs.Unknown
	}

	return hs
}

func ParseHandshake(raw []byte) (*Handshake, error) {

	rdr := common.NewReader(raw)

	header := Header{}
	header.Parse(rdr)

	h := New(header.HandshakeType)
	h.Payload.Parse(rdr)
	h.Header = header

	return h, nil
}

func TypeToString(t HandshakeType) string {
	switch t {
	case Type_ClientHello:
		return "ClientHello(1)"
	case Type_ServerHello:
		return "ServerHello(2)"
	case Type_HelloVerifyRequest:
		return "HelloVerifyRequest(3)"
	case Type_ServerKeyExchange:
		return "ServerKeyExchange(12)"
	case Type_ServerHelloDone:
		return "ServerHelloDone(14)"
	case Type_ClientKeyExchange:
		return "ClientKeyExchange(16)"
	case Type_Finished:
		return "Finished(20)"
	}
	return fmt.Sprintf("Unknown(%d)", int(t))
}

func CipherSuiteToString(c CipherSuite) string {
	switch c {
	case CipherSuite_TLS_PSK_WITH_AES_128_CCM_8:
		return "TLS_PSK_WITH_AES_128_CCM_8(0xC0A8)"
	}
	return fmt.Sprintf("Unknown(0x%X)", c)
}
