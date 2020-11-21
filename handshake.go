package dtls

import (
	"bytes"
	"fmt"
)

type handshakeType uint8

const (
	handshakeType_ClientHello        handshakeType = 1
	handshakeType_ServerHello        handshakeType = 2
	handshakeType_HelloVerifyRequest handshakeType = 3
	handshakeType_ServerKeyExchange  handshakeType = 12
	handshakeType_ServerHelloDone    handshakeType = 14
	handshakeType_ClientKeyExchange  handshakeType = 16
	handshakeType_Finished           handshakeType = 20
)

type CompressionMethod uint8

const (
	CompressionMethod_Null CompressionMethod = 0
)

type payload interface {
	Parse(rdr *byteReader) error
	Bytes() []byte
	Print() string
	//	Init()
}

type handshake struct {
	Header             header
	Payload            payload
	ClientHello        *clientHello
	ServerHello        *serverHello
	HelloVerifyRequest *helloVerifyRequest
	ServerKeyExchange  *serverKeyExchange
	ServerHelloDone    *serverHelloDone
	ClientKeyExchange  *clientKeyExchange
	Finished           *finished
	Unknown            *unknown
}

func (h *handshake) Print() string {
	return fmt.Sprintf("%s ||| %s", h.Header.Print(), h.Payload.Print())
}

func (h *handshake) Bytes() []byte {
	buf := new(bytes.Buffer)
	payload := h.Payload.Bytes()
	h.Header.SetLength(len(payload))
	buf.Write(h.Header.Bytes())
	buf.Write(payload)
	return buf.Bytes()
}

func newHandshake(handshakeType handshakeType) *handshake {
	hs := &handshake{}
	hs.Header.HandshakeType = handshakeType

	switch handshakeType {
	case handshakeType_ClientHello:
		hs.ClientHello = &clientHello{}
		hs.Payload = hs.ClientHello
	case handshakeType_HelloVerifyRequest:
		hs.HelloVerifyRequest = &helloVerifyRequest{}
		hs.Payload = hs.HelloVerifyRequest
	case handshakeType_ServerHello:
		hs.ServerHello = &serverHello{}
		hs.Payload = hs.ServerHello
	case handshakeType_ServerKeyExchange:
		hs.ServerKeyExchange = &serverKeyExchange{}
		hs.Payload = hs.ServerKeyExchange
	case handshakeType_ServerHelloDone:
		hs.ServerHelloDone = &serverHelloDone{}
		hs.Payload = hs.ServerHelloDone
	case handshakeType_ClientKeyExchange:
		hs.ClientKeyExchange = &clientKeyExchange{}
		hs.Payload = hs.ClientKeyExchange
	case handshakeType_Finished:
		hs.Finished = &finished{}
		hs.Payload = hs.Finished
	default:
		hs.Unknown = &unknown{}
		hs.Payload = hs.Unknown
	}

	return hs
}

func parseHandshake(raw []byte) (*handshake, error) {

	rdr := newByteReader(raw)

	header := header{}
	header.Parse(rdr)

	h := newHandshake(header.HandshakeType)
	h.Payload.Parse(rdr)
	h.Header = header

	return h, nil
}

func typeToString(t handshakeType) string {
	switch t {
	case handshakeType_ClientHello:
		return "ClientHello(1)"
	case handshakeType_ServerHello:
		return "ServerHello(2)"
	case handshakeType_HelloVerifyRequest:
		return "HelloVerifyRequest(3)"
	case handshakeType_ServerKeyExchange:
		return "ServerKeyExchange(12)"
	case handshakeType_ServerHelloDone:
		return "ServerHelloDone(14)"
	case handshakeType_ClientKeyExchange:
		return "ClientKeyExchange(16)"
	case handshakeType_Finished:
		return "Finished(20)"
	}
	return fmt.Sprintf("Unknown(%d)", int(t))
}
