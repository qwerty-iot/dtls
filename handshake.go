// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"bytes"
	"errors"
	"fmt"
)

type handshakeType uint8

const (
	handshakeType_ClientHello        handshakeType = 1
	handshakeType_ServerHello        handshakeType = 2
	handshakeType_HelloVerifyRequest handshakeType = 3
	handshakeType_Certificate        handshakeType = 11
	handshakeType_ServerKeyExchange  handshakeType = 12
	handshakeType_CertificateRequest handshakeType = 13
	handshakeType_ServerHelloDone    handshakeType = 14
	handshakeType_CertificateVerify  handshakeType = 15
	handshakeType_ClientKeyExchange  handshakeType = 16
	handshakeType_Finished           handshakeType = 20
)

type CompressionMethod uint8

const (
	CompressionMethod_Null CompressionMethod = 0
)

type payload interface {
	Parse(rdr *byteReader, size int) error
	Bytes() []byte
	Print() string
	//	InitPsk()
}

type handshake struct {
	Header             header
	Payload            payload
	Fragment           []byte
	ClientHello        *clientHello
	ServerHello        *serverHello
	HelloVerifyRequest *helloVerifyRequest
	Certificate        *certificate
	ServerKeyExchange  *serverKeyExchange
	CertificateRequest *certificateRequest
	ServerHelloDone    *serverHelloDone
	CertificateVerify  *certificateVerify
	ClientKeyExchange  *clientKeyExchange
	Finished           *finished
	Unknown            *unknown
}

func (h *handshake) Print() string {
	if h.Payload == nil {
		return fmt.Sprintf("%s ||| nil", h.Header.Print())
	} else {
		return fmt.Sprintf("%s ||| %s", h.Header.Print(), h.Payload.Print())
	}
}

func (h *handshake) Bytes() []byte {
	buf := new(bytes.Buffer)
	payload := h.Payload.Bytes()
	h.Header.SetLength(len(payload))
	buf.Write(h.Header.Bytes())
	buf.Write(payload)
	return buf.Bytes()
}

func (h *handshake) FragmentBytes(startingByte int, maxSize int) []byte {
	buf := new(bytes.Buffer)
	payload := h.Payload.Bytes()
	h.Header.SetLength(len(payload))
	h.Header.FragmentOfs = uint32(startingByte)
	fragmentSize := 0
	if len(payload)-startingByte > maxSize {
		h.Header.FragmentLen = uint32(maxSize)
		fragmentSize = maxSize
	} else {
		h.Header.FragmentLen = uint32(len(payload) - startingByte)
		fragmentSize = len(payload) - startingByte
	}
	buf.Write(h.Header.Bytes())
	buf.Write(payload[startingByte : startingByte+fragmentSize])
	return buf.Bytes()
}

func (h *handshake) IsFragment() bool {
	return len(h.Fragment) != 0
}

func (h *handshake) IsDuplicate() bool {
	return h.Header.duplicate
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
	case handshakeType_Certificate:
		hs.Certificate = &certificate{}
		hs.Payload = hs.Certificate
	case handshakeType_ServerHello:
		hs.ServerHello = &serverHello{}
		hs.Payload = hs.ServerHello
	case handshakeType_ServerKeyExchange:
		hs.ServerKeyExchange = &serverKeyExchange{}
		hs.Payload = hs.ServerKeyExchange
	case handshakeType_CertificateRequest:
		hs.CertificateRequest = &certificateRequest{}
		hs.Payload = hs.CertificateRequest
	case handshakeType_ServerHelloDone:
		hs.ServerHelloDone = &serverHelloDone{}
		hs.Payload = hs.ServerHelloDone
	case handshakeType_CertificateVerify:
		hs.CertificateVerify = &certificateVerify{}
		hs.Payload = hs.CertificateVerify
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

	if header.Length != header.FragmentLen {
		h := &handshake{}
		h.Header = header
		fragmentData := rdr.GetBytes(int(header.FragmentLen))
		h.Fragment = make([]byte, 0, h.Header.Length)
		if h.Header.FragmentLen > 65535 {
			logDebug(nil, nil, "bad handshake fragment length: %d", h.Header.FragmentLen)
			return nil, errors.New("bad handshake fragment length")
		}
		copy(h.Fragment[h.Header.FragmentOfs:h.Header.FragmentOfs+h.Header.FragmentLen], fragmentData)
		return h, nil
	}

	h := newHandshake(header.HandshakeType)
	h.Payload.Parse(rdr, int(header.Length))
	h.Header = header

	return h, nil
}

func parseFragments(header header, raw []byte) (*handshake, error) {
	rdr := newByteReader(raw)
	h := newHandshake(header.HandshakeType)
	h.Payload.Parse(rdr, int(header.Length))
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
	case handshakeType_Certificate:
		return "Certificate(11)"
	case handshakeType_ServerKeyExchange:
		return "ServerKeyExchange(12)"
	case handshakeType_CertificateRequest:
		return "CertificateRequest(13)"
	case handshakeType_ServerHelloDone:
		return "ServerHelloDone(14)"
	case handshakeType_CertificateVerify:
		return "CertificateVerify(15)"
	case handshakeType_ClientKeyExchange:
		return "ClientKeyExchange(16)"
	case handshakeType_Finished:
		return "Finished(20)"
	}
	return fmt.Sprintf("Unknown(%d)", int(t))
}
