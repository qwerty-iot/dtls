package dtls

import (
	"fmt"
)

type clientKeyExchange struct {
	identityLen uint16
	identity    []byte
}

func (h *clientKeyExchange) Init(identity []byte) {
	h.identity = identity
	h.identityLen = uint16(len(h.identity))
}

func (h *clientKeyExchange) Parse(rdr *byteReader) error {

	h.identityLen = rdr.GetUint16()
	if h.identityLen > 0 {
		h.identity = rdr.GetBytes(int(h.identityLen))
	}
	return nil
}

func (h *clientKeyExchange) Bytes() []byte {
	w := newByteWriter()
	w.PutUint16(h.identityLen)
	if h.identityLen > 0 {
		w.PutBytes(h.identity)
	}
	return w.Bytes()
}

func (h *clientKeyExchange) Print() string {
	return fmt.Sprintf("identity[%s][%d]", h.identity, h.identityLen)
}

func (h *clientKeyExchange) GetIdentity() []byte {
	return h.identity
}
