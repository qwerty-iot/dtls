package dtls

import (
	"fmt"
)

type helloVerifyRequest struct {
	version   uint16
	cookieLen uint8
	cookie    []byte
}

func (h *helloVerifyRequest) Init(cookie []byte) {
	h.version = DtlsVersion12
	h.cookie = cookie
	h.cookieLen = uint8(len(h.cookie))
}

func (h *helloVerifyRequest) Parse(rdr *byteReader) error {
	h.version = rdr.GetUint16()
	h.cookieLen = rdr.GetUint8()
	if h.cookieLen > 0 {
		h.cookie = rdr.GetBytes(int(h.cookieLen))
	}
	return nil
}

func (h *helloVerifyRequest) Bytes() []byte {
	w := newByteWriter()
	w.PutUint16(h.version)
	w.PutUint8(h.cookieLen)
	w.PutBytes(h.cookie)
	return w.Bytes()
}

func (h *helloVerifyRequest) Print() string {
	return fmt.Sprintf("version[%X] cookie[%X][%d]", h.version, h.cookie, h.cookieLen)
}

func (h *helloVerifyRequest) GetCookie() []byte {
	return h.cookie
}
