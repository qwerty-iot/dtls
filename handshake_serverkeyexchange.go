// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"fmt"
)

type serverKeyExchange struct {
	identityLen uint16
	identity    []byte
}

func (h *serverKeyExchange) Init(identity []byte) {
	h.identity = identity
	h.identityLen = uint16(len(h.identity))
}

func (h *serverKeyExchange) GetIdentity() []byte {
	return h.identity
}

func (h *serverKeyExchange) Parse(rdr *byteReader) error {

	h.identityLen = rdr.GetUint16()
	if h.identityLen > 0 {
		h.identity = rdr.GetBytes(int(h.identityLen))
	}
	return nil
}

func (h *serverKeyExchange) Bytes() []byte {
	w := newByteWriter()
	w.PutUint16(h.identityLen)
	if h.identityLen > 0 {
		w.PutBytes(h.identity)
	}
	return w.Bytes()
}

func (h *serverKeyExchange) Print() string {
	return fmt.Sprintf("identity[%s][%d]", h.identity, h.identityLen)
}
