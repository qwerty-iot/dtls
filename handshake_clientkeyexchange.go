// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"encoding/binary"
	"fmt"
)

type clientKeyExchange struct {
	identity []byte

	publicKey []byte
}

func (h *clientKeyExchange) InitPsk(identity []byte) {
	h.identity = identity
}

func (h *clientKeyExchange) InitCert(publicKey []byte) {
	h.publicKey = publicKey
}

func (h *clientKeyExchange) Parse(rdr *byteReader, size int) error {

	b0 := rdr.GetUint8()
	if int(b0) == size-1 {
		h.publicKey = rdr.GetBytes(int(b0))
	} else {
		b1 := rdr.GetUint8()
		l := int(binary.BigEndian.Uint16([]byte{b0, b1}))
		if l > 0 {
			h.identity = rdr.GetBytes(l)
		}
	}
	return nil
}

func (h *clientKeyExchange) Bytes() []byte {
	w := newByteWriter()
	if len(h.identity) != 0 {
		w.PutUint16(uint16(len(h.identity)))
		w.PutBytes(h.identity)
	} else {
		w.PutUint8(uint8(len(h.publicKey)))
		w.PutBytes(h.publicKey)
	}
	return w.Bytes()
}

func (h *clientKeyExchange) Print() string {
	if len(h.identity) != 0 {
		return fmt.Sprintf("identity[%s][%d]", h.identity, len(h.identity))
	} else {
		return fmt.Sprintf("publicKey[%X][%d]", h.publicKey, len(h.publicKey))
	}
}

func (h *clientKeyExchange) GetIdentity() []byte {
	return h.identity
}

func (h *clientKeyExchange) GetPublicKey() []byte {
	return h.publicKey
}
