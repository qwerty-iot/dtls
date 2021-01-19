// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type serverKeyExchange struct {
	identity []byte

	curve     eccCurve
	publicKey []byte
	signature []byte
}

func (h *serverKeyExchange) InitPsk(identity []byte) {
	h.identity = identity
}

func (h *serverKeyExchange) InitCert(curve eccCurve, publicKey []byte, signature []byte) {
	h.curve = curve
	h.publicKey = publicKey
	h.signature = signature
}

func (h *serverKeyExchange) GetIdentity() []byte {
	return h.identity
}

func (h *serverKeyExchange) GetCurve() eccCurve {
	return h.curve
}

func (h *serverKeyExchange) GetPublicKey() []byte {
	return h.publicKey
}

func (h *serverKeyExchange) GetSignature() []byte {
	return h.signature
}

func (h *serverKeyExchange) Parse(rdr *byteReader, size int) error {

	b0 := rdr.GetUint8()
	if b0 == 0x03 {
		h.curve = eccCurve(rdr.GetUint16())
		l := int(rdr.GetUint8())
		if l > 0 {
			h.publicKey = rdr.GetBytes(l)
			rdr.GetUint8()
			rdr.GetUint8()
			l = int(rdr.GetUint16())
			h.signature = rdr.GetBytes(l)
		}
	} else {
		b1 := rdr.GetUint8()
		l := binary.BigEndian.Uint16([]byte{b0, b1})
		if l > 0 {
			h.identity = rdr.GetBytes(int(l))
		}
	}
	return nil
}

func (h *serverKeyExchange) Bytes() []byte {
	w := newByteWriter()

	l := len(h.identity)
	if l > 0 {
		w.PutUint16(uint16(l))
		w.PutBytes(h.identity)
	} else {
		w.PutUint8(0x03)
		w.PutUint16(uint16(h.curve))
		w.PutUint8(byte(len(h.publicKey)))
		w.PutBytes(h.publicKey)
		w.PutUint8(0x04) // SHA256
		w.PutUint8(0x03) // ECDSA
		w.PutUint16(uint16(len(h.signature)))
		w.PutBytes(h.signature)
	}
	return w.Bytes()
}

func (h *serverKeyExchange) Print() string {
	if len(h.identity) != 0 {
		return fmt.Sprintf("identity[%s][%d]", h.identity, len(h.identity))
	} else {
		return fmt.Sprintf("eccCurve[%d] publicKey[%s] signature[%s]", h.curve, hex.EncodeToString(h.publicKey), hex.EncodeToString(h.signature))
	}
}
