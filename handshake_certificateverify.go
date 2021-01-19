// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"encoding/hex"
	"fmt"
)

type certificateVerify struct {
	signature []byte
}

func (h *certificateVerify) Init(signature []byte) {
	h.signature = signature
}

func (h *certificateVerify) GetSignature() []byte {
	return h.signature
}

func (h *certificateVerify) Parse(rdr *byteReader, size int) error {
	// no need to parse details at this time
	rdr.GetUint8()
	rdr.GetUint8()
	l := rdr.GetUint16()
	h.signature = rdr.GetBytes(int(l))
	return nil
}

func (h *certificateVerify) Bytes() []byte {
	w := newByteWriter()

	w.PutUint8(0x04) // SHA256
	w.PutUint8(0x03) // ECDSA
	w.PutUint16(uint16(len(h.signature)))
	w.PutBytes(h.signature)

	return w.Bytes()
}

func (h *certificateVerify) Print() string {
	return fmt.Sprintf("signature[%s][%d]", hex.EncodeToString(h.signature), len(h.signature))
}
