// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"fmt"
)

type header struct {
	HandshakeType handshakeType
	Length        uint32
	Sequence      uint16
	FragmentOfs   uint32
	FragmentLen   uint32
}

func (h *header) Parse(rdr *byteReader) error {
	h.HandshakeType = handshakeType(rdr.GetUint8())
	h.Length = rdr.GetUint24()
	h.Sequence = rdr.GetUint16()
	h.FragmentOfs = rdr.GetUint24()
	h.FragmentLen = rdr.GetUint24()
	return nil
}

func (h *header) Bytes() []byte {
	w := newByteWriter()
	w.PutUint8(uint8(h.HandshakeType))
	w.PutUint24(h.Length)
	w.PutUint16(h.Sequence)
	w.PutUint24(h.FragmentOfs)
	w.PutUint24(h.FragmentLen)

	return w.Bytes()
}

func (h *header) SetLength(length int) {
	h.Length = uint32(length)
	h.FragmentLen = h.Length
	return
}

func (h *header) Print() string {
	return fmt.Sprintf("handshakeType[%s] length[%d] sequence[%d] fragmentOfs[%d] fragmentLen[%d]", typeToString(h.HandshakeType), h.Length, h.Sequence, h.FragmentOfs, h.FragmentLen)
}
