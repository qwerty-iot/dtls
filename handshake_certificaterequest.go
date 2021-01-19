// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

type certificateRequest struct {
}

func (h *certificateRequest) Parse(rdr *byteReader, size int) error {
	// no need to parse details at this time
	return nil
}

func (h *certificateRequest) Bytes() []byte {
	w := newByteWriter()

	w.PutUint8(1)
	w.PutUint8(0x40) // ECDSA
	w.PutUint16(2)
	w.PutUint8(0x04) // SHA256
	w.PutUint8(0x03) // ECDSA
	w.PutUint16(0)

	return w.Bytes()
}

func (h *certificateRequest) Print() string {
	return "certificateRequest"
}
