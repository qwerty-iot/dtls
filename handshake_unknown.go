// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

type unknown struct {
}

func (h *unknown) Init() {
	return
}

func (h *unknown) Parse(rdr *byteReader, size int) error {
	return nil
}

func (h *unknown) Bytes() []byte {
	return nil
}

func (h *unknown) Print() string {
	return ""
}
