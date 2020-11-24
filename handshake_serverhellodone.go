// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

type serverHelloDone struct {
}

func (h *serverHelloDone) Init() {
	return
}

func (h *serverHelloDone) Parse(rdr *byteReader) error {
	return nil
}

func (h *serverHelloDone) Bytes() []byte {
	return nil
}

func (h *serverHelloDone) Print() string {
	return ""
}
