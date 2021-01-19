// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"fmt"
)

type certificate struct {
	certs [][]byte
}

func (h *certificate) Init(certs [][]byte) error {
	h.certs = certs
	return nil
}

func (h *certificate) Parse(rdr *byteReader, size int) error {
	certsLen := rdr.GetUint24()
	h.certs = [][]byte{}
	totalRead := 3
	for {
		certLen := rdr.GetUint24()
		certBytes := rdr.GetBytes(int(certLen))
		h.certs = append(h.certs, certBytes)
		totalRead = totalRead + 3 + int(certsLen)
		if totalRead >= int(certsLen) {
			break
		}
	}
	return nil
}

func (h *certificate) Bytes() []byte {
	w := newByteWriter()
	totalLen := 0
	for _, cert := range h.certs {
		totalLen = totalLen + 3 + len(cert)
	}
	w.PutUint24(uint32(totalLen))
	for _, cert := range h.certs {
		w.PutUint24(uint32(len(cert)))
		w.PutBytes(cert)
	}
	return w.Bytes()
}

func (h *certificate) Print() string {
	certsStr := "certs["
	for idx, cert := range h.certs {
		certsStr += fmt.Sprintf("(%d)%X,", idx, cert)
	}
	certsStr += "]"

	return certsStr
}

func (h *certificate) GetCerts() [][]byte {
	return h.certs
}
