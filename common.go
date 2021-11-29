// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"crypto/rand"
)

const (
	DtlsVersion10 uint16 = 0xFEFF
	DtlsVersion12 uint16 = 0xFEFD
)

func randomBytes(length int) []byte {
	rbuf := make([]byte, length)
	rand.Read(rbuf)
	return rbuf
}
