package dtls

import (
	"crypto/rand"
)

const (
	DtlsVersion12 uint16 = 0xFEFD
)

func randomBytes(length int) []byte {
	rbuf := make([]byte, length)
	rand.Read(rbuf)
	return rbuf
}
