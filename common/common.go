package common

import (
	"crypto/rand"
)

const (
	DtlsVersion12 uint16 = 0xFEFD
)

func RandomBytes(length int) []byte {
	rbuf := make([]byte, length)
	rand.Read(rbuf)
	return rbuf
}
