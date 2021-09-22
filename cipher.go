// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import "fmt"

type CipherSuite uint16

const (
	CipherSuite_TLS_PSK_WITH_AES_128_CCM_8              CipherSuite = 0xC0A8
	CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256         CipherSuite = 0x00AE
	CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8      CipherSuite = 0xC0AE
	CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 CipherSuite = 0xC023
)

func (cs CipherSuite) NeedPsk() bool {
	switch cs {
	case CipherSuite_TLS_PSK_WITH_AES_128_CCM_8, CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256:
		return true
	}
	return false
}

func (cs CipherSuite) NeedCert() bool {
	switch cs {
	case CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return true
	}
	return false
}

type Cipher interface {
	GetPrfSize() int
	GenerateKeyBlock(masterSecret []byte, rawKeyBlock []byte) *KeyBlock
	Encrypt(rec *record, key []byte, iv []byte, mac []byte) ([]byte, error)
	Decrypt(rec *record, key []byte, iv []byte, mac []byte) ([]byte, error)
}

func getCipher(peer *Peer, cipherSuite CipherSuite) Cipher {
	switch cipherSuite {
	case CipherSuite_TLS_PSK_WITH_AES_128_CCM_8:
		return CipherCcm{peer: peer}
	case CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256:
		return CipherCBC{peer: peer}
	case CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return CipherCcm{peer: peer}
	case CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return CipherCBC{peer: peer}
	}
	return nil
}

func cipherSuiteToString(c CipherSuite) string {
	switch c {
	case CipherSuite_TLS_PSK_WITH_AES_128_CCM_8:
		return "TLS_PSK_WITH_AES_128_CCM_8(0xC0A8)"
	case CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256:
		return "TLS_PSK_WITH_AES_128_CBC_SHA256(0x00AE)"
	case CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(0xC0AE)"
	case CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023)"
	}
	return fmt.Sprintf("Unknown(0x%X)", c)
}
