// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type clientHello struct {
	version               uint16
	randomTime            uint32
	randomBytes           []byte
	sessionIdLen          uint8
	sessionId             []byte
	cookieLen             uint8
	cookie                []byte
	cipherSuitesLen       uint16
	cipherSuites          []CipherSuite
	compressionMethodsLen uint8
	compressionMethods    []CompressionMethod
}

func (h *clientHello) Init(sessionId []byte, randomBytes []byte, cookie []byte, cipherSuites []CipherSuite, compressionMethods []CompressionMethod) error {
	if len(randomBytes) < 4 {
		return errors.New("dtls: random data underflow")
	}
	h.version = DtlsVersion12
	h.randomBytes = randomBytes
	h.randomTime = binary.BigEndian.Uint32(h.randomBytes[:4])
	if sessionId != nil {
		h.sessionId = sessionId
		h.sessionIdLen = uint8(len(sessionId))
	}
	if cookie != nil {
		h.cookie = cookie
		h.cookieLen = uint8(len(cookie))
	}
	h.cipherSuitesLen = uint16(len(cipherSuites) * 2)
	h.cipherSuites = cipherSuites
	h.compressionMethodsLen = uint8(len(compressionMethods))
	h.compressionMethods = compressionMethods
	return nil
}

func (h *clientHello) Parse(rdr *byteReader, size int) error {
	h.version = rdr.GetUint16()
	h.randomBytes = rdr.GetBytes(32)
	h.randomTime = binary.BigEndian.Uint32(h.randomBytes[:4])
	h.sessionIdLen = rdr.GetUint8()
	if h.sessionIdLen > 0 {
		h.sessionId = rdr.GetBytes(int(h.sessionIdLen))
	}
	h.cookieLen = rdr.GetUint8()
	if h.cookieLen > 0 {
		h.cookie = rdr.GetBytes(int(h.cookieLen))
	}
	h.cipherSuitesLen = rdr.GetUint16()
	if h.cipherSuitesLen > 0 {
		h.cipherSuites = make([]CipherSuite, 0, h.cipherSuitesLen/2)
		for i := 0; i < int(h.cipherSuitesLen)/2; i++ {
			h.cipherSuites = append(h.cipherSuites, CipherSuite(rdr.GetUint16()))
		}
	}
	h.compressionMethodsLen = rdr.GetUint8()
	if h.compressionMethodsLen > 0 {
		h.compressionMethods = make([]CompressionMethod, 0, h.compressionMethodsLen)
		for i := 0; i < int(h.compressionMethodsLen); i++ {
			h.compressionMethods = append(h.compressionMethods, CompressionMethod(rdr.GetUint8()))
		}
	}
	return nil
}

func (h *clientHello) Bytes() []byte {
	w := newByteWriter()
	w.PutUint16(h.version)
	w.PutBytes(h.randomBytes)
	w.PutUint8(h.sessionIdLen)
	if h.sessionIdLen > 0 {
		w.PutBytes(h.sessionId)
	}
	w.PutUint8(h.cookieLen)
	if h.cookieLen > 0 {
		w.PutBytes(h.cookie)
	}
	w.PutUint16(h.cipherSuitesLen)
	if h.cipherSuitesLen > 0 {
		for _, cs := range h.cipherSuites {
			w.PutUint16(uint16(cs))
		}
	}
	w.PutUint8(h.compressionMethodsLen)
	if h.compressionMethodsLen > 0 {
		for _, cm := range h.compressionMethods {
			w.PutUint8(uint8(cm))
		}
	}
	if h.cipherSuites[0] == CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 ||
		h.cipherSuites[0] == CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 {
		// TODO: Implement proper extensions
		w.PutUint16(24) // extensions length

		w.PutUint16(10)     // supported_groups
		w.PutUint16(4)      // len
		w.PutUint16(1)      // list count
		w.PutUint16(0x0017) // secp256r1

		w.PutUint16(11) // ec_point_formats
		w.PutUint16(2)
		w.PutUint16(1)
		w.PutUint16(0)

		w.PutUint16(13) // signature_algorithms
		w.PutUint16(4)
		w.PutUint16(2)
		w.PutUint16(0x0403)
	}
	return w.Bytes()
}

func (h *clientHello) Print() string {
	suitesStr := ""
	for _, suite := range h.cipherSuites {
		suitesStr += fmt.Sprintf("%s,", cipherSuiteToString(suite))
	}
	if len(suitesStr) > 2 {
		suitesStr = suitesStr[:len(suitesStr)-1]
	}
	comprStr := ""
	for _, compr := range h.compressionMethods {
		comprStr += fmt.Sprintf("0x%02X,", compr)
	}
	if len(comprStr) > 2 {
		comprStr = comprStr[:len(comprStr)-1]
	}

	return fmt.Sprintf("version[0x%X] randomData[%s][%X] sessionId[%X][%d] cookie[%X][%d] advertisedCipherSuites[%s][%d] advertisedCompressionMethods[%v][%d]", h.version, time.Unix(int64(h.randomTime), 0).String(), h.randomBytes, h.sessionId, h.sessionIdLen, h.cookie, h.cookieLen, suitesStr, h.cipherSuitesLen, comprStr, h.compressionMethodsLen)
}

func (h *clientHello) GetRandom() (time.Time, []byte) {
	return time.Unix(int64(h.randomTime), 0), h.randomBytes
}

func (h *clientHello) GetCookie() []byte {
	return h.cookie
}

func (h *clientHello) HasSessionId() bool {
	return h.sessionIdLen > 0
}

func (h *clientHello) GetSessionId() []byte {
	return h.sessionId
}

func (h *clientHello) GetSessionIdStr() string {
	return hex.EncodeToString(h.sessionId)
}

func (h *clientHello) GetCipherSuites() []CipherSuite {
	return h.cipherSuites
}

func (h *clientHello) SelectCipherSuite(advertised []CipherSuite) CipherSuite {
	for _, ad := range advertised {
		for _, cipher := range h.cipherSuites {
			if ad == cipher {
				return cipher
			}
		}
	}
	return 0
}

func (h *clientHello) GetCompressionMethods() []CompressionMethod {
	return h.compressionMethods
}

func (h *clientHello) MakeCookie(seed []byte) []byte {
	hash := sha256.New()
	hash.Write(seed)
	hash.Write(h.randomBytes)
	for _, cs := range h.cipherSuites {
		buf := make([]byte, 2)
		buf[0] = byte(cs & 0xFF)
		buf[1] = byte(cs & 0xFF00 >> 8)
		hash.Write(buf)
	}
	for _, cm := range h.compressionMethods {
		hash.Write([]byte{byte(cm)})
	}
	return hash.Sum(nil)
}
