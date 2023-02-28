// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"encoding/binary"
	"fmt"
	"time"
)

type serverHello struct {
	version           uint16
	randomTime        uint32
	randomBytes       []byte
	sessionIdLen      uint8
	sessionId         []byte
	cipherSuite       CipherSuite
	compressionMethod CompressionMethod
	cid               []byte
	cidVersion        uint16
}

func (h *serverHello) Init(randomBytes []byte, sessionId []byte, cid []byte, cidVersion uint16, cipherSuite CipherSuite) {
	h.version = DtlsVersion12
	h.randomBytes = randomBytes
	h.randomTime = binary.BigEndian.Uint32(h.randomBytes[:4])
	h.sessionId = sessionId
	h.sessionIdLen = uint8(len(h.sessionId))
	h.cid = cid
	h.cidVersion = cidVersion
	h.cipherSuite = cipherSuite
	h.compressionMethod = CompressionMethod_Null
}

func (h *serverHello) Parse(rdr *byteReader, size int) error {
	h.version = rdr.GetUint16()
	h.randomBytes = rdr.GetBytes(32)
	h.randomTime = binary.BigEndian.Uint32(h.randomBytes[:4])
	h.sessionIdLen = rdr.GetUint8()
	if h.sessionIdLen > 0 {
		h.sessionId = rdr.GetBytes(int(h.sessionIdLen))
	}
	h.cipherSuite = CipherSuite(rdr.GetUint16())
	h.compressionMethod = CompressionMethod(rdr.GetUint8())

	extTotalLen := rdr.GetUint16()
	if extTotalLen != 0 {
		// have extensions
		for read := 0; read < int(extTotalLen); {
			extType := rdr.GetUint16()
			extLen := rdr.GetUint16()
			switch extType {
			case DtlsExtConnectionId:
				cidLen := rdr.GetUint8()
				h.cid = rdr.GetBytes(int(cidLen))
				h.cidVersion = DtlsExtConnectionId
			case DtlsExtConnectionIdLegacy:
				cidLen := rdr.GetUint8()
				h.cid = rdr.GetBytes(int(cidLen))
				h.cidVersion = DtlsExtConnectionIdLegacy
			default:
				rdr.GetBytes(int(extLen))
			}
			read += 4 + int(extLen)
		}
	}
	return nil
}

func (h *serverHello) Bytes() []byte {
	w := newByteWriter()
	w.PutUint16(h.version)
	w.PutBytes(h.randomBytes)
	w.PutUint8(h.sessionIdLen)
	if h.sessionIdLen > 0 {
		w.PutBytes(h.sessionId)
	}
	w.PutUint16(uint16(h.cipherSuite))
	w.PutUint8(uint8(h.compressionMethod))

	ext := newByteWriter()

	if h.cid != nil {
		ext.PutUint16(h.cidVersion)
		ext.PutUint16(uint16(len(h.cid) + 1))
		if len(h.cid) > 0 {
			ext.PutUint8(uint8(len(h.cid)))
			ext.PutBytes(h.cid)
		}
	}

	if h.cipherSuite == CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 ||
		h.cipherSuite == CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 {

		ext.PutUint16(10)     // supported_groups
		ext.PutUint16(4)      // len
		ext.PutUint16(2)      // list count
		ext.PutUint16(0x0017) // secp256r1

		ext.PutUint16(11) // ec_point_formats
		ext.PutUint16(2)
		ext.PutUint8(1)
		ext.PutUint8(0)
	}

	if eb := ext.Bytes(); len(eb) != 0 {
		w.PutUint16(uint16(len(eb)))
		w.PutBytes(eb)
	}

	return w.Bytes()
}

func (h *serverHello) Print() string {
	return fmt.Sprintf("version[%X] randomData[%s][%d bytes] sessionId[%X][%d] cipherSuite[%s] compressionMethod[%x] cid[%X]", h.version, time.Unix(int64(h.randomTime), 0).String(), len(h.randomBytes), h.sessionId, h.sessionIdLen, cipherSuiteToString(h.cipherSuite), h.compressionMethod, h.cid)
}

func (h *serverHello) GetRandom() (time.Time, []byte) {
	return time.Unix(int64(h.randomTime), 0), h.randomBytes
}

func (h *serverHello) GetSessionId() []byte {
	return h.sessionId
}
