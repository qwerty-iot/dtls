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
}

func (h *serverHello) Init(randomBytes []byte, sessionId []byte) {
	h.version = DtlsVersion12
	h.randomBytes = randomBytes
	h.randomTime = binary.BigEndian.Uint32(h.randomBytes[:4])
	h.sessionId = sessionId
	h.sessionIdLen = uint8(len(h.sessionId))
	h.cipherSuite = CipherSuite_TLS_PSK_WITH_AES_128_CCM_8
	h.compressionMethod = CompressionMethod_Null
}

func (h *serverHello) Parse(rdr *byteReader) error {
	h.version = rdr.GetUint16()
	h.randomBytes = rdr.GetBytes(32)
	h.randomTime = binary.BigEndian.Uint32(h.randomBytes[:4])
	h.sessionIdLen = rdr.GetUint8()
	if h.sessionIdLen > 0 {
		h.sessionId = rdr.GetBytes(int(h.sessionIdLen))
	}
	h.cipherSuite = CipherSuite(rdr.GetUint16())
	h.compressionMethod = CompressionMethod(rdr.GetUint8())

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

	return w.Bytes()
}

func (h *serverHello) Print() string {
	return fmt.Sprintf("version[%X] randomData[%s][%d bytes] sessionId[%X][%d] cipherSuite[%s] compressionMethod[%x]", h.version, time.Unix(int64(h.randomTime), 0).String(), len(h.randomBytes), h.sessionId, h.sessionIdLen, cipherSuiteToString(h.cipherSuite), h.compressionMethod)
}

func (h *serverHello) GetRandom() (time.Time, []byte) {
	return time.Unix(int64(h.randomTime), 0), h.randomBytes
}

func (h *serverHello) GetSessionId() []byte {
	return h.sessionId
}
