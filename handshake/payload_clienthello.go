package handshake

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/bocajim/dtls/common"
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

func (h *clientHello) Init(randomBytes []byte, cookie []byte) {
	h.version = common.DtlsVersion12
	h.randomBytes = randomBytes
	h.randomTime = binary.BigEndian.Uint32(h.randomBytes[:4])
	if cookie != nil {
		h.cookie = cookie
		h.cookieLen = uint8(len(cookie))
	}
	h.cipherSuitesLen = 2
	h.cipherSuites = []CipherSuite{CipherSuite_TLS_PSK_WITH_AES_128_CCM_8}
	h.compressionMethodsLen = 1
	h.compressionMethods = []CompressionMethod{CompressionMethod_Null}
}

func (h *clientHello) Parse(rdr *common.Reader) error {
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
	w := common.NewWriter()
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
	return w.Bytes()
}

func (h *clientHello) Print() string {
	suitesStr := ""
	for _, suite := range h.cipherSuites {
		suitesStr += fmt.Sprintf("%s,", CipherSuiteToString(suite))
	}
	suitesStr = suitesStr[:len(suitesStr)-1]

	comprStr := ""
	for _, compr := range h.compressionMethods {
		comprStr += fmt.Sprintf("0x%02X,", compr)
	}
	comprStr = comprStr[:len(comprStr)-1]

	return fmt.Sprintf("version[0x%X] randomData[%s][%X] sessionId[%X][%d] cookie[%X][%d] cipherSuites[%s][%d] compressionMethods[%v][%d]", h.version, time.Unix(int64(h.randomTime), 0).String(), h.randomBytes, h.sessionId, h.sessionIdLen, h.cookie, h.cookieLen, suitesStr, h.cipherSuitesLen, comprStr, h.compressionMethodsLen)
}

func (h *clientHello) GetRandom() (time.Time, []byte) {
	return time.Unix(int64(h.randomTime), 0), h.randomBytes
}

func (h *clientHello) GetCookie() []byte {
	return h.cookie
}
