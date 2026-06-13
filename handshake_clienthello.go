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
	cidEnable             bool
	cidVersion            uint16
	cid                   []byte
	supportedVersions     []uint16
	pskKeyExchangeModes   []uint8
	pskIdentities         []dtls13PSKIdentity
	pskBinders            [][]byte
}

type dtls13PSKIdentity struct {
	Identity            []byte
	ObfuscatedTicketAge uint32
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

func (h *clientHello) EnableCid(cid []byte, version uint16) {
	h.cidEnable = true
	h.cidVersion = version
	h.cid = cid
}

func (h *clientHello) EnableSupportedVersions(versions []uint16) {
	h.supportedVersions = append([]uint16(nil), versions...)
}

func (h *clientHello) EnablePskKeyExchangeModes(modes []uint8) {
	h.pskKeyExchangeModes = append([]uint8(nil), modes...)
}

func (h *clientHello) EnableExternalPSK(identity []byte, binder []byte) {
	h.pskIdentities = []dtls13PSKIdentity{{Identity: append([]byte(nil), identity...)}}
	h.pskBinders = [][]byte{append([]byte(nil), binder...)}
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
	extTotalLen := rdr.GetUint16()
	if extTotalLen != 0 {
		// have extensions
		for read := 0; read < int(extTotalLen); {
			extType := rdr.GetUint16()
			extLen := rdr.GetUint16()
			switch extType {
			case DtlsExtConnectionId:
				h.cidEnable = true
				h.cidVersion = DtlsExtConnectionId
				cidLen := rdr.GetUint8()
				if cidLen > 0 {
					h.cid = rdr.GetBytes(int(cidLen))
				}
			case DtlsExtConnectionIdLegacy:
				h.cidEnable = true
				h.cidVersion = DtlsExtConnectionIdLegacy
				cidLen := rdr.GetUint8()
				if cidLen > 0 {
					h.cid = rdr.GetBytes(int(cidLen))
				}
			case DtlsExtSupportedVersions:
				versionsLen := int(rdr.GetUint8())
				for i := 0; i < versionsLen/2; i++ {
					h.supportedVersions = append(h.supportedVersions, rdr.GetUint16())
				}
			case DtlsExtPskKeyExchangeModes:
				modesLen := int(rdr.GetUint8())
				h.pskKeyExchangeModes = rdr.GetBytes(modesLen)
			case DtlsExtPreSharedKey:
				identitiesLen := int(rdr.GetUint16())
				for readIdentities := 0; readIdentities < identitiesLen; {
					identityLen := int(rdr.GetUint16())
					identity := rdr.GetBytes(identityLen)
					age := rdr.GetUint32()
					h.pskIdentities = append(h.pskIdentities, dtls13PSKIdentity{Identity: identity, ObfuscatedTicketAge: age})
					readIdentities += 2 + identityLen + 4
				}
				bindersLen := int(rdr.GetUint16())
				for readBinders := 0; readBinders < bindersLen; {
					binderLen := int(rdr.GetUint8())
					binder := rdr.GetBytes(binderLen)
					h.pskBinders = append(h.pskBinders, binder)
					readBinders += 1 + binderLen
				}
			default:
				rdr.GetBytes(int(extLen))
			}
			read += 4 + int(extLen)
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

	ext := newByteWriter()

	if h.cidEnable {
		ext.PutUint16(h.cidVersion)
		ext.PutUint16(uint16(len(h.cid) + 1))
		ext.PutUint8(uint8(len(h.cid)))
		if len(h.cid) > 0 {
			ext.PutBytes(h.cid)
		}
	}

	if h.cipherSuites[0] == CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 ||
		h.cipherSuites[0] == CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 {
		// TODO: Implement proper extensions

		ext.PutUint16(10)     // supported_groups
		ext.PutUint16(4)      // len
		ext.PutUint16(1)      // list count
		ext.PutUint16(0x0017) // secp256r1

		ext.PutUint16(11) // ec_point_formats
		ext.PutUint16(2)
		ext.PutUint16(1)
		ext.PutUint16(0)

		ext.PutUint16(13) // signature_algorithms
		ext.PutUint16(4)
		ext.PutUint16(2)
		ext.PutUint16(0x0403)
	}

	if len(h.supportedVersions) > 0 {
		ext.PutUint16(DtlsExtSupportedVersions)
		ext.PutUint16(uint16(1 + len(h.supportedVersions)*2))
		ext.PutUint8(uint8(len(h.supportedVersions) * 2))
		for _, version := range h.supportedVersions {
			ext.PutUint16(version)
		}
	}

	if len(h.pskKeyExchangeModes) > 0 {
		ext.PutUint16(DtlsExtPskKeyExchangeModes)
		ext.PutUint16(uint16(1 + len(h.pskKeyExchangeModes)))
		ext.PutUint8(uint8(len(h.pskKeyExchangeModes)))
		ext.PutBytes(h.pskKeyExchangeModes)
	}

	if len(h.pskIdentities) > 0 {
		pskExt := newByteWriter()
		identities := newByteWriter()
		for _, identity := range h.pskIdentities {
			identities.PutUint16(uint16(len(identity.Identity)))
			identities.PutBytes(identity.Identity)
			identities.PutUint32(identity.ObfuscatedTicketAge)
		}
		identitiesBytes := identities.Bytes()
		pskExt.PutUint16(uint16(len(identitiesBytes)))
		pskExt.PutBytes(identitiesBytes)

		binders := newByteWriter()
		for _, binder := range h.pskBinders {
			binders.PutUint8(uint8(len(binder)))
			binders.PutBytes(binder)
		}
		bindersBytes := binders.Bytes()
		pskExt.PutUint16(uint16(len(bindersBytes)))
		pskExt.PutBytes(bindersBytes)
		pskExtBytes := pskExt.Bytes()
		ext.PutUint16(DtlsExtPreSharedKey)
		ext.PutUint16(uint16(len(pskExtBytes)))
		ext.PutBytes(pskExtBytes)
	}

	if eb := ext.Bytes(); len(eb) != 0 {
		w.PutUint16(uint16(len(eb)))
		w.PutBytes(eb)
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

	return fmt.Sprintf("version[0x%X] randomData[%s][%X] sessionId[%X][%d] cookie[%X][%d] advertisedCipherSuites[%s][%d] advertisedCompressionMethods[%v][%d] cid[%t][%d][%X]", h.version, time.Unix(int64(h.randomTime), 0).String(),
		h.randomBytes, h.sessionId, h.sessionIdLen, h.cookie, h.cookieLen, suitesStr, h.cipherSuitesLen, comprStr, h.compressionMethodsLen, h.cidEnable, h.cidVersion, h.cid)
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

func (h *clientHello) HasCookie() bool {
	return h != nil && h.cookieLen > 0
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

func (h *clientHello) SelectCipherSuite(supported []CipherSuite) CipherSuite {
	for _, ad := range supported {
		if ad.NeedPsk() {
			for _, cipher := range h.cipherSuites {
				if ad == cipher {
					return cipher
				}
			}
		}
	}
	for _, ad := range supported {
		if ad.NeedCert() {
			for _, cipher := range h.cipherSuites {
				if ad == cipher {
					return cipher
				}
			}
		}
	}
	return 0
}

func (h *clientHello) SelectTLS13CipherSuite(supported []CipherSuite) CipherSuite {
	for _, ad := range supported {
		if !ad.IsTLS13() {
			continue
		}
		for _, cipher := range h.cipherSuites {
			if ad == cipher {
				return cipher
			}
		}
	}
	return 0
}

func (h *clientHello) SupportsVersion(version uint16) bool {
	for _, supported := range h.supportedVersions {
		if supported == version {
			return true
		}
	}
	return false
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
