package alert

import (
	"fmt"
)

const (
	TypeWarning                uint8 = 1
	TypeFatal                  uint8 = 2
	DescCloseNotify            uint8 = 0
	DescUnexpectedMessage      uint8 = 10
	DescBadRecordMac           uint8 = 20
	DescDecryptionFailed       uint8 = 21
	DescRecordOverflow         uint8 = 22
	DescDecompressionFailure   uint8 = 30
	DescHandshakeFailure       uint8 = 40
	DescNoCertificate          uint8 = 41
	DescBadCertificate         uint8 = 42
	DescUnsupportedCertificate uint8 = 43
	DesCcertificateRevoked     uint8 = 44
	DescCertificateExpired     uint8 = 45
	DescCertificateUnknown     uint8 = 46
	DescIllegalParameter       uint8 = 47
	DescUnknownCa              uint8 = 48
	DescAccessDenied           uint8 = 49
	DescDecodeError            uint8 = 50
	DescDecryptError           uint8 = 51
	DescExportRestriction      uint8 = 60
	DescProtocolVersion        uint8 = 70
	DescInsufficientSecurity   uint8 = 71
	DescInternalError          uint8 = 80
	DescUserCanceled           uint8 = 90
	DescNoRenegotiation        uint8 = 100
	DescUnsupportedExtension   uint8 = 110
)

type Alert struct {
	Type uint8
	Desc uint8
}

func New(t uint8, d uint8) *Alert {
	return &Alert{t, d}
}

func (a *Alert) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = a.Type
	b[1] = a.Desc
	return b
}

func TypeToString(t uint8) string {
	switch t {
	case TypeWarning:
		return "warning"
	case TypeFatal:
		return "fatal"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

func DescToString(d uint8) string {
	switch d {
	case DescCloseNotify:
		return "close notify"
	case DescUnexpectedMessage:
		return "unexpected message"
	case DescBadRecordMac:
		return "bad record mac"
	case DescDecryptionFailed:
		return "decryption failed"
	case DescRecordOverflow:
		return "record overflow"
	case DescDecompressionFailure:
		return "decompression failure"
	case DescHandshakeFailure:
		return "handshake failure"
	case DescNoCertificate:
		return "no certificate"
	case DescBadCertificate:
		return "bad certificate"
	case DescUnsupportedCertificate:
		return "unsupported certificate"
	case DesCcertificateRevoked:
		return "certificate revoked"
	case DescCertificateExpired:
		return "certificate expired"
	case DescCertificateUnknown:
		return "certificate unknown"
	case DescIllegalParameter:
		return "illegal parameter"
	case DescUnknownCa:
		return "unknown ca"
	case DescAccessDenied:
		return "access denied"
	case DescDecodeError:
		return "decode error"
	case DescDecryptError:
		return "decrypt error"
	case DescExportRestriction:
		return "export restriction"
	case DescProtocolVersion:
		return "protocol version"
	case DescInsufficientSecurity:
		return "insufficient security"
	case DescInternalError:
		return "internal error"
	case DescUserCanceled:
		return "user canceled"
	case DescNoRenegotiation:
		return "return no renegotiation"
	case DescUnsupportedExtension:
		return "unsupported extension"
	}
	return fmt.Sprintf("unknown(%d)", d)
}
