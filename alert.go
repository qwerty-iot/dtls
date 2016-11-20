package dtls

import (
	"fmt"
)

const (
	AlertType_Warning                uint8 = 1
	AlertType_Fatal                  uint8 = 2
	AlertDesc_CloseNotify            uint8 = 0
	AlertDesc_UnexpectedMessage      uint8 = 10
	AlertDesc_BadRecordMac           uint8 = 20
	AlertDesc_DecryptionFailed       uint8 = 21
	AlertDesc_RecordOverflow         uint8 = 22
	AlertDesc_DecompressionFailure   uint8 = 30
	AlertDesc_HandshakeFailure       uint8 = 40
	AlertDesc_NoCertificate          uint8 = 41
	AlertDesc_BadCertificate         uint8 = 42
	AlertDesc_UnsupportedCertificate uint8 = 43
	AlertDesc_CertificateRevoked     uint8 = 44
	AlertDesc_CertificateExpired     uint8 = 45
	AlertDesc_CertificateUnknown     uint8 = 46
	AlertDesc_IllegalParameter       uint8 = 47
	AlertDesc_UnknownCa              uint8 = 48
	AlertDesc_AccessDenied           uint8 = 49
	AlertDesc_DecodeError            uint8 = 50
	AlertDesc_DecryptError           uint8 = 51
	AlertDesc_ExportRestriction      uint8 = 60
	AlertDesc_ProtocolVersion        uint8 = 70
	AlertDesc_InsufficientSecurity   uint8 = 71
	AlertDesc_InternalError          uint8 = 80
	AlertDesc_UserCanceled           uint8 = 90
	AlertDesc_NoRenegotiation        uint8 = 100
	AlertDesc_UnsupportedExtension   uint8 = 110
)

type alert struct {
	Type uint8
	Desc uint8
}

func newAlert(t uint8, d uint8) *alert {
	return &alert{t, d}
}

func (a *alert) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = a.Type
	b[1] = a.Desc
	return b
}

func alertTypeToString(t uint8) string {
	switch t {
	case AlertType_Warning:
		return "warning"
	case AlertType_Fatal:
		return "fatal"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

func alertDescToString(d uint8) string {
	switch d {
	case AlertDesc_CloseNotify:
		return "close notify"
	case AlertDesc_UnexpectedMessage:
		return "unexpected message"
	case AlertDesc_BadRecordMac:
		return "bad record mac"
	case AlertDesc_DecryptionFailed:
		return "decryption failed"
	case AlertDesc_RecordOverflow:
		return "record overflow"
	case AlertDesc_DecompressionFailure:
		return "decompression failure"
	case AlertDesc_HandshakeFailure:
		return "handshake failure"
	case AlertDesc_NoCertificate:
		return "no certificate"
	case AlertDesc_BadCertificate:
		return "bad certificate"
	case AlertDesc_UnsupportedCertificate:
		return "unsupported certificate"
	case AlertDesc_CertificateRevoked:
		return "certificate revoked"
	case AlertDesc_CertificateExpired:
		return "certificate expired"
	case AlertDesc_CertificateUnknown:
		return "certificate unknown"
	case AlertDesc_IllegalParameter:
		return "illegal parameter"
	case AlertDesc_UnknownCa:
		return "unknown ca"
	case AlertDesc_AccessDenied:
		return "access denied"
	case AlertDesc_DecodeError:
		return "decode error"
	case AlertDesc_DecryptError:
		return "decrypt error"
	case AlertDesc_ExportRestriction:
		return "export restriction"
	case AlertDesc_ProtocolVersion:
		return "protocol version"
	case AlertDesc_InsufficientSecurity:
		return "insufficient security"
	case AlertDesc_InternalError:
		return "internal error"
	case AlertDesc_UserCanceled:
		return "user canceled"
	case AlertDesc_NoRenegotiation:
		return "return no renegotiation"
	case AlertDesc_UnsupportedExtension:
		return "unsupported extension"
	}
	return fmt.Sprintf("unknown(%d)", d)
}
