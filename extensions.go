package dtls

const (
	DtlsExtPreSharedKey        uint16 = 41
	DtlsExtSupportedVersions   uint16 = 43
	DtlsExtCookie              uint16 = 44
	DtlsExtPskKeyExchangeModes uint16 = 45
)

const (
	Dtls13PskKeyExchangeModePSKOnly uint8 = 0
	Dtls13PskKeyExchangeModePSKDHE  uint8 = 1
)
