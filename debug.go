package dtls

var DebugHandshake bool = false
var DebugHandshakeHash bool = false
var DebugEncryption bool = false

func DebugAll() {
	DebugHandshake = true
	DebugHandshakeHash = true
	DebugEncryption = true
}
