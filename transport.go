package dtls

type Transport interface {
	Type() string
	Local() string
	NewPeer(address string) TransportPeer
	ReadPacket() ([]byte, TransportPeer, error)
}

type TransportPeer interface {
	String() string
	WritePacket(data []byte) error
}
