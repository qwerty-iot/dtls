package dtls

type Transport interface {
	Type() string
	Local() string
	Shutdown() error
	NewEndpoint(address string) TransportEndpoint
	ReadPacket() ([]byte, TransportEndpoint, error)
}

type TransportEndpoint interface {
	String() string
	WritePacket(data []byte) error
}
