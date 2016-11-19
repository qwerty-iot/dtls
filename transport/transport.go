package transport

type Transport interface {
	Type() string
	Local() string
	NewPeer(address string) Peer
	ReadPacket() ([]byte, Peer, error)
}

type Peer interface {
	String() string
	WritePacket(data []byte) error
}

type NilPeer struct {
}

func (p *NilPeer) String() string {
	return "nil"
}
func (p *NilPeer) WritePacket(data []byte) error {
	return nil
}
