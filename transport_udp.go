package dtls

import (
	"net"
	"time"
)

type udpPeer struct {
	addr   *net.UDPAddr
	handle *udpTransport
}

type udpTransport struct {
	socket      *net.UDPConn
	readTimeout time.Duration
}

func newUdpTransport(listenAddress string, readTimeout time.Duration) (*udpTransport, error) {
	if len(listenAddress) == 0 {
		listenAddress = ":0"
	}
	la, err := net.ResolveUDPAddr("udp", listenAddress)
	if err != nil {
		return nil, err
	}

	conn := &udpTransport{readTimeout: readTimeout}

	conn.socket, err = net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (u *udpTransport) Type() string {
	return "udp"
}

func (u *udpTransport) Local() string {
	return u.socket.LocalAddr().String()
}

func (u *udpTransport) Shutdown() error {
	return u.socket.Close()
}

func (u *udpTransport) ReadPacket() ([]byte, TransportPeer, error) {
	buffer := make([]byte, 32768)

	//TODO add timeout support

	for {
		length, from, err := u.socket.ReadFromUDP(buffer)
		if err != nil {
			logError("dtls: failed to receive packet: %s", err.Error())
			return nil, nil, err
		}
		return buffer[:length], &udpPeer{addr: from, handle: u}, nil
	}
}

func (p *udpPeer) WritePacket(data []byte) error {
	_, err := p.handle.socket.WriteToUDP(data, p.addr)
	return err
}

func (p *udpPeer) String() string {
	return p.addr.String()
}

func (p *udpTransport) NewPeer(addr string) TransportPeer {
	peer := &udpPeer{}
	peer.addr, _ = net.ResolveUDPAddr("udp", addr)
	peer.handle = p
	return peer
}

func NewUdpPeerFromSocket(socket *net.UDPConn, addr *net.UDPAddr) TransportPeer {
	return &udpPeer{addr: addr, handle: &udpTransport{socket: socket}}
}
