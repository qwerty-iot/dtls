package dtls

import (
	"net"
	"time"
)

type udpPeer struct {
	addr   *net.UDPAddr
	handle *udpHandle
}

type udpHandle struct {
	socket      *net.UDPConn
	readTimeout time.Duration
}

func newUdpHandle(listenAddress string, readTimeout time.Duration) (*udpHandle, error) {
	if len(listenAddress) == 0 {
		listenAddress = ":0"
	}
	la, err := net.ResolveUDPAddr("udp", listenAddress)
	if err != nil {
		return nil, err
	}

	conn := &udpHandle{readTimeout: readTimeout}

	conn.socket, err = net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (u *udpHandle) Type() string {
	return "udp"
}

func (u *udpHandle) Local() string {
	return u.socket.LocalAddr().String()
}

func (u *udpHandle) ReadPacket() ([]byte, TransportPeer, error) {
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

func (p *udpHandle) NewPeer(addr string) TransportPeer {
	peer := &udpPeer{}
	peer.addr, _ = net.ResolveUDPAddr("udp", addr)
	peer.handle = p
	return peer
}
