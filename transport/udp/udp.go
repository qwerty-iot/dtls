package udp

import (
	"net"
	"time"

	"github.com/bocajim/dtls/common"
	"github.com/bocajim/dtls/transport"
)

type UdpPeer struct {
	addr   *net.UDPAddr
	handle *UdpHandle
}

type UdpHandle struct {
	socket      *net.UDPConn
	readTimeout time.Duration
}

func NewUdpHandle(listenAddress string, readTimeout time.Duration) (*UdpHandle, error) {
	if len(listenAddress) == 0 {
		listenAddress = ":0"
	}
	la, err := net.ResolveUDPAddr("udp", listenAddress)
	if err != nil {
		return nil, err
	}

	conn := &UdpHandle{readTimeout: readTimeout}

	conn.socket, err = net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (u *UdpHandle) Type() string {
	return "udp"
}

func (u *UdpHandle) Local() string {
	return u.socket.LocalAddr().String()
}

func (u *UdpHandle) ReadPacket() ([]byte, transport.Peer, error) {
	buffer := make([]byte, 32768)

	//TODO add timeout support

	for {
		length, from, err := u.socket.ReadFromUDP(buffer)
		if err != nil {
			common.LogError("dtls: failed to receive packet: %s", err.Error())
			return nil, nil, err
		}
		return buffer[:length], &UdpPeer{addr: from, handle: u}, nil
	}
}

func (p *UdpPeer) WritePacket(data []byte) error {
	_, err := p.handle.socket.WriteToUDP(data, p.addr)
	return err
}

func (p *UdpPeer) String() string {
	return p.addr.String()
}

func (p *UdpHandle) NewPeer(addr string) transport.Peer {
	peer := &UdpPeer{}
	peer.addr, _ = net.ResolveUDPAddr("udp", addr)
	peer.handle = p
	return peer
}
