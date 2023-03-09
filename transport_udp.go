// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"errors"
	"fmt"
	"net"
	"time"
)

var MaxPacketSize = 16384

type udpEndpoint struct {
	addr   *net.UDPAddr
	handle *udpTransport
}

type udpTransport struct {
	socket      *net.UDPConn
	readTimeout time.Duration
	shutdown    bool
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
	u.shutdown = true
	return u.socket.Close()
}

func (u *udpTransport) ReadPacket() ([]byte, TransportEndpoint, error) {
	buffer := make([]byte, MaxPacketSize)

	//TODO add timeout support

	length, from, err := u.socket.ReadFromUDP(buffer)
	if err != nil {
		if u.shutdown {
			return nil, nil, errors.New("shutdown")
		}
		logError(nil, nil, err, "failed to receive packet")
		return nil, nil, err
	}
	if length > MaxPacketSize {
		err = fmt.Errorf("packet size %d>%d", length, MaxPacketSize)
		logError(nil, nil, err, "packet too large")
		return nil, nil, nil
	}
	sniffActivity(u.Type(), SniffRead, from.String(), u.Local(), buffer[:length])
	return buffer[:length], &udpEndpoint{addr: from, handle: u}, nil
}

func (p *udpEndpoint) WritePacket(data []byte) error {
	sniffActivity(p.handle.Type(), SniffWrite, p.handle.Local(), p.addr.String(), data)
	_, err := p.handle.socket.WriteToUDP(data, p.addr)
	return err
}

func (p *udpEndpoint) String() string {
	return p.addr.String()
}

func (p *udpTransport) NewEndpoint(addr string) TransportEndpoint {
	peer := &udpEndpoint{}
	peer.addr, _ = net.ResolveUDPAddr("udp", addr)
	peer.handle = p
	return peer
}

func NewUdpPeerFromSocket(socket *net.UDPConn, addr *net.UDPAddr) TransportEndpoint {
	return &udpEndpoint{addr: addr, handle: &udpTransport{socket: socket}}
}
