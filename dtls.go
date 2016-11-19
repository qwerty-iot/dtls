package dtls

import (
	"sync"
	"time"

	"github.com/bocajim/dtls/common"
	"github.com/bocajim/dtls/session"
	"github.com/bocajim/dtls/transport"
	"github.com/bocajim/dtls/transport/udp"
)

type Listener struct {
	transport transport.Transport
	peers     map[string]*Peer
	readQueue chan *msg
	mux       sync.Mutex
}

type msg struct {
	data []byte
	peer *Peer
}

func NewUdpListener(listener string, readTimeout time.Duration) (*Listener, error) {
	utrans, err := udp.NewUdpHandle(listener, readTimeout)
	if err != nil {
		return nil, err
	}

	l := &Listener{transport: utrans, peers: make(map[string]*Peer), readQueue: make(chan *msg, 128)}
	go receiver(l)
	return l, nil
}

func receiver(l *Listener) {
	common.LogInfo("[%s][%s] receiver started", l.transport.Type(), l.transport.Local())
	for {
		data, peer, err := l.transport.ReadPacket()
		if err != nil {
			common.LogWarn("[%s][%s] failed to read packet: %s", l.transport.Type(), l.transport.Local(), err.Error())
			break
		}
		l.mux.Lock()
		p, found := l.peers[peer.String()]
		l.mux.Unlock()
		if !found {
			//this is where server code will go
			common.LogInfo("[%s][%s] received from unknown peer %s", l.transport.Type(), l.transport.Local(), peer.String())
			p, _ = l.addServerPeer(peer)
		}
		if !p.session.IsHandshakeDone() {
			if err := p.session.ProcessHandshakePacket(data); err != nil {
				if p.session.Type == session.TypeServer {
					l.mux.Lock()
					delete(l.peers, peer.String())
					l.mux.Unlock()
				}
				common.LogWarn("[%s][%s] failed to complete handshake for %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), err.Error())
			}
		} else {
			for {
				rec, rem, err := p.session.ParseRecord(data)
				if err == nil {
					if p.queue != nil {
						p.queue <- rec.Data
					} else {
						l.readQueue <- &msg{rec.Data, p}
					}
					//TODO handle case where queue is full and not being read
				} else {
					common.LogWarn("[%s][%s] failed to decrypt packet from %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), err.Error())
				}
				if rem == nil {
					return
				} else {
					data = rem
				}
			}
		}

	}
	common.LogInfo("[%s][%s] receiver stopped", l.transport.Type(), l.transport.Local())
}

func (l *Listener) addServerPeer(tpeer transport.Peer) (*Peer, error) {
	peer := &Peer{peer: tpeer}
	peer.session = session.NewServerSession(peer.peer)
	l.mux.Lock()
	l.peers[peer.peer.String()] = peer
	l.mux.Unlock()
	return peer, nil
}

func (l *Listener) AddPeer(addr string, identity string) (*Peer, error) {
	peer := &Peer{peer: l.transport.NewPeer(addr)}
	peer.UseQueue(true)
	peer.session = session.NewClientSession(peer.peer)
	peer.session.Client.Identity = identity
	l.mux.Lock()
	l.peers[peer.peer.String()] = peer
	l.mux.Unlock()
	peer.session.StartHandshake()
	if err := peer.session.WaitForHandshake(time.Second * 30); err != nil {
		l.mux.Lock()
		delete(l.peers, peer.peer.String())
		l.mux.Unlock()
		return nil, err
	}
	return peer, nil
}

func (l *Listener) Read() ([]byte, *Peer) {
	msg := <-l.readQueue

	return msg.data, msg.peer
}
