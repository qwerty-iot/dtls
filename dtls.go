package dtls

import (
	"sync"
	"time"
)

type Listener struct {
	transport Transport
	peers     map[string]*Peer
	readQueue chan *msg
	mux       sync.Mutex
}

type msg struct {
	data []byte
	peer *Peer
}

func NewUdpListener(listener string, readTimeout time.Duration) (*Listener, error) {
	utrans, err := NewUdpHandle(listener, readTimeout)
	if err != nil {
		return nil, err
	}

	l := &Listener{transport: utrans, peers: make(map[string]*Peer), readQueue: make(chan *msg, 128)}
	go receiver(l)
	return l, nil
}

func receiver(l *Listener) {
	logInfo("[%s][%s] receiver started", l.transport.Type(), l.transport.Local())
	for {
		data, peer, err := l.transport.ReadPacket()
		if err != nil {
			logWarn("[%s][%s] failed to read packet: %s", l.transport.Type(), l.transport.Local(), err.Error())
			break
		}
		l.mux.Lock()
		p, found := l.peers[peer.String()]
		l.mux.Unlock()
		if !found {
			//this is where server code will go
			logInfo("[%s][%s] received from unknown peer %s", l.transport.Type(), l.transport.Local(), peer.String())
			p, _ = l.addServerPeer(peer)
		} else {
			logInfo("[%s][%s] received from peer %s", l.transport.Type(), l.transport.Local(), peer.String())
		}
		if !p.session.isHandshakeDone() {
			if err := p.session.processHandshakePacket(data); err != nil {
				if p.session.Type == SessionType_Server {
					l.mux.Lock()
					delete(l.peers, peer.String())
					l.mux.Unlock()
				}
				logWarn("[%s][%s] failed to complete handshake for %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), err.Error())
			}
		} else {
			for {
				rec, rem, err := p.session.parseRecord(data)
				if err == nil {
					if p.queue != nil {
						p.queue <- rec.Data
					} else {
						l.readQueue <- &msg{rec.Data, p}
					}
					//TODO handle case where queue is full and not being read
				} else {
					logWarn("[%s][%s] failed to decrypt packet from %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), err.Error())
				}
				if rem == nil {
					return
				} else {
					data = rem
				}
			}
		}

	}
	logInfo("[%s][%s] receiver stopped", l.transport.Type(), l.transport.Local())
}

func (l *Listener) addServerPeer(tpeer TransportPeer) (*Peer, error) {
	peer := &Peer{peer: tpeer}
	peer.session = newServerSession(peer.peer)
	l.mux.Lock()
	l.peers[peer.peer.String()] = peer
	l.mux.Unlock()
	return peer, nil
}

type PeerParams struct {
	Addr             string
	Identity         string
	HandshakeTimeout time.Duration
}

func (l *Listener) AddPeer(addr string, identity string) (*Peer, error) {
	return l.AddPeerParams(&PeerParams{Addr: addr, Identity: identity, HandshakeTimeout: time.Second * 20})
}

func (l *Listener) AddPeerParams(params *PeerParams) (*Peer, error) {
	peer := &Peer{peer: l.transport.NewPeer(params.Addr)}
	peer.UseQueue(true)
	peer.session = newClientSession(peer.peer)
	peer.session.Client.Identity = params.Identity
	l.mux.Lock()
	l.peers[peer.peer.String()] = peer
	l.mux.Unlock()
	peer.session.startHandshake()
	if err := peer.session.waitForHandshake(params.HandshakeTimeout); err != nil {
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
