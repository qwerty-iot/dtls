package dtls

import (
	"errors"
	"sync"
	"time"
)

type Listener struct {
	transport          Transport
	peers              map[string]*Peer
	readQueue          chan *msg
	mux                sync.Mutex
	wg                 sync.WaitGroup
	isShutdown         bool
	cipherSuites       []CipherSuite
	compressionMethods []CompressionMethod
}

type msg struct {
	data []byte
	peer *Peer
}

func NewUdpListener(listener string, readTimeout time.Duration) (*Listener, error) {
	utrans, err := newUdpTransport(listener, readTimeout)
	if err != nil {
		return nil, err
	}

	l := &Listener{transport: utrans, peers: make(map[string]*Peer), readQueue: make(chan *msg, 128)}
	l.wg.Add(1)
	go receiver(l)
	return l, nil
}

func receiver(l *Listener) {
	if l.isShutdown {
		logDebug("dtls: [%s][%s] receiver shutting down", l.transport.Type(), l.transport.Local())
		l.wg.Done()
		return
	}
	logDebug("dtls: [%s][%s] waiting for packet", l.transport.Type(), l.transport.Local())
	data, peer, err := l.transport.ReadPacket()
	if err != nil {
		logError("[%s][%s] failed to read packet: %s", l.transport.Type(), l.transport.Local(), err.Error())
		l.wg.Done()
		return
	}

	l.mux.Lock()
	p, found := l.peers[peer.String()]
	l.mux.Unlock()
	if !found {
		//this is where server code will go
		logInfo("dtls: [%s][%s] received from unknown peer %s", l.transport.Type(), l.transport.Local(), peer.String())
		p, _ = l.addServerPeer(peer)
	} else {
		logInfo("dtls: [%s][%s] received from peer %s", l.transport.Type(), l.transport.Local(), peer.String())
	}

	for {
		rec, rem, err := p.session.parseRecord(data)
		if err != nil {
			logWarn("dtls: [%s][%s] error parsing record from %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), err.Error())
			l.RemovePeer(p, AlertDesc_DecodeError)
			break
		}

		if rec.IsHandshake() {
			if !p.session.isHandshakeDone() {
				logDebug("dtls: [%s][%s] handshake in progress from %s", l.transport.Type(), l.transport.Local(), peer.String())
				if err := p.session.processHandshakePacket(rec); err != nil {
					l.RemovePeer(p, AlertDesc_HandshakeFailure)
					logWarn("dtls: [%s][%s] failed to complete handshake for %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), err.Error())
				}
			} else {
				l.RemovePeer(p, AlertDesc_HandshakeFailure)
				logWarn("dtls: [%s][%s] received handshake message after handshake is complete for %s", l.transport.Type(), l.transport.Local(), peer.String())
			}
		} else if rec.IsAlert() {
			//handle alert
			alert, err := parseAlert(rec.Data)
			if err != nil {
				l.RemovePeer(p, AlertDesc_DecodeError)
				logWarn("dtls: [%s][%s] failed to parse alert for %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), err.Error())
			}
			if alert.Type == AlertType_Warning {
				logInfo("dtls: [%s][%s] received warning alert from %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), alertDescToString(alert.Desc))
			} else {
				l.RemovePeer(p, AlertDesc_Noop)
				logWarn("dtls: [%s][%s] received fatal alert from %s: %s", l.transport.Type(), l.transport.Local(), peer.String(), alertDescToString(alert.Desc))
			}
		} else if rec.IsAppData() && !p.session.isHandshakeDone() {
			l.RemovePeer(p, AlertDesc_DecryptError)
			logWarn("dtls: [%s][%s] received app data message without completing handshake for %s", l.transport.Type(), l.transport.Local(), peer.String())
		} else {
			if p.queue != nil {
				p.queue <- rec.Data
			} else {
				l.readQueue <- &msg{rec.Data, p}
			}
			//TODO handle case where queue is full and not being read
		}
		if rem == nil {
			break
		} else {
			data = rem
		}
	}

	l.wg.Add(1)
	go receiver(l)
	l.wg.Done()
	//TODO need to queue records for each session so that we can process multiple in parallel
}

func (l *Listener) RemovePeer(peer *Peer, alertDesc uint8) error {
	l.mux.Lock()
	if alertDesc != AlertDesc_Noop {
		peer.Close(alertDesc)
	}
	delete(l.peers, peer.RemoteAddr())
	l.mux.Unlock()
	return nil
}

func (l *Listener) addServerPeer(tpeer TransportPeer) (*Peer, error) {
	peer := &Peer{peer: tpeer}
	peer.session = newServerSession(peer.peer)
	if l.cipherSuites != nil {
		peer.session.cipherSuites = l.cipherSuites
	}
	if l.compressionMethods != nil {
		peer.session.compressionMethods = l.compressionMethods
	}
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
	return l.AddPeerWithParams(&PeerParams{Addr: addr, Identity: identity, HandshakeTimeout: time.Second * 20})
}

func (l *Listener) AddPeerWithParams(params *PeerParams) (*Peer, error) {
	peer := &Peer{peer: l.transport.NewPeer(params.Addr)}
	peer.UseQueue(true)
	peer.session = newClientSession(peer.peer)
	if l.cipherSuites != nil {
		peer.session.cipherSuites = l.cipherSuites
	}
	if l.compressionMethods != nil {
		peer.session.compressionMethods = l.compressionMethods
	}
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

func (l *Listener) Shutdown() error {
	l.isShutdown = true
	//gracefully send alerts to each connected peer
	err := l.transport.Shutdown()
	l.wg.Wait()
	return err
}

func (l *Listener) AddCipherSuite(cipherSuite CipherSuite) {
	if l.cipherSuites == nil {
		l.cipherSuites = make([]CipherSuite, 0, 4)
	}
	l.cipherSuites = append(l.cipherSuites, cipherSuite)
	return
}

func (l *Listener) AddCompressionMethod(compressionMethod CompressionMethod) {
	if l.compressionMethods == nil {
		l.compressionMethods = make([]CompressionMethod, 0, 4)
	}
	l.compressionMethods = append(l.compressionMethods, compressionMethod)
	return
}

func (l *Listener) FindPeer(addr string) (*Peer, error) {
	l.mux.Lock()
	p, found := l.peers[addr]
	l.mux.Unlock()
	if found {
		return p, nil
	} else {
		return nil, errors.New("dtls: Peer [" + addr + "] not found.")
	}
}

func (l *Listener) CountPeers() int {
	var count int
	l.mux.Lock()
	count = len(l.peers)
	l.mux.Unlock()
	return count
}
