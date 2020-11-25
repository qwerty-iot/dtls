// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

var PeerInactivityTimeout = time.Hour * 24

type msg struct {
	data []byte
	peer *Peer
}

// This callback is invoked each time a handshake completes, if the handshake failed, the reason is stored in error
var HandshakeCompleteCallback func(*Peer, []byte, time.Duration, error)

func NewUdpListener(listener string, readTimeout time.Duration) (*Listener, error) {
	utrans, err := newUdpTransport(listener, readTimeout)
	if err != nil {
		return nil, err
	}

	l := &Listener{transport: utrans, peers: make(map[string]*Peer), readQueue: make(chan *msg, 128)}
	go sweeper(l)
	l.wg.Add(1)
	go receiver(l)
	return l, nil
}

func receiver(l *Listener) {
	if l.isShutdown {
		logDebug(nil, nil, "receiver shutting down")
		l.wg.Done()
		return
	}
	data, peer, err := l.transport.ReadPacket()
	if err != nil {
		logError(nil, nil, err, "failed to read packet")
		l.wg.Done()
		return
	}

	l.wg.Add(1)
	go receiver(l)

	l.mux.Lock()
	p, found := l.peers[peer.String()]

	if !found {
		//this is where server code will go
		p, _ = l.addServerPeer(peer)
		logDebug(p, nil, "received from unknown endpoint")
	} else {
		logDebug(p, nil, "received from endpoint")
	}
	l.mux.Unlock()

	p.Lock()

	for {
		rec, rem, err := p.session.parseRecord(data)
		if err != nil {
			logWarn(p, rec, err, "error parsing record")
			l.RemovePeer(p, AlertDesc_DecodeError)
			break
		}

		if rec.IsHandshake() {
			logDebug(p, rec, "handshake received")
			if err := p.session.processHandshakePacket(rec); err != nil {
				l.RemovePeer(p, AlertDesc_HandshakeFailure)
				logWarn(p, rec, err, "failed to complete handshake")
			}
		} else if rec.IsAlert() {
			//handle alert
			alert, err := parseAlert(rec.Data)
			if err != nil {
				l.RemovePeer(p, AlertDesc_DecodeError)
				logWarn(p, rec, err, "failed to parse alert")
			}
			if alert.Type == AlertType_Warning {
				logWarn(p, nil, nil, "received warning alert: %s", alertDescToString(alert.Desc))
			} else {
				l.RemovePeer(p, AlertDesc_Noop)
				logWarn(p, nil, nil, "received fatal alert: %s", alertDescToString(alert.Desc))
			}
		} else if rec.IsAppData() && !p.session.isHandshakeDone() {
			l.RemovePeer(p, AlertDesc_DecryptError)
			logWarn(p, nil, nil, "received app data message without completing handshake")
		} else {
			if p.queue != nil {
				p.queue <- rec.Data
			} else {
				l.readQueue <- &msg{rec.Data, p}
			}
			//TODO handle case where queue is full and not being read
		}
		if rem == nil || len(rem) == 0 {
			break
		} else {
			data = rem
		}
	}

	p.Unlock()

	l.wg.Done()
	//TODO need to queue records for each session so that we can process multiple in parallel
}

func sweeper(l *Listener) {
	for {
		if l.isShutdown {
			logDebug(nil, nil, "sweeper shutting down")
			return
		}
		expiry := time.Now().Add(PeerInactivityTimeout * -1)
		for _, peer := range l.peers {
			if peer.activity.Before(expiry) {
				logDebug(peer, nil, "sweeper removing peer")
				l.RemovePeer(peer, AlertDesc_Noop)
			}
		}
		time.Sleep(time.Minute)
	}
}

func (l *Listener) RemovePeer(peer *Peer, alertDesc uint8) {
	l.mux.Lock()
	if alertDesc != AlertDesc_Noop {
		peer.Close(alertDesc)
	}
	delete(l.peers, peer.RemoteAddr())
	l.mux.Unlock()
	return
}

func (l *Listener) RemovePeerByAddr(addr string, alertDesc uint8) {
	l.mux.Lock()
	p, found := l.peers[addr]
	if found {
		if alertDesc != AlertDesc_Noop {
			p.Close(alertDesc)
		}
		delete(l.peers, p.RemoteAddr())
	}
	l.mux.Unlock()
	return
}

func (l *Listener) addServerPeer(tpeer TransportEndpoint) (*Peer, error) {
	peer := &Peer{transport: tpeer}
	peer.session = newServerSession(peer)
	peer.session.listener = l
	//disabled lock because it is included in the existing lock
	//l.mux.Lock()
	l.peers[peer.RemoteAddr()] = peer
	//l.mux.Unlock()
	return peer, nil
}

type PeerParams struct {
	Addr             string
	Identity         []byte
	HandshakeTimeout time.Duration
	SessionId        []byte
}

func (l *Listener) AddPeer(addr string, identity []byte) (*Peer, error) {
	return l.AddPeerWithParams(&PeerParams{Addr: addr, Identity: identity, HandshakeTimeout: time.Second * 20})
}

func (l *Listener) AddPeerWithParams(params *PeerParams) (*Peer, error) {
	peer := &Peer{transport: l.transport.NewEndpoint(params.Addr), activity: time.Now()}
	peer.UseQueue(true)
	peer.session = newClientSession(peer)
	peer.name = peer.RemoteAddr()
	peer.session.listener = l
	peer.session.Identity = params.Identity
	if params.SessionId != nil && len(params.SessionId) != 0 {
		peer.session.Id = params.SessionId
	}
	l.mux.Lock()
	l.peers[peer.RemoteAddr()] = peer
	l.mux.Unlock()
	err := peer.session.startHandshake()
	if err != nil {
		l.mux.Lock()
		delete(l.peers, peer.RemoteAddr())
		l.mux.Unlock()
		logWarn(peer, nil, err, "failed to start handshake")
		return nil, err
	}
	if err := peer.session.waitForHandshake(params.HandshakeTimeout); err != nil {
		l.mux.Lock()
		delete(l.peers, peer.RemoteAddr())
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
	//gracefully send alerts to each connected transport
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
		return nil, errors.New("dtls: peer [" + addr + "] not found")
	}
}

func (l *Listener) CountPeers() int {
	var count int
	l.mux.Lock()
	count = len(l.peers)
	l.mux.Unlock()
	return count
}
