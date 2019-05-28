package dtls

import (
	"errors"
	"sync"
	"time"
)

type Peer struct {
	peer     TransportPeer
	session  *session
	activity time.Time
	queue    chan []byte
	mux      sync.Mutex
}

func (p *Peer) UseQueue(en bool) {
	if en {
		p.queue = make(chan []byte, 128)
	} else {
		if p.queue != nil {
			q := p.queue
			p.queue = nil
			close(q)
		}
	}
}

func (p *Peer) RemoteAddr() string {
	return p.peer.String()
}

func (p *Peer) SessionIdentity() string {
	return p.session.Client.Identity
}

func (p *Peer) LastActivity() time.Time {
	return p.activity
}

func (p *Peer) Close(alertDesc uint8) {
	rec := newRecord(ContentType_Alert, p.session.getEpoch(), p.session.getNextSequence(), newAlert(AlertType_Fatal, alertDesc).Bytes())
	p.activity = time.Now()
	_ = p.session.writeRecord(rec)
}

func (p *Peer) Write(data []byte) error {
	p.activity = time.Now()
	rec := newRecord(ContentType_Appdata, p.session.getEpoch(), p.session.getNextSequence(), data)
	return p.session.writeRecord(rec)
}

func (p *Peer) Read(timeout time.Duration) ([]byte, error) {
	if p.queue == nil {
		return nil, errors.New("dtls: peer not in queue mode")
	}
	select {
	case b := <-p.queue:
		p.activity = time.Now()
		return b, nil
	case <-time.After(timeout):
		return nil, errors.New("dtls: queued read timed out")
	}
}

func (p *Peer) Lock() {
	p.mux.Lock()
}

func (p *Peer) Unlock() {
	p.mux.Unlock()
}
