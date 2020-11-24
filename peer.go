package dtls

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"
	"unicode/utf8"
)

type Peer struct {
	transport TransportEndpoint
	session   *session
	activity  time.Time
	queue     chan []byte
	mux       sync.Mutex
	name      string
}

func (p *Peer) SetName(name string) {
	p.name = name
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
	if p == nil {
		return ""
	}
	return p.transport.String()
}

func (p *Peer) SessionIdentity() []byte {
	return p.session.Identity
}

func (p *Peer) SessionIdentityString() string {
	if utf8.Valid(p.session.Identity) {
		return string(p.session.Identity)
	} else {
		return hex.EncodeToString(p.session.Identity)
	}
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
		return nil, errors.New("dtls: transport not in queue mode")
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
