package dtls

import (
	"errors"
	"time"
)

type Peer struct {
	peer    TransportPeer
	session *session
	queue   chan []byte
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

func (p *Peer) Close() {
	rec := newRecord(ContentType_Alert, p.session.getEpoch(), p.session.getNextSequence(), newAlert(AlertType_Fatal, AlertDesc_CloseNotify).Bytes())
	p.session.writeRecord(rec)
}

func (p *Peer) Write(data []byte) error {
	rec := newRecord(ContentType_Appdata, p.session.getEpoch(), p.session.getNextSequence(), data)
	return p.session.writeRecord(rec)
}

func (p *Peer) Read(timeout time.Duration) ([]byte, error) {
	if p.queue == nil {
		return nil, errors.New("dtls: peer not in queue mode")
	}
	select {
	case b := <-p.queue:
		return b, nil
	case <-time.After(timeout):
		return nil, errors.New("dtls: queued read timed out")
	}
	return nil, nil
}
