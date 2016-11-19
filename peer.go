package dtls

import (
	"errors"
	"time"

	"github.com/bocajim/dtls/record"
	"github.com/bocajim/dtls/session"
	"github.com/bocajim/dtls/transport"
)

type Peer struct {
	peer    transport.Peer
	session *session.Session
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

func (p *Peer) Write(data []byte) error {
	rec := record.New(record.ContentType_Appdata)
	rec.Epoch = p.session.GetEpoch()
	rec.Sequence = p.session.GetNextSequence()
	rec.SetData(data)
	return p.session.WriteRecord(rec)
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
