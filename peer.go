package dtls

import (
	"github.com/bocajim/dtls/record"
	"github.com/bocajim/dtls/session"
	"github.com/bocajim/dtls/transport"
)

type Peer struct {
	peer    transport.Peer
	session *session.Session
}

func (p *Peer) Write(data []byte) error {
	rec := record.New(record.ContentType_Appdata)
	rec.Epoch = p.session.GetEpoch()
	rec.Sequence = p.session.GetNextSequence()
	rec.SetData(data)
	return p.session.WriteRecord(rec)
}
