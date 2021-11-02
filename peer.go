// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync"
	"time"
	"unicode/utf8"
)

type Peer struct {
	transport      TransportEndpoint
	session        *session
	activity       time.Time
	queue          chan []byte
	mux            sync.Mutex
	name           string
	transportQueue chan []byte
	processor      bool
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
	return p.session.peerIdentity
}

func (p *Peer) SessionIdentityString() string {
	if utf8.Valid(p.session.peerIdentity) {
		return string(p.session.peerIdentity)
	} else {
		return hex.EncodeToString(p.session.peerIdentity)
	}
}

func (p *Peer) SessionPublicKey() []byte {
	if p.session.peerPublicKey != nil && len(p.session.peerPublicKey) != 0 {
		return p.session.peerPublicKey
	}
	return nil
}

func (p *Peer) SessionCertificate() *x509.Certificate {
	if p.session.peerCert != nil {
		return p.session.peerCert
	}
	return nil
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

func (p *Peer) SessionExport() string {
	if p.session != nil && p.session.isHandshakeDone() {
		return p.session.export()
	} else {
		return ""
	}
}

func (p *Peer) Lock() {
	p.mux.Lock()
}

func (p *Peer) Unlock() {
	p.mux.Unlock()
}
