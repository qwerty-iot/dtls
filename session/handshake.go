package session

import (
	"errors"
	"reflect"
	"time"

	"github.com/bocajim/dtls/common"
	"github.com/bocajim/dtls/crypto"
	"github.com/bocajim/dtls/handshake"
	"github.com/bocajim/dtls/keystore"
	"github.com/bocajim/dtls/record"
)

func (s *Session) ParseRecord(data []byte) (*record.Record, []byte, error) {

	rec, rem, err := record.ParseRecord(data)
	if err != nil {
		common.LogWarn("dtls: [%s] parse record: %s", s.peer.String(), err.Error())
		return nil, nil, err
	}

	common.LogDebug("dtls: [%s] read %s", s.peer.String(), rec.Print())

	if s.decrypt {
		var iv []byte
		var key []byte
		if s.Type == TypeClient {
			iv = s.KeyBlock.ServerIV
			key = s.KeyBlock.ServerWriteKey
		} else {
			iv = s.KeyBlock.ClientIV
			key = s.KeyBlock.ClientWriteKey
		}
		nonce := crypto.CreateNonce(iv, rec.Epoch, rec.Sequence)
		aad := crypto.CreateAad(rec.Epoch, rec.Sequence, uint8(rec.ContentType), uint16(len(rec.Data)-16))
		clearText, err := crypto.PayloadDecrypt(rec.Data[8:], nonce, key, aad, s.peer.String())
		if err != nil {
			return nil, nil, err
		}
		rec.SetData(clearText)
	}

	return rec, rem, nil
}

func (s *Session) parseHandshake(data []byte) (*handshake.Handshake, *record.Record, []byte, error) {
	rec, rem, err := s.ParseRecord(data)
	if err != nil {
		return nil, nil, nil, err
	}
	if !rec.IsHandshake() {
		return nil, rec, rem, nil
		//return nil, nil, errors.New("dtls: response is not a handshake")
	}
	hs, err := handshake.ParseHandshake(rec.Data)
	s.UpdateHash(rec.Data)
	if err != nil {
		return nil, nil, rem, err
	}
	common.LogDebug("dtls: [%s] read %s", s.peer.String(), hs.Print())
	return hs, rec, rem, err
}

func (s *Session) writeHandshake(hs *handshake.Handshake) error {
	rec := record.New(record.ContentType_Handshake)
	rec.Epoch = s.GetEpoch()
	rec.Sequence = s.GetNextSequence()
	hs.Header.Sequence = s.handshake.seq
	s.handshake.seq += 1
	rec.SetData(hs.Bytes())

	s.UpdateHash(rec.Data)

	common.LogDebug("dtls: [%s] write %s", s.peer.String(), hs.Print())

	return s.WriteRecord(rec)
}

func (s *Session) WriteRecord(rec *record.Record) error {
	if s.encrypt {
		var iv []byte
		var key []byte
		if s.Type == TypeClient {
			iv = s.KeyBlock.ClientIV
			key = s.KeyBlock.ClientWriteKey
		} else {
			iv = s.KeyBlock.ServerIV
			key = s.KeyBlock.ServerWriteKey
		}
		nonce := crypto.CreateNonce(iv, rec.Epoch, rec.Sequence)
		aad := crypto.CreateAad(rec.Epoch, rec.Sequence, uint8(rec.ContentType), uint16(len(rec.Data)))
		cipherText, err := crypto.PayloadEncrypt(rec.Data, nonce, key, aad, s.peer.String())
		if err != nil {
			return err
		}
		w := common.NewWriter()
		w.PutUint16(rec.Epoch)
		w.PutUint48(rec.Sequence)
		w.PutBytes(cipherText)
		rec.SetData(w.Bytes())
		common.LogDebug("dtls: [%s] write %s", s.peer.String(), rec.Print())
		return s.peer.WritePacket(rec.Bytes())
	} else {
		common.LogDebug("dtls: [%s] write %s", s.peer.String(), rec.Print())
		return s.peer.WritePacket(rec.Bytes())
	}
}

func (s *Session) generateCookie() {
	s.handshake.cookie = common.RandomBytes(16)
}

func (s *Session) StartHandshake() error {
	reqHs := handshake.New(handshake.Type_ClientHello)
	reqHs.ClientHello.Init(s.Client.Random, nil)

	s.handshake.done = make(chan bool)

	err := s.writeHandshake(reqHs)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) WaitForHandshake(timeout time.Duration) error {
	if s.handshake.done == nil {
		return errors.New("dtls: handshake not in-progress")
	}
	select {
	case <-s.handshake.done:
		if s.handshake.state == "finished" {
			return nil
		} else {
			return errors.New("dtls: handshake failed while in state [" + s.handshake.state + "]")
		}
	case <-time.After(timeout):
		return errors.New("dtls: timed out waiting for handshake to complete")
	}
	return errors.New("dtls: unknown wait error")
}

func (s *Session) ProcessHandshakePacket(data []byte) error {
	var reqHs, rspHs *handshake.Handshake
	var rspRec *record.Record
	var rem []byte
	var err error

	rspHs, rspRec, rem, err = s.parseHandshake(data)
	if err != nil {
		return err
	}

	switch rspRec.ContentType {
	case record.ContentType_Handshake:
		switch rspHs.Header.HandshakeType {
		case handshake.Type_ClientHello:
			cookie := rspHs.ClientHello.GetCookie()
			if len(cookie) == 0 {
				s.generateCookie()
				s.handshake.state = "recv-clienthello-initial"
			} else {
				if !reflect.DeepEqual(cookie, s.handshake.cookie) {
					s.handshake.state = "failed"
					err = errors.New("dtls: cookie in clienthello does not match")
					break
				}
				s.Client.RandomTime, s.Client.Random = rspHs.ClientHello.GetRandom()
				s.handshake.state = "recv-clienthello"
			}
		case handshake.Type_HelloVerifyRequest:
			if len(s.handshake.cookie) == 0 {
				s.handshake.cookie = rspHs.HelloVerifyRequest.GetCookie()
				s.ResetHash()
				s.handshake.state = "recv-helloverifyrequest"
			} else {
				s.handshake.state = "failed"
				if s.handshake.done != nil {
					s.handshake.done <- true
				}
				err = errors.New("dtls: received hello verify request, but already have cookie")
				break
			}
			s.handshake.state = "recv-helloverifyrequest"
		case handshake.Type_ServerHello:
			s.Server.RandomTime, s.Server.Random = rspHs.ServerHello.GetRandom()
			s.Id = rspHs.ServerHello.GetSessionId()
			s.handshake.state = "recv-serverhello"
		case handshake.Type_ClientKeyExchange:
			s.Client.Identity = string(rspHs.ClientKeyExchange.GetIdentity())
			psk := keystore.GetPsk(s.Client.Identity)
			if psk == nil {
				err = errors.New("dtls: no valid psk for identity")
				break
			}
			s.Psk = psk
			s.InitKeyBlock()

			s.handshake.state = "recv-clientkeyexchange"

			//TODO fail here if identity isn't found
		case handshake.Type_ServerKeyExchange:
			s.Server.Identity = string(rspHs.ServerKeyExchange.GetIdentity())
			s.handshake.state = "recv-serverkeyexchange"
		case handshake.Type_ServerHelloDone:
			s.handshake.state = "recv-serverhellodone"
		case handshake.Type_Finished:
			var label string
			if s.Type == TypeClient {
				label = "server"
			} else {
				label = "client"
			}
			if rspHs.Finished.Match(s.KeyBlock.MasterSecret, s.handshake.savedHash, label) {
				common.LogDebug("dtls: [%s] encryption matches, handshake complete", s.peer.String())
			} else {
				s.handshake.state = "failed"
				if s.handshake.done != nil {
					s.handshake.done <- true
				}
				err = errors.New("dtls: crypto verification failed")
				break
			}
			s.handshake.state = "finished"
			break
		}
	case record.ContentType_ChangeCipherSpec:
		s.decrypt = true
		s.handshake.savedHash = s.GetHash()
		s.handshake.state = "cipherchangespec"
	}

	if err == nil {
		switch s.handshake.state {
		case "recv-clienthello-initial":
			reqHs = handshake.New(handshake.Type_HelloVerifyRequest)
			reqHs.HelloVerifyRequest.Init(s.handshake.cookie)
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
			s.ResetHash()
		case "recv-clienthello":
			//TODO consider adding serverkeyexchange, not sure what to recommend as a server identity
			reqHs = handshake.New(handshake.Type_ServerHello)
			reqHs.ServerHello.Init(s.Server.Random, s.Id)
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}

			reqHs = handshake.New(handshake.Type_ServerHelloDone)
			reqHs.ServerHelloDone.Init()
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}

		case "recv-helloverifyrequest":
			reqHs = handshake.New(handshake.Type_ClientHello)
			reqHs.ClientHello.Init(s.Client.Random, s.handshake.cookie)
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
		case "recv-serverhellodone":
			reqHs = handshake.New(handshake.Type_ClientKeyExchange)
			if len(s.Server.Identity) > 0 {
				psk := keystore.GetPsk(s.Server.Identity)
				if len(psk) > 0 {
					s.Client.Identity = s.Server.Identity
					s.Psk = psk
				}
			}
			if len(s.Psk) == 0 {
				psk := keystore.GetPsk(s.Client.Identity)
				if len(psk) > 0 {
					s.Psk = psk
				} else {
					err = errors.New("dtls: no psk could be found")
					break
				}
			}
			reqHs.ClientKeyExchange.Init([]byte(s.Client.Identity))
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
			s.InitKeyBlock()

			rec := record.New(record.ContentType_ChangeCipherSpec)
			rec.Epoch = s.GetEpoch()
			rec.Sequence = s.GetNextSequence()
			s.IncEpoch()
			rec.SetData([]byte{0x01})
			err = s.WriteRecord(rec)
			if err != nil {
				break
			}
			s.encrypt = true

			reqHs = handshake.New(handshake.Type_Finished)
			reqHs.Finished.Init(s.KeyBlock.MasterSecret, s.GetHash(), "client")
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
		case "finished":
			if s.Type == TypeServer {
				rec := record.New(record.ContentType_ChangeCipherSpec)
				rec.Epoch = s.GetEpoch()
				rec.Sequence = s.GetNextSequence()
				s.IncEpoch()
				rec.SetData([]byte{0x01})
				err = s.WriteRecord(rec)
				if err != nil {
					break
				}
				s.encrypt = true

				reqHs = handshake.New(handshake.Type_Finished)
				reqHs.Finished.Init(s.KeyBlock.MasterSecret, s.GetHash(), "server")
				err = s.writeHandshake(reqHs)
				if err != nil {
					break
				}
			}
		}
	}

	if err != nil {
		s.handshake.state = "failed"
		if s.handshake.done != nil {
			s.handshake.done <- true
		}
		return err
	}
	if s.handshake.state == "finished" && s.handshake.done != nil {
		s.handshake.done <- true
	}

	if rem != nil {
		return s.ProcessHandshakePacket(rem)
	}
	return nil
}
