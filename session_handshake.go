package dtls

import (
	"errors"
	"reflect"
	"time"
)

func (s *session) parseRecord(data []byte) (*record, []byte, error) {

	rec, rem, err := parseRecord(data)
	if err != nil {
		logWarn(s.peer.String(), "dtls: parse record: %s", err.Error())
		return nil, nil, err
	}

	if s.decrypt {
		if s.KeyBlock == nil {
			logWarn(s.peer.String(), "dtls: tried to decrypt but KeyBlock not initialized.")
			return nil, nil, errors.New("dtls: key block not initialized")
		}
		if len(rec.Data) < 8 {
			if rec.IsAlert() {
				// we were expecting encryption, but received an unencrypted alert message.
				logDebug(s.peer.String(), "dtls: read %s (rem:%d) (decrypted:not-applicable-alert)", rec.Print(), len(rem))
				return rec, rem, nil
			} else {
				logWarn(s.peer.String(), "dtls: data underflow, expected at least 8 bytes, but received %d.", len(rec.Data))
				return nil, nil, errors.New("dtls: data underflow, expected at least 8 bytes")
			}
		}
		var iv []byte
		var key []byte
		if s.Type == SessionType_Client {
			iv = s.KeyBlock.ServerIV
			key = s.KeyBlock.ServerWriteKey
		} else {
			iv = s.KeyBlock.ClientIV
			key = s.KeyBlock.ClientWriteKey
		}
		nonce := newNonceFromBytes(iv, rec.Data[:8])
		aad := newAad(rec.Epoch, rec.Sequence, uint8(rec.ContentType), uint16(len(rec.Data)-16))
		clearText, err := dataDecrypt(rec.Data[8:], nonce, key, aad, s.peer.String())
		if err != nil {
			if s.handshake.firstDecrypt {
				//callback that psk is invalid
				logWarn(s.peer.String(), "dtls: PSK is most likely invalid for identity: %s%s", s.Server.Identity, s.Client.Identity)
				s.handshake.firstDecrypt = false
			}
			if rec.IsHandshake() {
				logDebug(s.peer.String(), "dtls: read %s (rem:%d) (decrypted:not-applicable): %s", rec.Print(), len(rem), err.Error())
				return rec, rem, nil
			} else {
				logWarn(s.peer.String(), "dtls: read decryption error: %s", err.Error())
				return nil, nil, err
			}
		}

		rec.SetData(clearText)
	}

	logDebug(s.peer.String(), "dtls: read %s (rem:%d) (decrypted:%t)", rec.Print(), len(rem), s.decrypt)

	return rec, rem, nil
}

func (s *session) parseHandshake(data []byte) (*handshake, error) {
	hs, err := parseHandshake(data)
	s.updateHash(data)
	if err != nil {
		return nil, err
	}
	logDebug(s.peer.String(), "dtls: read %s", hs.Print())
	return hs, err
}

func (s *session) writeHandshake(hs *handshake) error {
	hs.Header.Sequence = s.handshake.seq
	s.handshake.seq += 1

	rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), hs.Bytes())

	s.updateHash(rec.Data)

	logDebug(s.peer.String(), "dtls: write (handshake) %s", hs.Print())

	return s.writeRecord(rec)
}

func (s *session) writeRecord(rec *record) error {
	if s.encrypt {
		var iv []byte
		var key []byte
		if s.Type == SessionType_Client {
			iv = s.KeyBlock.ClientIV
			key = s.KeyBlock.ClientWriteKey
		} else {
			iv = s.KeyBlock.ServerIV
			key = s.KeyBlock.ServerWriteKey
		}
		nonce := newNonce(iv, rec.Epoch, rec.Sequence)
		aad := newAad(rec.Epoch, rec.Sequence, uint8(rec.ContentType), uint16(len(rec.Data)))
		cipherText, err := dataEncrypt(rec.Data, nonce, key, aad, s.peer.String())
		if err != nil {
			return err
		}
		w := newByteWriter()
		w.PutUint16(rec.Epoch)
		w.PutUint48(rec.Sequence)
		w.PutBytes(cipherText)
		rec.SetData(w.Bytes())
		logDebug(s.peer.String(), "dtls: write (encrptyed) %s", rec.Print())
		return s.peer.WritePacket(rec.Bytes())
	} else {
		logDebug(s.peer.String(), "dtls: write (unencrypted) %s", rec.Print())
		return s.peer.WritePacket(rec.Bytes())
	}
}

func (s *session) generateCookie() {
	s.handshake.cookie = randomBytes(16)
}

func (s *session) startHandshake() error {
	reqHs := newHandshake(handshakeType_ClientHello)
	reqHs.ClientHello.Init(s.Client.Random, nil, s.cipherSuites, s.compressionMethods)

	err := s.writeHandshake(reqHs)
	if err != nil {
		return err
	}
	return nil
}

func (s *session) waitForHandshake(timeout time.Duration) error {
	if s.handshake.done == nil {
		return errors.New("dtls: handshake not in-progress")
	}
	select {
	case err := <-s.handshake.done:
		if s.handshake.state == "finished" {
			return nil
		} else {
			return err
		}
	case <-time.After(timeout):
		return errors.New("dtls: timed out waiting for handshake to complete")
	}
	return errors.New("dtls: unknown wait error")
}

func (s *session) processHandshakePacket(rspRec *record) error {
	var reqHs, rspHs *handshake
	var err error

	switch rspRec.ContentType {
	case ContentType_Handshake:
		rspHs, err = s.parseHandshake(rspRec.Data)
		if err != nil {
			return err
		}

		if s.isHandshakeDone() && rspHs.Header.HandshakeType != handshakeType_ClientHello {
			return errors.New("dtls: handshake packet received after handshake is complete")
		}

		switch rspHs.Header.HandshakeType {
		case handshakeType_ClientHello:
			cookie := rspHs.ClientHello.GetCookie()
			if len(cookie) == 0 {
				s.reset()
				s.generateCookie()
				s.sequenceNumber = uint64(rspHs.Header.Sequence)
				s.handshake.seq = rspHs.Header.Sequence
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
		case handshakeType_HelloVerifyRequest:
			if len(s.handshake.cookie) == 0 {
				s.handshake.cookie = rspHs.HelloVerifyRequest.GetCookie()
				s.resetHash()
				s.handshake.state = "recv-helloverifyrequest"
			} else {
				s.handshake.state = "failed"
				err = errors.New("dtls: received hello verify request, but already have cookie")
				break
			}
			s.handshake.state = "recv-helloverifyrequest"
		case handshakeType_ServerHello:
			s.Server.RandomTime, s.Server.Random = rspHs.ServerHello.GetRandom()
			s.Id = rspHs.ServerHello.GetSessionId()
			s.handshake.state = "recv-serverhello"
		case handshakeType_ClientKeyExchange:
			s.Client.Identity = string(rspHs.ClientKeyExchange.GetIdentity())
			psk := GetPskFromKeystore(s.Client.Identity, s.peer.String())
			if psk == nil {
				err = errors.New("dtls: no valid psk for identity")
				break
			}
			s.Psk = psk
			s.initKeyBlock()

			s.handshake.state = "recv-clientkeyexchange"

			//TODO fail here if identity isn't found
		case handshakeType_ServerKeyExchange:
			s.Server.Identity = string(rspHs.ServerKeyExchange.GetIdentity())
			s.handshake.state = "recv-serverkeyexchange"
		case handshakeType_ServerHelloDone:
			s.handshake.state = "recv-serverhellodone"
		case handshakeType_Finished:
			var label string
			if s.Type == SessionType_Client {
				label = "server"
			} else {
				label = "client"
			}
			if rspHs.Finished.Match(s.KeyBlock.MasterSecret, s.handshake.savedHash, label) {
				logDebug(s.peer.String(), "dtls: encryption matches, handshake complete")
			} else {
				s.handshake.state = "failed"
				err = errors.New("dtls: crypto verification failed")
				break
			}
			s.handshake.state = "finished"
			break
		default:
			logWarn(s.peer.String(), "dtls: invalid handshake type [%v] received", rspRec.ContentType)
			err = errors.New("dtls: bad handshake type")
			break
		}
	case ContentType_ChangeCipherSpec:
		s.decrypt = true
		s.handshake.firstDecrypt = true
		s.handshake.savedHash = s.getHash()
		s.handshake.state = "cipherchangespec"
	}

	if err == nil {
		switch s.handshake.state {
		case "recv-clienthello-initial":
			reqHs = newHandshake(handshakeType_HelloVerifyRequest)
			reqHs.HelloVerifyRequest.Init(s.handshake.cookie)
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
			s.resetHash()
		case "recv-clienthello":
			//TODO consider adding serverkeyexchange, not sure what to recommend as a server identity
			reqHs = newHandshake(handshakeType_ServerHello)
			reqHs.ServerHello.Init(s.Server.Random, s.Id)
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}

			reqHs = newHandshake(handshakeType_ServerHelloDone)
			reqHs.ServerHelloDone.Init()
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}

		case "recv-helloverifyrequest":
			reqHs = newHandshake(handshakeType_ClientHello)
			err = reqHs.ClientHello.Init(s.Client.Random, s.handshake.cookie, s.cipherSuites, s.compressionMethods)
			if err != nil {
				break
			}
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
		case "recv-serverhellodone":
			reqHs = newHandshake(handshakeType_ClientKeyExchange)
			if len(s.Server.Identity) > 0 {
				psk := GetPskFromKeystore(s.Server.Identity, s.peer.String())
				if len(psk) > 0 {
					s.Client.Identity = s.Server.Identity
					s.Psk = psk
				}
			}
			if len(s.Psk) == 0 {
				psk := GetPskFromKeystore(s.Client.Identity, s.peer.String())
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
			s.initKeyBlock()

			rec := newRecord(ContentType_ChangeCipherSpec, s.getEpoch(), s.getNextSequence(), []byte{0x01})
			s.incEpoch()
			err = s.writeRecord(rec)
			if err != nil {
				break
			}
			s.encrypt = true

			reqHs = newHandshake(handshakeType_Finished)
			reqHs.Finished.Init(s.KeyBlock.MasterSecret, s.getHash(), "client")
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
		case "finished":
			if s.Type == SessionType_Server {
				rec := newRecord(ContentType_ChangeCipherSpec, s.getEpoch(), s.getNextSequence(), []byte{0x01})
				s.incEpoch()
				err = s.writeRecord(rec)
				if err != nil {
					break
				}
				s.encrypt = true

				reqHs = newHandshake(handshakeType_Finished)
				reqHs.Finished.Init(s.KeyBlock.MasterSecret, s.getHash(), "server")
				err = s.writeHandshake(reqHs)
				if err != nil {
					break
				}
			}
		}
	}

	if err != nil {
		s.handshake.state = "failed"
		s.handshake.err = err
	FORERR:
		for {
			select {
			case s.handshake.done <- err:
				continue
			default:
				break FORERR
			}
		}
		return err
	} else {
		s.handshake.err = nil
	}
	if s.handshake.state == "finished" {
	FORFIN:
		for {
			select {
			case s.handshake.done <- nil:
				continue
			default:
				break FORFIN
			}
		}
	}

	return nil
}
