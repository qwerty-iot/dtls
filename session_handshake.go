package dtls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"time"
)

func (s *session) parseRecord(data []byte) (*record, []byte, error) {

	rec, rem, err := parseRecord(data)
	if err != nil {
		logWarn(s.peer, err, "dtls: parse record")
		return nil, nil, err
	}

	if s.decrypt && rec.IsHandshake() && rec.Data[0] == 0x01 {
		logDebug(s.peer, "dtls: client hello received on established session.")
	} else if s.decrypt {
		if s.keyBlock == nil {
			logWarn(s.peer, nil, "dtls: tried to decrypt but keyBlock not initialized.")
			return nil, nil, errors.New("dtls: key block not initialized")
		}
		if len(rec.Data) < 8 {
			if rec.IsAlert() {
				// we were expecting encryption, but received an unencrypted alert message.
				logDebug(s.peer, "dtls: read %s (rem:%d) (decrypted:not-applicable-alert)", rec.Print(), len(rem))
				return rec, rem, nil
			} else {
				logWarn(s.peer, nil, "dtls: data underflow, expected at least 8 bytes, but received %d.", len(rec.Data))
				return nil, nil, errors.New("dtls: data underflow, expected at least 8 bytes")
			}
		}
		var iv []byte
		var key []byte
		var mac []byte
		if s.Type == SessionType_Client {
			iv = s.keyBlock.ServerIV
			key = s.keyBlock.ServerWriteKey
			mac = s.keyBlock.ServerMac
		} else {
			iv = s.keyBlock.ClientIV
			key = s.keyBlock.ClientWriteKey
			mac = s.keyBlock.ClientMac
		}

		clearText, err := s.cipher.Decrypt(rec, key, iv, mac)
		if err != nil {
			if s.handshake.firstDecrypt {
				//callback that psk is invalid
				logWarn(s.peer, nil, "dtls: PSK is most likely invalid for identity: %s", s.Identity)
				s.handshake.firstDecrypt = false
			}
			if rec.IsHandshake() {
				logDebug(s.peer, "dtls: read %s (rem:%d) (decrypted:not-applicable): %s", rec.Print(), len(rem), err.Error())
				return rec, rem, nil
			} else {
				logWarn(s.peer, err, "dtls: read decryption error")
				return nil, nil, err
			}
		}
		if s.handshake.firstDecrypt {
			s.handshake.firstDecrypt = false
		}

		rec.SetData(clearText)
	}

	logDebug(s.peer, "dtls: read %s (rem:%d) (decrypted:%t)", rec.Print(), len(rem), s.decrypt)

	return rec, rem, nil
}

func (s *session) parseHandshake(data []byte) (*handshake, error) {
	hs, err := parseHandshake(data)
	s.updateHash(data)
	if err != nil {
		return nil, err
	}
	logDebug(s.peer, "dtls: read %s", hs.Print())
	return hs, err
}

func (s *session) writeHandshake(hs *handshake) error {
	hs.Header.Sequence = s.handshake.seq
	s.handshake.seq += 1

	rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), hs.Bytes())

	s.updateHash(rec.Data)

	logDebug(s.peer, "dtls: write (handshake) %s", hs.Print())

	return s.writeRecord(rec)
}

func (s *session) writeHandshakes(hss []*handshake) error {
	recs := make([]*record, len(hss))
	for idx, hs := range hss {
		hs.Header.Sequence = s.handshake.seq
		s.handshake.seq += 1

		rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), hs.Bytes())

		s.updateHash(rec.Data)

		logDebug(s.peer, "dtls: write (handshake) %s", hs.Print())
		recs[idx] = rec
	}
	return s.writeRecords(recs)
}

func (s *session) writeRecord(rec *record) error {
	if s.encrypt {
		var iv []byte
		var key []byte
		var mac []byte
		if s.Type == SessionType_Client {
			iv = s.keyBlock.ClientIV
			key = s.keyBlock.ClientWriteKey
			mac = s.keyBlock.ClientMac
		} else {
			iv = s.keyBlock.ServerIV
			key = s.keyBlock.ServerWriteKey
			mac = s.keyBlock.ServerMac
		}
		cipherText, err := s.cipher.Encrypt(rec, key, iv, mac)
		if err != nil {
			return err
		}
		rec.SetData(cipherText)
		logDebug(s.peer, "dtls: write (encrptyed) %s", rec.Print())
		return s.peer.transport.WritePacket(rec.Bytes())
	} else {
		logDebug(s.peer, "dtls: write (unencrypted) %s", rec.Print())
		return s.peer.transport.WritePacket(rec.Bytes())
	}
}

func (s *session) writeRecords(recs []*record) error {
	if s.encrypt {
		return errors.New("dtls: can't write multiple encrypted records.")
	} else {
		buf := bytes.Buffer{}
		for _, rec := range recs {
			logDebug(s.peer, "dtls: write (unencrypted) %s", rec.Print())
			buf.Write(rec.Bytes())
		}
		return s.peer.transport.WritePacket(buf.Bytes())
	}
}

func (s *session) generateCookie() {
	s.handshake.cookie = randomBytes(16)
}

func (s *session) startHandshake() error {
	reqHs := newHandshake(handshakeType_ClientHello)
	reqHs.ClientHello.Init(s.Id, s.client.Random, nil, s.listener.cipherSuites, s.listener.compressionMethods)

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
				s.started = time.Now()
			} else {
				if !reflect.DeepEqual(cookie, s.handshake.cookie) {
					s.handshake.state = "failed"
					err = errors.New("dtls: cookie in clienthello does not match")
					break
				}
				s.client.RandomTime, s.client.Random = rspHs.ClientHello.GetRandom()
				if rspHs.ClientHello.HasSessionId() {
					//resuming a session
					s.Identity = getIdentityFromCache(rspHs.ClientHello.GetSessionIdStr())
					if len(s.Identity) > 0 {
						s.Id = rspHs.ClientHello.GetSessionId()
						logDebug(s.peer, "dtls: resuming previously established session, set identity: %s", s.Identity)
						s.resumed = true

						psk := GetPskFromKeystore(s.Identity, s.peer.RemoteAddr())
						if psk == nil {
							err = errors.New("dtls: no valid psk for identity")
							break
						}
						s.Psk = psk
						s.initKeyBlock()

					} else {
						logDebug(s.peer, "dtls: tried to resume session, but it was not found")
						s.resumed = false
					}
				} else {
					s.resumed = false
				}
				s.selectedCipherSuite = rspHs.ClientHello.SelectCipherSuite(s.listener.cipherSuites)
				s.cipher = getCipher(s.peer, s.selectedCipherSuite)
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
			s.server.RandomTime, s.server.Random = rspHs.ServerHello.GetRandom()
			if reflect.DeepEqual(s.Id, rspHs.ServerHello.GetSessionId()) {
				//resuming session
				s.resumed = true
			} else {
				s.Id = rspHs.ServerHello.GetSessionId()
			}
			s.selectedCipherSuite = rspHs.ServerHello.cipherSuite
			s.cipher = getCipher(s.peer, s.selectedCipherSuite)
			s.handshake.state = "recv-serverhello"
		case handshakeType_ClientKeyExchange:
			s.Identity = string(rspHs.ClientKeyExchange.GetIdentity())
			psk := GetPskFromKeystore(s.Identity, s.peer.RemoteAddr())
			if psk == nil {
				err = errors.New("dtls: no valid psk for identity")
				break
			}
			s.Psk = psk
			s.initKeyBlock()

			s.handshake.state = "recv-clientkeyexchange"

			//TODO fail here if identity isn't found
		case handshakeType_ServerKeyExchange:
			s.Identity = string(rspHs.ServerKeyExchange.GetIdentity())
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
			if rspHs.Finished.Match(s.keyBlock.MasterSecret, s.handshake.savedHash, label) {
				if s.Type == SessionType_Server {
					setIdentityToCache(hex.EncodeToString(s.Id), s.Identity)
				}
				logDebug(s.peer, "dtls: encryption matches, handshake complete")
			} else {
				s.handshake.state = "failed"
				err = errors.New("dtls: crypto verification failed")
				break
			}
			s.handshake.state = "finished"
			break
		default:
			logWarn(s.peer, nil, "dtls: invalid handshake type [%v] received", rspRec.ContentType)
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
			reqHs.ServerHello.Init(s.server.Random, s.Id, s.selectedCipherSuite)

			reqHs2 := newHandshake(handshakeType_ServerHelloDone)
			reqHs2.ServerHelloDone.Init()

			err = s.writeHandshakes([]*handshake{reqHs, reqHs2})
			if err != nil {
				break
			}
		case "recv-helloverifyrequest":
			reqHs = newHandshake(handshakeType_ClientHello)
			err = reqHs.ClientHello.Init(s.Id, s.client.Random, s.handshake.cookie, s.listener.cipherSuites, s.listener.compressionMethods)
			if err != nil {
				break
			}
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
		case "recv-serverhellodone":

			if len(s.Identity) > 0 {
				psk := GetPskFromKeystore(s.Identity, s.peer.RemoteAddr())
				if len(psk) > 0 {
					s.Psk = psk
				} else {
					err = errors.New("dtls: no psk could be found")
					break
				}
			}

			if !s.resumed {
				reqHs = newHandshake(handshakeType_ClientKeyExchange)

				reqHs.ClientKeyExchange.Init([]byte(s.Identity))
				err = s.writeHandshake(reqHs)
				if err != nil {
					break
				}
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
			reqHs.Finished.Init(s.keyBlock.MasterSecret, s.getHash(), "client")
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
				reqHs.Finished.Init(s.keyBlock.MasterSecret, s.getHash(), "server")
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
		if HandshakeCompleteCallback != nil {
			HandshakeCompleteCallback(s.peer, s.Identity, time.Now().Sub(s.started), err)
		}
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
		if HandshakeCompleteCallback != nil {
			HandshakeCompleteCallback(s.peer, s.Identity, time.Now().Sub(s.started), nil)
		}
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
