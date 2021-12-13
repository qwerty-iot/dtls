// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

func (s *session) parseRecord(data []byte) (*record, []byte, error) {

	rec, rem, err := parseRecord(data)
	if err != nil {
		if len(data) > 64 {
			logDebug(s.peer, nil, "dtls: bad packet: [%X](%d)", data[:64], len(data))
		} else {
			logDebug(s.peer, nil, "dtls: bad packet: [%X]", data)
		}

		logWarn(s.peer, nil, err, "dtls: parse record")
		return nil, nil, err
	}

	if s.decrypt && rec.IsHandshake() && rec.Epoch == 0 {
		logDebug(s.peer, nil, "read handshake out of sequence %s (rem:%d) (decrypted:%t)", rec.Print(), len(rem), false)
	} else if s.decrypt {
		if s.keyBlock == nil {
			err = errors.New("dtls: key block not initialized")
			logWarn(s.peer, rec, err, "tried to decrypt but KeyBlock not initialized.")
			return nil, nil, err
		}
		if len(rec.Data) < 8 {
			if rec.IsAlert() {
				// we were expecting encryption, but received an unencrypted alert message.
				logDebug(s.peer, rec, "read %s (rem:%d) (decrypted:not-applicable-alert)", rec.Print(), len(rem))
				return rec, rem, nil
			} else {
				err = errors.New("dtls: data underflow, expected at least 8 bytes")
				logWarn(s.peer, rec, err, "data underflow, expected at least 8 bytes, but received %d.", len(rec.Data))
				return nil, nil, err
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
			if s.handshake != nil && s.handshake.firstDecrypt {
				//callback that psk is invalid
				logWarn(s.peer, rec, nil, "PSK is most likely invalid for identity: %s", s.peerIdentity)
				s.handshake.firstDecrypt = false
			}
			if rec.IsHandshake() {
				logDebug(s.peer, rec, "read %s (rem:%d) (decrypted:not-applicable): %s", rec.Print(), len(rem), err.Error())
				return rec, rem, nil
			} else {
				logWarn(s.peer, rec, err, "read decryption error")
				return nil, nil, err
			}
		}
		if s.handshake != nil && s.handshake.firstDecrypt {
			s.handshake.firstDecrypt = false
		}

		rec.SetData(clearText)
		logDebug(s.peer, rec, "read %s (rem:%d) (decrypted:%t)", rec.Print(), len(rem), s.decrypt)
	}

	return rec, rem, nil
}

var sessionHandshakeFragments sync.Map

func (s *session) parseHandshake(rec *record) (*handshake, error) {
	hs, err := parseHandshake(rec.Data)
	if err != nil {
		return nil, err
	}

	if hs.IsFragment() {
		// save fragment && restore fragment
		if oldFragment, loaded := sessionHandshakeFragments.LoadOrStore(s.Id, hs.Fragment); loaded {
			// existing fragment available
			data := append(oldFragment.([]byte), hs.Fragment...)

			if hs.Header.FragmentOfs+hs.Header.FragmentLen == hs.Header.Length {
				// have complete fragement
				hs.Header.FragmentOfs = 0
				hs.Header.FragmentLen = hs.Header.Length
				hs, err = parseFragments(hs.Header, data)
				if err != nil {
					return nil, err
				}
				logDebug(s.peer, rec, "re-assembled fragments")
				s.updateHash(hs.Bytes())
			} else {
				sessionHandshakeFragments.Store(s.Id, data)
				return hs, nil
			}
		} else {
			return hs, nil
		}

	} else {
		s.updateHash(rec.Data)
	}

	logDebug(s.peer, rec, "read handshake: %s", hs.Print())
	return hs, err
}

func (s *session) writeHandshake(hs *handshake) error {

	hs.Header.Sequence = s.handshake.seq
	s.handshake.seq += 1

	data := hs.Bytes()
	dataLen := int(hs.Header.Length)
	s.updateHash(data)

	if dataLen > s.listener.maxHandshakeSize {
		// need to fragment sending

		for idx := 0; idx < dataLen/s.listener.maxHandshakeSize+1; idx++ {
			data = hs.FragmentBytes(idx*s.listener.maxHandshakeSize, s.listener.maxHandshakeSize)
			rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), data)
			if DebugHandshake {
				logDebug(s.peer, nil, "write (handshake) %s (fragment %d/%d)", hs.Print(), idx*s.listener.maxHandshakeSize, dataLen)
			}
			err := s.writeRecord(rec)
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), data)

		if DebugHandshake {
			logDebug(s.peer, nil, "write (handshake) %s", hs.Print())
		}

		return s.writeRecord(rec)
	}
}

func (s *session) writeHandshakes(hss []*handshake) error {
	var recs []*record
	for _, hs := range hss {

		hs.Header.Sequence = s.handshake.seq
		s.handshake.seq += 1

		data := hs.Bytes()
		dataLen := int(hs.Header.Length)
		s.updateHash(data)

		if dataLen > s.listener.maxHandshakeSize {
			// need to fragment sending

			for idx := 0; idx < dataLen/s.listener.maxHandshakeSize+1; idx++ {
				data = hs.FragmentBytes(idx*s.listener.maxHandshakeSize, s.listener.maxHandshakeSize)
				rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), data)
				if DebugHandshake {
					logDebug(s.peer, nil, "write (handshake) %s (fragment %d/%d)", hs.Print(), idx*s.listener.maxHandshakeSize, dataLen)
				}
				recs = append(recs, rec)
			}
		} else {
			rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), data)

			if DebugHandshake {
				logDebug(s.peer, nil, "write (handshake) %s", hs.Print())
			}

			recs = append(recs, rec)
		}
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
		logDebug(s.peer, rec, "write (encrypted) %s", rec.Print())
		return s.peer.transport.WritePacket(rec.Bytes())
	} else {
		logDebug(s.peer, rec, "write (unencrypted) %s", rec.Print())
		return s.peer.transport.WritePacket(rec.Bytes())
	}
}

func (s *session) writeRecords(recs []*record) error {
	if s.encrypt {
		return errors.New("dtls: can't write multiple encrypted records.")
	} else {
		buf := bytes.Buffer{}
		for _, rec := range recs {
			logDebug(s.peer, rec, "write (unencrypted) %s", rec.Print())
			nextRec := rec.Bytes()
			if len(nextRec)+buf.Len() > s.listener.maxPacketSize {
				if err := s.peer.transport.WritePacket(buf.Bytes()); err != nil {
					return err
				}
				buf.Reset()
			}
			buf.Write(nextRec)
		}
		return s.peer.transport.WritePacket(buf.Bytes())
	}
}

func (s *session) generateCookie() {
	s.handshake.cookie = randomBytes(16)
}

func (s *session) startHandshake() error {
	reqHs := newHandshake(handshakeType_ClientHello)
	reqHs.ClientHello.Init(s.Id, s.handshake.client.Random, nil, s.listener.cipherSuites, s.listener.compressionMethods)

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
		if s.handshake != nil && s.handshake.state == "finished" {
			return nil
		} else {
			return err
		}
	case <-time.After(timeout):
		return fmt.Errorf("dtls: timed out waiting for handshake to complete (state:%s)", s.handshake.state)
	}
}

func (s *session) processHandshakePacket(rspRec *record) error {

	var reqHs, rspHs *handshake
	var err error

	if s.handshake != nil {
		logDebug(s.peer, rspRec, "processing handshake packet, current state: %s", s.handshake.state)
	} else {
		logDebug(s.peer, rspRec, "processing handshake packet, current state: nil")
	}

	switch rspRec.ContentType {
	case ContentType_Handshake:

		if s.isHandshakeDone() && (rspRec.Epoch != 0 || rspRec.Data[0] != byte(handshakeType_ClientHello)) {
			logDebug(s.peer, rspRec, "handshake packet received after handshake is complete")
			return nil
		}
		if !s.isHandshakeDone() && rspRec.Epoch != 0 && !s.decrypt {
			logDebug(s.peer, rspRec, "encrypted handshake packet received, but cipher not initialized")
			return nil
		}

		rspHs, err = s.parseHandshake(rspRec)
		if err != nil {
			return err
		}
		if rspHs.IsFragment() {
			logDebug(s.peer, rspRec, "handshake fragment received %d/%d", rspHs.Header.FragmentOfs+rspHs.Header.FragmentLen, rspHs.Header.Length)
			return nil
		}

		if s.handshake != nil {
			if _, found := s.handshake.dedup[rspHs.Header.Sequence]; found && rspHs.Header.Sequence != 0 {
				// duplicate packet received, drop it.
				logDebug(s.peer, rspRec, "duplicate handshake received seq: %d", rspHs.Header.Sequence)
				return nil
			} else {
				s.handshake.dedup[rspHs.Header.Sequence] = true
			}
		}

		switch rspHs.Header.HandshakeType {
		case handshakeType_ClientHello:
			cookie := rspHs.ClientHello.GetCookie()
			if len(cookie) == 0 {
				if s.handshake != nil && len(s.handshake.state) != 0 {
					logWarn(s.peer, rspRec, nil, "previous handshake not completed, last state: %s", s.handshake.state)
				}
				s.reset()
				s.generateCookie()
				s.sequenceNumber = uint64(rspHs.Header.Sequence)
				s.handshake.seq = rspHs.Header.Sequence
				s.started = time.Now()
				s.handshake.state = "recv-clienthello-initial"
			} else {
				if s.handshake == nil || s.handshake.cookie == nil {
					s.handshake.state = "failed"
					err = errors.New("dtls: clienthello sent cookie, but we have nothing to compare against")
					break
				}
				if !reflect.DeepEqual(cookie, s.handshake.cookie) {
					s.handshake.state = "failed"
					err = errors.New("dtls: cookie in clienthello does not match")
					break
				}

				s.handshake.client.RandomTime, s.handshake.client.Random = rspHs.ClientHello.GetRandom()
				s.selectedCipherSuite = rspHs.ClientHello.SelectCipherSuite(s.listener.cipherSuites)
				s.cipher = getCipher(s.peer, s.selectedCipherSuite)
				if s.cipher == nil {
					s.handshake.state = "failed"
					err = errors.New("dtls: no valid cipher available")
					break
				}

				if rspHs.ClientHello.HasSessionId() {
					//resuming a session
					ce := getFromSessionCache(rspHs.ClientHello.GetSessionIdStr())
					if ce != nil {
						s.Id = rspHs.ClientHello.GetSessionId()
						if s.selectedCipherSuite.NeedPsk() {
							s.peerIdentity = ce.Identity

							logDebug(s.peer, rspRec, "resuming previously established session, set identity: %s", s.peerIdentity)

							psk := GetPskFromKeystore(s.peerIdentity, s.peer.RemoteAddr())
							if psk == nil {
								err = errors.New("dtls: no valid psk for identity")
								break
							}
							s.handshake.psk = psk
							s.handshake.masterSecret = ce.MasterSecret

							s.handshake.resumed = true
						} else {
							s.peerPublicKey = ce.PublicKey
							s.peerCert = ce.cert
							s.handshake.eccCurve = ce.EccCurve
							s.handshake.eccKeypair = ce.EccKeypair
							s.handshake.masterSecret = ce.MasterSecret

							logDebug(s.peer, rspRec, "resuming previously established session, set certificate")
							s.handshake.resumed = true
						}
					} else {
						logDebug(s.peer, rspRec, "tried to resume session, but it was not found")
						s.handshake.resumed = false
					}
				}

				if !s.handshake.resumed {
					s.handshake.state = "recv-clienthello"
				} else {
					s.handshake.state = "recv-clienthello-resumed"
				}
			}
		case handshakeType_ServerHello:
			s.handshake.server.RandomTime, s.handshake.server.Random = rspHs.ServerHello.GetRandom()
			if reflect.DeepEqual(s.Id, rspHs.ServerHello.GetSessionId()) {
				//resuming session
				s.handshake.resumed = true
			} else {
				s.Id = rspHs.ServerHello.GetSessionId()
			}
			s.selectedCipherSuite = rspHs.ServerHello.cipherSuite
			s.cipher = getCipher(s.peer, s.selectedCipherSuite)
			if s.cipher == nil {
				s.handshake.state = "failed"
				err = errors.New("dtls: no valid cipher available")
				break
			}
			s.handshake.state = "recv-serverhello"
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
		case handshakeType_Certificate:
			s.handshake.certs = rspHs.Certificate.GetCerts()
			s.handshake.state = "recv-certificate"
		case handshakeType_ServerKeyExchange:
			s.peerIdentity = rspHs.ServerKeyExchange.GetIdentity()
			s.peerPublicKey = rspHs.ServerKeyExchange.GetPublicKey()
			s.handshake.state = "recv-serverkeyexchange"
		case handshakeType_ServerHelloDone:
			s.handshake.state = "recv-serverhellodone"
		case handshakeType_CertificateVerify:
			err = eccVerifySignature(s.handshake.verifySum, rspHs.CertificateVerify.signature, s.handshake.certs)
			if err != nil {
				logWarn(s.peer, rspRec, err, "certificate verification failed")
				break
			}
			logDebug(s.peer, rspRec, "certificate verified")
			s.handshake.state = "recv-certificateverify"
		case handshakeType_ClientKeyExchange:
			if s.selectedCipherSuite.NeedPsk() {
				s.peerIdentity = rspHs.ClientKeyExchange.GetIdentity()
				psk := GetPskFromKeystore(s.peerIdentity, s.peer.RemoteAddr())
				if psk == nil {
					err = errors.New("dtls: no valid psk for identity")
					break
				}
				s.handshake.psk = psk
			} else {
				s.peerPublicKey = rspHs.ClientKeyExchange.GetPublicKey()
				if s.handshake.certs != nil && len(s.handshake.certs) > 0 {
					if ValidateCertificateCallback != nil {
						cert, err := x509.ParseCertificate(s.handshake.certs[0])
						if err != nil {
							err = errors.New("dtls: certificate cant be parsed: " + err.Error())
							break
						}
						err = ValidateCertificateCallback(s.peer, cert)
						if err != nil {
							err = errors.New("dtls: certificate validation failed: " + err.Error())
							break
						}
						s.peerCert = cert
					}
				} else {
					err = errors.New("dtls: no certificate to validate")
					break
				}
				if s.peerPublicKey == nil {
					err = errors.New("dtls: peer did not present a public key")
					break
				}
				if s.handshake.eccKeypair == nil {
					err = errors.New("dtls: ecc keypair not initialized")
					break
				}
			}
			s.initKeyBlock()
			s.handshake.verifySum = s.getHash()
			s.handshake.state = "recv-clientkeyexchange"
		case handshakeType_Finished:
			var label string
			if s.Type == SessionType_Client {
				label = "server"
			} else {
				label = "client"
			}
			if rspHs.Finished.Match(s.keyBlock.MasterSecret, s.handshake.savedHash, label) {
				if s.Type == SessionType_Server {
					saveToSessionCache(s)
				}
				logDebug(s.peer, rspRec, "encryption matches, handshake complete")
			} else {
				s.handshake.state = "failed"
				err = errors.New("dtls: crypto verification failed")
				break
			}
			s.handshake.state = "finished"
			break
		default:
			logWarn(s.peer, rspRec, nil, "invalid handshake type [%v] received", rspRec.ContentType)
			err = errors.New("dtls: bad handshake type")
			break
		}
	case ContentType_ChangeCipherSpec:
		if !s.isHandshakeDone() {
			s.decrypt = true
			s.handshake.firstDecrypt = true
			s.handshake.savedHash = s.getHash()
			s.handshake.state = "cipherchangespec"
		} else {
			return nil
		}
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

			var hsArr []*handshake

			reqHs = newHandshake(handshakeType_ServerHello)
			reqHs.ServerHello.Init(s.handshake.server.Random, s.Id, s.selectedCipherSuite)
			hsArr = append(hsArr, reqHs)

			if s.selectedCipherSuite.NeedCert() {
				reqHs = newHandshake(handshakeType_Certificate)
				// need server cert
				_ = reqHs.Certificate.Init(s.listener.certificate.Certificate)
				hsArr = append(hsArr, reqHs)

				s.handshake.eccCurve = EccCurve_P256
				s.handshake.eccKeypair, _ = eccGetKeypair(s.handshake.eccCurve)

				reqHs = newHandshake(handshakeType_ServerKeyExchange)
				signature, err := eccGetKeySignature(s.handshake.client.Random, s.handshake.server.Random, s.handshake.eccKeypair.publicKey, s.handshake.eccCurve, s.listener.certificate.PrivateKey)
				if err != nil {
					break
				}
				reqHs.ServerKeyExchange.InitCert(EccCurve_P256, s.handshake.eccKeypair.publicKey, signature)
				hsArr = append(hsArr, reqHs)

				reqHs = newHandshake(handshakeType_CertificateRequest)
				hsArr = append(hsArr, reqHs)
			}

			reqHs = newHandshake(handshakeType_ServerHelloDone)
			reqHs.ServerHelloDone.Init()
			hsArr = append(hsArr, reqHs)

			err = s.writeHandshakes(hsArr)
			if err != nil {
				break
			}
		case "recv-clienthello-resumed":

			reqHs = newHandshake(handshakeType_ServerHello)
			reqHs.ServerHello.Init(s.handshake.server.Random, s.Id, s.selectedCipherSuite)
			err = s.writeHandshake(reqHs)

			s.initKeyBlock()

			rec := newRecord(ContentType_ChangeCipherSpec, s.getEpoch(), s.getNextSequence(), []byte{0x01})
			if DebugHandshake {
				logDebug(s.peer, rspRec, "session resume incremented epoc from %d to %d", s.getEpoch(), s.getEpoch()+1)
			}
			s.incEpoch()
			err = s.writeRecord(rec)
			if err != nil {
				break
			}
			s.encrypt = true

			reqHs2 := newHandshake(handshakeType_Finished)
			reqHs2.Finished.Init(s.keyBlock.MasterSecret, s.getHash(), "server")
			err = s.writeHandshake(reqHs2)
			if err != nil {
				break
			}
		case "recv-helloverifyrequest":
			reqHs = newHandshake(handshakeType_ClientHello)
			err = reqHs.ClientHello.Init(s.Id, s.handshake.client.Random, s.handshake.cookie, s.listener.cipherSuites, s.listener.compressionMethods)
			if err != nil {
				break
			}
			err = s.writeHandshake(reqHs)
			if err != nil {
				break
			}
		case "recv-serverhellodone":

			if s.selectedCipherSuite.NeedPsk() {
				psk := GetPskFromKeystore(s.peerIdentity, s.peer.RemoteAddr())
				if len(psk) > 0 {
					s.handshake.psk = psk
				} else {
					err = errors.New("dtls: no psk could be found")
					break
				}
			}

			if !s.handshake.resumed {
				reqHs = newHandshake(handshakeType_ClientKeyExchange)

				reqHs.ClientKeyExchange.InitPsk(s.peerIdentity)
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
			if s.Type == SessionType_Server && !s.handshake.resumed {
				rec := newRecord(ContentType_ChangeCipherSpec, s.getEpoch(), s.getNextSequence(), []byte{0x01})
				if DebugHandshake {
					logDebug(s.peer, rspRec, "finish incremented inc epoch from %d to %d", s.getEpoch(), s.getEpoch()+1)
				}
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
			HandshakeCompleteCallback(s.peer, s.peerIdentity, time.Now().Sub(s.started), err)
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
			HandshakeCompleteCallback(s.peer, s.peerIdentity, time.Now().Sub(s.started), nil)
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
		close(s.handshake.done)
		s.handshake = nil
	}

	return nil
}
