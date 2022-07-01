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

	if rec.Epoch != 0 {
		if s.keyBlock == nil {
			err = errors.New("dtls: key block not initialized")
			logWarn(s.peer, rec, err, "tried to decrypt but KeyBlock not initialized.")
			return nil, nil, err
		}
		if len(rec.Data) < 8 {
			if rec.IsAlert() {
				// we were expecting encryption, but received an unencrypted alert message.
				if DebugEncryption {
					logDebug(s.peer, rec, "read %s (rem:%d) (decrypted:not-applicable-alert)", rec.Print(), len(rem))
				}
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

		clearText, err := s.cipher.Decrypt(rec, key, iv, mac, s.cid)
		if s.cid != nil {
			// DTLSInnerPlaintext
			clearText = bytes.TrimRight(clearText, "\x00")
			rec.ContentType = ContentType(clearText[len(clearText)-1])
			clearText = clearText[:len(clearText)-1]
		}

		if err != nil {
			if s.handshake != nil && s.handshake.firstDecrypt {
				//callback that psk is invalid
				logWarn(s.peer, rec, nil, "PSK is most likely invalid for identity: %s", s.peerIdentity)
				s.handshake.firstDecrypt = false
			}
			if rec.IsHandshake() {
				if DebugEncryption {
					logDebug(s.peer, rec, "read %s (rem:%d) (decrypted:not-applicable): %s", rec.Print(), len(rem), err.Error())
				}
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
		if DebugEncryption {
			logDebug(s.peer, rec, "read %s (rem:%d)", rec.Print(), len(rem))
		}
	}

	return rec, rem, nil
}

var sessionHandshakeFragments sync.Map

func (s *session) parseHandshake(rec *record) (*handshake, error) {
	hs, err := parseHandshake(rec.Data)
	if err != nil {
		return nil, err
	}

	if s.handshake != nil {
		if _, found := s.handshake.dedup[hs.Header.Sequence]; found && hs.Header.Sequence != 0 {
			// dupilicate packet received, drop it.
			hs.Header.duplicate = true
			s.cacheHandshakeFlush(hs.Header.Sequence)
			return hs, nil
		} else {
			s.handshake.dedup[hs.Header.Sequence] = true
		}
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

	if DebugHandshake {
		logDebug(s.peer, rec, "read handshake: %s", hs.Print())
	}
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
			rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), nil, data)
			if DebugHandshake {
				logDebug(s.peer, nil, "write (handshake) %s (fragment %d/%d)", hs.Print(), idx*s.listener.maxHandshakeSize, dataLen)
			}

			s.cacheHandshake(rec)
			err := s.writeRecord(rec)
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), nil, data)

		if DebugHandshake {
			logDebug(s.peer, nil, "write (handshake) %s", hs.Print())
		}

		s.cacheHandshake(rec)
		err := s.writeRecord(rec)
		return err
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
				rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), nil, data)
				if DebugHandshake {
					logDebug(s.peer, nil, "write (handshake) %s (fragment %d/%d)", hs.Print(), idx*s.listener.maxHandshakeSize, dataLen)
				}
				s.cacheHandshake(rec)
				recs = append(recs, rec)
			}
		} else {
			rec := newRecord(ContentType_Handshake, s.getEpoch(), s.getNextSequence(), nil, data)

			if DebugHandshake {
				logDebug(s.peer, nil, "write (handshake) %s", hs.Print())
			}
			s.cacheHandshake(rec)
			recs = append(recs, rec)
		}
	}
	return s.writeRecords(recs)
}

func (s *session) cacheHandshakeFlush(seq uint16) {

	if recArr, found := s.handshake.dedupCache[seq]; found {
		for _, rec := range recArr {
			if rec.ContentType == ContentType_ChangeCipherSpec {
				s.epoch = 0
				s.sequenceNumber1 = 0
			}
			rec.Epoch = s.getEpoch()
			rec.Sequence = s.getNextSequence()
			if rec.ContentType == ContentType_ChangeCipherSpec {
				s.incEpoch()
			}
		}
		err := s.writeRecords(recArr)
		if err != nil {
			logWarn(s.peer, nil, err, "retransmit write")
		} else if DebugHandshake {
			logDebug(s.peer, nil, "retransmit (handshake)")
		}
	}
}

func (s *session) cacheHandshake(rec *record) {
	if DebugHandshake {
		logDebug(s.peer, rec, "storing handshake for retransmit")
	}
	if recArr, found := s.handshake.dedupCache[s.handshake.lastSeqRecv]; found {
		recArr = append(recArr, rec)
		s.handshake.dedupCache[s.handshake.lastSeqRecv] = recArr
	} else {
		s.handshake.dedupCache[s.handshake.lastSeqRecv] = []*record{rec}
	}
}

func (s *session) writeRecord(rec *record) error {
	if rec.Epoch != 0 {
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
		if s.peerCid != nil {
			// DTLSInnerPlaintext
			rec.Data = append(rec.Data, byte(rec.ContentType))
			rec.ContentType = ContentType_Appdata_Cid
			rec.Cid = s.peerCid
		}
		cipherText, err := s.cipher.Encrypt(rec, key, iv, mac, s.peerCid)
		if err != nil {
			return err
		}
		rec.SetData(cipherText)
		if DebugEncryption {
			logDebug(s.peer, rec, "write (encrypted) %s", rec.Print())
		}
		return s.peer.transport.WritePacket(rec.Bytes())
	} else {
		if DebugEncryption {
			logDebug(s.peer, rec, "write (unencrypted) %s", rec.Print())
		}
		return s.peer.transport.WritePacket(rec.Bytes())
	}
}

func (s *session) writeRecords(recs []*record) error {
	buf := bytes.Buffer{}
	for _, rec := range recs {
		if rec.Epoch != 0 {
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
			cipherText, err := s.cipher.Encrypt(rec, key, iv, mac, s.peerCid)
			if err != nil {
				return err
			}
			rec.SetData(cipherText)
		}
		if DebugEncryption {
			logDebug(s.peer, rec, "write (unencrypted) %s", rec.Print())
		}
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

func (s *session) processHandshakePacket(incomingRec *record) error {

	var outgoingHs, incomingHs *handshake
	var err error

	if DebugHandshake {
		if s.handshake != nil {
			logDebug(s.peer, incomingRec, "processing handshake packet, current state: %s", s.handshake.state)
		} else {
			logDebug(s.peer, incomingRec, "processing handshake packet, current state: nil")
		}
	}

	switch incomingRec.ContentType {
	case ContentType_Handshake:

		incomingHs, err = s.parseHandshake(incomingRec)
		if err != nil {
			return err
		}
		if incomingHs.IsFragment() {
			logDebug(s.peer, incomingRec, "handshake fragment received %d/%d", incomingHs.Header.FragmentOfs+incomingHs.Header.FragmentLen, incomingHs.Header.Length)
			return nil
		}

		if incomingHs.IsDuplicate() && incomingRec.Data[0] != byte(handshakeType_ClientHello) {
			logDebug(s.peer, incomingRec, "duplicate handshake received seq: %d", incomingHs.Header.Sequence)
			return nil
		}

		if s.isHandshakeDone() && (incomingRec.Epoch != 0 || incomingRec.Data[0] != byte(handshakeType_ClientHello)) {
			logDebug(s.peer, incomingRec, "handshake packet received after handshake is complete")
			return nil
		}

		s.handshake.lastSeqRecv = incomingHs.Header.Sequence

		switch incomingHs.Header.HandshakeType {
		case handshakeType_ClientHello:
			cookie := incomingHs.ClientHello.GetCookie()
			if len(cookie) == 0 {
				if s.handshake != nil && len(s.handshake.state) != 0 {
					logWarn(s.peer, incomingRec, nil, "previous handshake not completed, last state: %s", s.handshake.state)
				}
				s.reset()
				s.generateCookie()
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

				s.handshake.client.RandomTime, s.handshake.client.Random = incomingHs.ClientHello.GetRandom()
				s.selectedCipherSuite = incomingHs.ClientHello.SelectCipherSuite(s.listener.cipherSuites)
				s.cipher = getCipher(s.peer, s.selectedCipherSuite)
				if s.cipher == nil {
					s.handshake.state = "failed"
					err = errors.New("dtls: no valid cipher available")
					break
				}
				if incomingHs.ClientHello.cidEnable {
					s.handshake.cidEnabled = true
					s.peerCid = incomingHs.ClientHello.cid
				}

				if incomingHs.ClientHello.HasSessionId() {
					//resuming a session
					ce := getFromSessionCache(incomingHs.ClientHello.GetSessionIdStr())
					if ce != nil {
						s.Id = incomingHs.ClientHello.GetSessionId()
						if s.selectedCipherSuite.NeedPsk() {
							s.peerIdentity = ce.Identity

							logDebug(s.peer, incomingRec, "resuming previously established session, set identity: %s", s.peerIdentity)

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

							logDebug(s.peer, incomingRec, "resuming previously established session, set certificate")
							s.handshake.resumed = true
						}
					} else {
						logDebug(s.peer, incomingRec, "tried to resume session, but it was not found")
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
			s.handshake.server.RandomTime, s.handshake.server.Random = incomingHs.ServerHello.GetRandom()
			sid := incomingHs.ServerHello.GetSessionId()
			if len(sid) != 0 && reflect.DeepEqual(s.Id, sid) {
				//resuming session
				s.handshake.resumed = true
			} else {
				s.Id = incomingHs.ServerHello.GetSessionId()
			}
			s.selectedCipherSuite = incomingHs.ServerHello.cipherSuite
			s.cipher = getCipher(s.peer, s.selectedCipherSuite)
			if s.cipher == nil {
				s.handshake.state = "failed"
				err = errors.New("dtls: no valid cipher available")
				break
			}
			s.handshake.cidEnabled = true
			s.peerCid = incomingHs.ServerHello.cid

			s.handshake.state = "recv-serverhello"
		case handshakeType_HelloVerifyRequest:
			if len(s.handshake.cookie) == 0 {
				s.handshake.cookie = incomingHs.HelloVerifyRequest.GetCookie()
				s.resetHash()
				s.handshake.state = "recv-helloverifyrequest"
			} else {
				s.handshake.state = "failed"
				err = errors.New("dtls: received hello verify request, but already have cookie")
				break
			}
			s.handshake.state = "recv-helloverifyrequest"
		case handshakeType_Certificate:
			s.handshake.certs = incomingHs.Certificate.GetCerts()
			s.handshake.state = "recv-certificate"
		case handshakeType_ServerKeyExchange:
			s.peerIdentity = incomingHs.ServerKeyExchange.GetIdentity()
			s.peerPublicKey = incomingHs.ServerKeyExchange.GetPublicKey()
			s.handshake.state = "recv-serverkeyexchange"
		case handshakeType_ServerHelloDone:
			s.handshake.state = "recv-serverhellodone"
		case handshakeType_CertificateVerify:
			err = eccVerifySignature(s.handshake.verifySum, incomingHs.CertificateVerify.signature, s.handshake.certs)
			if err != nil {
				logWarn(s.peer, incomingRec, err, "certificate verification failed")
				break
			}
			logDebug(s.peer, incomingRec, "certificate verified")
			s.handshake.state = "recv-certificateverify"
		case handshakeType_ClientKeyExchange:
			if s.selectedCipherSuite.NeedPsk() {
				s.peerIdentity = incomingHs.ClientKeyExchange.GetIdentity()
				psk := GetPskFromKeystore(s.peerIdentity, s.peer.RemoteAddr())
				if psk == nil {
					err = errors.New("dtls: no valid psk for identity")
					break
				}
				s.handshake.psk = psk
			} else {
				s.peerPublicKey = incomingHs.ClientKeyExchange.GetPublicKey()
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
			if incomingHs.Finished.Match(s.keyBlock.MasterSecret, s.handshake.savedHash, label) {
				if s.Type == SessionType_Server {
					saveToSessionCache(s)
				}
				logDebug(s.peer, incomingRec, "encryption matches, handshake complete")
			} else {
				s.handshake.state = "failed"
				err = errors.New("dtls: crypto verification failed")
				break
			}
			s.handshake.state = "finished"
			break
		default:
			logWarn(s.peer, incomingRec, nil, "invalid handshake type [%v] received", incomingRec.ContentType)
			err = errors.New("dtls: bad handshake type")
			break
		}
	case ContentType_ChangeCipherSpec:
		if !s.isHandshakeDone() {
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
			outgoingHs = newHandshake(handshakeType_HelloVerifyRequest)
			outgoingHs.HelloVerifyRequest.Init(s.handshake.cookie)
			err = s.writeHandshake(outgoingHs)
			if err != nil {
				break
			}
			s.resetHash()
		case "recv-clienthello":

			var hsArr []*handshake

			if s.handshake.cidEnabled && s.listener.cidLen > 0 {
				// if we receive a CID from the client, use the same length CID.
				cidLen := s.listener.cidLen
				/*if s.peerCid != nil {
					cidLen = len(s.peerCid)
				}*/
				s.cid = randomBytes(cidLen)

				// first byte of server generated CID is always its length
				s.cid[0] = byte(cidLen - 1)
				s.listener.mux.Lock()
				s.listener.peerCids[string(s.cid)] = s.peer
				s.listener.mux.Unlock()
				logDebug(s.peer, incomingRec, "server cid generated: %X", s.cid)
			}

			outgoingHs = newHandshake(handshakeType_ServerHello)
			outgoingHs.ServerHello.Init(s.handshake.server.Random, s.Id, s.cid, s.selectedCipherSuite)

			hsArr = append(hsArr, outgoingHs)

			if s.selectedCipherSuite.NeedCert() {
				outgoingHs = newHandshake(handshakeType_Certificate)
				// need server cert
				_ = outgoingHs.Certificate.Init(s.listener.certificate.Certificate)
				hsArr = append(hsArr, outgoingHs)

				s.handshake.eccCurve = EccCurve_P256
				s.handshake.eccKeypair, _ = eccGetKeypair(s.handshake.eccCurve)

				outgoingHs = newHandshake(handshakeType_ServerKeyExchange)
				signature, err := eccGetKeySignature(s.handshake.client.Random, s.handshake.server.Random, s.handshake.eccKeypair.publicKey, s.handshake.eccCurve, s.listener.certificate.PrivateKey)
				if err != nil {
					break
				}
				outgoingHs.ServerKeyExchange.InitCert(EccCurve_P256, s.handshake.eccKeypair.publicKey, signature)
				hsArr = append(hsArr, outgoingHs)

				outgoingHs = newHandshake(handshakeType_CertificateRequest)
				hsArr = append(hsArr, outgoingHs)
			}

			outgoingHs = newHandshake(handshakeType_ServerHelloDone)
			outgoingHs.ServerHelloDone.Init()
			hsArr = append(hsArr, outgoingHs)

			err = s.writeHandshakes(hsArr)
			if err != nil {
				break
			}
		case "recv-clienthello-resumed":

			outgoingHs = newHandshake(handshakeType_ServerHello)
			outgoingHs.ServerHello.Init(s.handshake.server.Random, s.Id, s.cid, s.selectedCipherSuite)
			err = s.writeHandshake(outgoingHs)

			s.initKeyBlock()

			rec := newRecord(ContentType_ChangeCipherSpec, s.getEpoch(), s.getNextSequence(), s.getPeerCid(), []byte{0x01})
			if DebugHandshake {
				logDebug(s.peer, incomingRec, "session resume incremented epoc from %d to %d", s.getEpoch(), s.getEpoch()+1)
			}
			s.incEpoch()
			err = s.writeRecord(rec)
			if err != nil {
				break
			}

			reqHs2 := newHandshake(handshakeType_Finished)
			reqHs2.Finished.Init(s.keyBlock.MasterSecret, s.getHash(), "server")
			err = s.writeHandshake(reqHs2)
			if err != nil {
				break
			}
		case "recv-helloverifyrequest":
			outgoingHs = newHandshake(handshakeType_ClientHello)
			err = outgoingHs.ClientHello.Init(s.Id, s.handshake.client.Random, s.handshake.cookie, s.listener.cipherSuites, s.listener.compressionMethods)
			if err != nil {
				break
			}
			err = s.writeHandshake(outgoingHs)
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
				outgoingHs = newHandshake(handshakeType_ClientKeyExchange)

				outgoingHs.ClientKeyExchange.InitPsk(s.peerIdentity)
				err = s.writeHandshake(outgoingHs)
				if err != nil {
					break
				}
			}

			s.initKeyBlock()

			rec := newRecord(ContentType_ChangeCipherSpec, s.getEpoch(), s.getNextSequence(), s.getPeerCid(), []byte{0x01})
			s.incEpoch()
			err = s.writeRecord(rec)
			if err != nil {
				break
			}

			outgoingHs = newHandshake(handshakeType_Finished)
			outgoingHs.Finished.Init(s.keyBlock.MasterSecret, s.getHash(), "client")
			err = s.writeHandshake(outgoingHs)
			if err != nil {
				break
			}
		case "finished":
			if s.Type == SessionType_Server && !s.handshake.resumed {
				rec := newRecord(ContentType_ChangeCipherSpec, s.getEpoch(), s.getNextSequence(), s.getPeerCid(), []byte{0x01})
				if DebugHandshake {
					logDebug(s.peer, incomingRec, "finish incremented inc epoch from %d to %d", s.getEpoch(), s.getEpoch()+1)
				}
				s.cacheHandshake(rec)
				s.incEpoch()
				err = s.writeRecord(rec)
				if err != nil {
					break
				}

				outgoingHs = newHandshake(handshakeType_Finished)
				outgoingHs.Finished.Init(s.keyBlock.MasterSecret, s.getHash(), "server")
				err = s.writeHandshake(outgoingHs)
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
			if s.selectedCipherSuite.NeedPsk() {
				HandshakeCompleteCallback(s.peer, s.peerIdentity, time.Now().Sub(s.started), err)
			} else {
				HandshakeCompleteCallback(s.peer, s.peerPublicKey, time.Now().Sub(s.started), err)
			}
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
			if s.selectedCipherSuite.NeedPsk() {
				HandshakeCompleteCallback(s.peer, s.peerIdentity, time.Now().Sub(s.started), nil)
			} else {
				HandshakeCompleteCallback(s.peer, s.peerPublicKey, time.Now().Sub(s.started), nil)
			}
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
	}

	return nil
}
