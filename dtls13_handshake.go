package dtls

import (
	"crypto/hmac"
	"errors"
	"fmt"
)

func (s *session) supportsProtocolVersion(version uint16) bool {
	for _, supported := range s.listener.supportedVersions {
		if supported == version {
			return true
		}
	}
	return false
}

func (s *session) shouldStartDtls13() bool {
	if !s.supportsProtocolVersion(DtlsVersion13) {
		return false
	}
	for _, cipherSuite := range s.listener.cipherSuites {
		if cipherSuite.IsTLS13() {
			return true
		}
	}
	return false
}

func (s *session) firstDtls13CipherSuite() CipherSuite {
	for _, cipherSuite := range s.listener.cipherSuites {
		if cipherSuite.IsTLS13() {
			return cipherSuite
		}
	}
	return 0
}

func (s *session) startHandshake13() error {
	s.protocolVersion = DtlsVersion13
	s.ensureDtls13()
	cipherSuite := s.firstDtls13CipherSuite()
	if cipherSuite == 0 {
		return errors.New("dtls: no DTLS 1.3 cipher suite configured")
	}
	psk := GetPskFromKeystore(s.peerIdentity, s.peer.RemoteAddr())
	if len(psk) == 0 {
		return errors.New("dtls: no psk could be found")
	}
	zeroBinder := make([]byte, cipherSuite.HashSize())
	hs := s.newDtls13ClientHello(zeroBinder)
	zeroBinderInput := hs.Bytes()
	zeroBinderInput = zeroBinderInput[:len(zeroBinderInput)-len(zeroBinder)]
	binder := dtls13ExternalPSKBinder(psk, zeroBinderInput)
	hs = s.newDtls13ClientHello(binder)
	raw := hs.Bytes()
	s.dtls13.clientHello = append([]byte(nil), raw...)
	s.dtls13.selectedPsk = psk
	rec := newRecord(ContentType_Handshake, 0, s.getNextSequence(), nil, raw)
	return s.peer.transport.WritePacket(rec.Bytes())
}

func (s *session) newDtls13ClientHello(binder []byte) *handshake {
	hs := newHandshake(handshakeType_ClientHello)
	hs.Header.Sequence = 0
	hs.ClientHello.Init(nil, s.handshake.client.Random, nil, s.listener.cipherSuites, []CompressionMethod{CompressionMethod_Null})
	hs.ClientHello.EnableSupportedVersions(s.listener.supportedVersions)
	hs.ClientHello.EnablePskKeyExchangeModes([]uint8{Dtls13PskKeyExchangeModePSKOnly})
	hs.ClientHello.EnableExternalPSK(s.peerIdentity, binder)
	return hs
}

func (s *session) processDtls13Handshake(incomingRec *record, incomingHs *handshake) error {
	s.protocolVersion = DtlsVersion13
	s.ensureDtls13()

	switch incomingHs.Header.HandshakeType {
	case handshakeType_ClientHello:
		return s.processDtls13ClientHello(incomingRec, incomingHs)
	case handshakeType_ServerHello:
		return s.processDtls13ServerHello(incomingRec, incomingHs)
	case handshakeType_EncryptedExtensions:
		s.dtls13.encryptedExtensions = append([]byte(nil), incomingRec.Data...)
		return nil
	case handshakeType_Finished:
		if s.Type == SessionType_Client {
			return s.processDtls13ServerFinished(incomingRec, incomingHs)
		}
		return s.processDtls13ClientFinished(incomingRec, incomingHs)
	default:
		return fmt.Errorf("dtls: unsupported DTLS 1.3 handshake type %s", typeToString(incomingHs.Header.HandshakeType))
	}
}

func (s *session) processDtls13ClientHello(incomingRec *record, incomingHs *handshake) error {
	cipherSuite := incomingHs.ClientHello.SelectTLS13CipherSuite(s.listener.cipherSuites)
	if cipherSuite == 0 {
		return errors.New("dtls: no valid DTLS 1.3 cipher available")
	}
	if len(incomingHs.ClientHello.pskIdentities) == 0 || len(incomingHs.ClientHello.pskBinders) == 0 {
		return errors.New("dtls: DTLS 1.3 clienthello missing external psk")
	}
	identity := incomingHs.ClientHello.pskIdentities[0].Identity
	psk := GetPskFromKeystore(identity, s.peer.RemoteAddr())
	if len(psk) == 0 {
		return errors.New("dtls: no valid psk for identity")
	}
	expectedBinder := dtls13ExternalPSKBinder(psk, dtls13ClientHelloBinderInput(incomingHs))
	if !hmac.Equal(expectedBinder, incomingHs.ClientHello.pskBinders[0]) {
		return errors.New("dtls: DTLS 1.3 psk binder invalid")
	}

	s.selectedCipherSuite = cipherSuite
	s.peerIdentity = append([]byte(nil), identity...)
	s.dtls13.selectedIdentity = append([]byte(nil), identity...)
	s.dtls13.selectedPsk = psk
	s.dtls13.clientHello = append([]byte(nil), incomingRec.Data...)

	serverHello := newHandshake(handshakeType_ServerHello)
	serverHello.Header.Sequence = 1
	serverHello.ServerHello.Init13(s.handshake.server.Random, nil, cipherSuite, 0)
	serverHelloRaw := serverHello.Bytes()
	s.dtls13.serverHello = append([]byte(nil), serverHelloRaw...)
	if err := s.writeDtls13PlainHandshake(serverHelloRaw); err != nil {
		return err
	}

	s.dtls13.keys = dtls13MakeKeySchedule(cipherSuite, psk, s.dtls13.clientHello, s.dtls13.serverHello, nil, nil)
	encryptedExtensions := newHandshake(handshakeType_EncryptedExtensions)
	encryptedExtensions.Header.Sequence = 2
	encryptedExtensions.EncryptedExtensions.Init()
	encryptedExtensionsRaw := encryptedExtensions.Bytes()
	s.dtls13.encryptedExtensions = append([]byte(nil), encryptedExtensionsRaw...)
	if err := s.writeDtls13EncryptedHandshake(encryptedExtensionsRaw, s.dtls13.keys.ServerHandshakeKeys); err != nil {
		return err
	}

	serverFinished := newHandshake(handshakeType_Finished)
	serverFinished.Header.Sequence = 3
	verifyData := dtls13FinishedVerifyData(s.dtls13.keys.ServerHandshakeTrafficSecret, dtls13TranscriptHash(s.dtls13.clientHello, s.dtls13.serverHello, s.dtls13.encryptedExtensions))
	serverFinished.Finished.Init13(verifyData)
	serverFinishedRaw := serverFinished.Bytes()
	s.dtls13.serverFinished = append([]byte(nil), serverFinishedRaw...)
	s.dtls13.keys = dtls13MakeKeySchedule(cipherSuite, psk, s.dtls13.clientHello, s.dtls13.serverHello, s.dtls13.encryptedExtensions, s.dtls13.serverFinished)
	return s.writeDtls13EncryptedHandshake(serverFinishedRaw, s.dtls13.keys.ServerHandshakeKeys)
}

func (s *session) processDtls13ServerHello(incomingRec *record, incomingHs *handshake) error {
	if incomingHs.ServerHello.supportedVersion != DtlsVersion13 {
		return errors.New("dtls: server did not negotiate DTLS 1.3")
	}
	s.selectedCipherSuite = incomingHs.ServerHello.cipherSuite
	s.dtls13.serverHello = append([]byte(nil), incomingRec.Data...)
	if len(s.dtls13.selectedPsk) == 0 {
		return errors.New("dtls: DTLS 1.3 psk not initialized")
	}
	s.dtls13.keys = dtls13MakeKeySchedule(s.selectedCipherSuite, s.dtls13.selectedPsk, s.dtls13.clientHello, s.dtls13.serverHello, nil, nil)
	s.handshake.state = "recv-dtls13-serverhello"
	return nil
}

func (s *session) processDtls13ServerFinished(incomingRec *record, incomingHs *handshake) error {
	expected := dtls13FinishedVerifyData(s.dtls13.keys.ServerHandshakeTrafficSecret, dtls13TranscriptHash(s.dtls13.clientHello, s.dtls13.serverHello, s.dtls13.encryptedExtensions))
	if !hmac.Equal(expected, incomingHs.Finished.data) {
		s.handshake.state = "failed"
		return errors.New("dtls: DTLS 1.3 server finished invalid")
	}
	s.dtls13.serverFinished = append([]byte(nil), incomingRec.Data...)
	s.dtls13.keys = dtls13MakeKeySchedule(s.selectedCipherSuite, s.dtls13.selectedPsk, s.dtls13.clientHello, s.dtls13.serverHello, s.dtls13.encryptedExtensions, s.dtls13.serverFinished)

	clientFinished := newHandshake(handshakeType_Finished)
	clientFinished.Header.Sequence = 4
	verifyData := dtls13FinishedVerifyData(s.dtls13.keys.ClientHandshakeTrafficSecret, dtls13TranscriptHash(s.dtls13.clientHello, s.dtls13.serverHello, s.dtls13.encryptedExtensions, s.dtls13.serverFinished))
	clientFinished.Finished.Init13(verifyData)
	if err := s.writeDtls13EncryptedHandshake(clientFinished.Bytes(), s.dtls13.keys.ClientHandshakeKeys); err != nil {
		return err
	}
	s.finishDtls13Handshake(nil)
	return nil
}

func (s *session) processDtls13ClientFinished(incomingRec *record, incomingHs *handshake) error {
	expected := dtls13FinishedVerifyData(s.dtls13.keys.ClientHandshakeTrafficSecret, dtls13TranscriptHash(s.dtls13.clientHello, s.dtls13.serverHello, s.dtls13.encryptedExtensions, s.dtls13.serverFinished))
	if !hmac.Equal(expected, incomingHs.Finished.data) {
		s.handshake.state = "failed"
		return errors.New("dtls: DTLS 1.3 client finished invalid")
	}
	s.finishDtls13Handshake(nil)
	return nil
}

func (s *session) finishDtls13Handshake(err error) {
	if err != nil {
		s.handshake.state = "failed"
		s.handshake.err = err
	} else {
		s.handshake.state = "finished"
		s.handshake.err = nil
		s.handshake.completed = s.now()
	}
	if HandshakeCompleteCallback != nil {
		HandshakeCompleteCallback(s.peer, s.peerIdentity, s.now().Sub(s.started), err)
	}
	select {
	case s.handshake.done <- err:
	default:
	}
	if err == nil {
		close(s.handshake.done)
	}
}

func (s *session) writeDtls13PlainHandshake(raw []byte) error {
	rec := newRecord(ContentType_Handshake, 0, s.getNextSequence(), nil, raw)
	return s.peer.transport.WritePacket(rec.Bytes())
}

func (s *session) writeDtls13EncryptedHandshake(raw []byte, keys dtls13TrafficKeys) error {
	packet, err := dtls13ProtectRecord(s.selectedCipherSuite, keys, 2, s.nextDtls13Sequence(2), ContentType_Handshake, raw)
	if err != nil {
		return err
	}
	return s.peer.transport.WritePacket(packet)
}

func (s *session) writeDtls13ApplicationData(data []byte) error {
	if s.dtls13 == nil || s.dtls13.keys == nil {
		return errors.New("dtls: DTLS 1.3 keys not initialized")
	}
	var keys dtls13TrafficKeys
	if s.Type == SessionType_Client {
		keys = s.dtls13.keys.ClientApplicationKeys
	} else {
		keys = s.dtls13.keys.ServerApplicationKeys
	}
	packet, err := dtls13ProtectRecord(s.selectedCipherSuite, keys, 3, s.nextDtls13Sequence(3), ContentType_Appdata, data)
	if err != nil {
		return err
	}
	return s.peer.transport.WritePacket(packet)
}

func (s *session) parseDtls13Ciphertext(data []byte) (*record, []byte, error) {
	if s.dtls13 == nil || s.dtls13.keys == nil {
		return nil, nil, errors.New("dtls: DTLS 1.3 keys not initialized")
	}
	if len(data) < 5 {
		return nil, nil, errors.New("dtls: DTLS 1.3 record too small")
	}
	length := int(data[3])<<8 | int(data[4])
	if len(data) < 5+length {
		return nil, nil, errors.New("dtls: DTLS 1.3 record truncated")
	}
	raw := data[:5+length]
	epoch := uint64(data[0] & 0x03)
	var keys dtls13TrafficKeys
	switch epoch {
	case 2:
		if s.Type == SessionType_Client {
			keys = s.dtls13.keys.ServerHandshakeKeys
		} else {
			keys = s.dtls13.keys.ClientHandshakeKeys
		}
	case 3:
		if s.Type == SessionType_Client {
			keys = s.dtls13.keys.ServerApplicationKeys
		} else {
			keys = s.dtls13.keys.ClientApplicationKeys
		}
	default:
		return nil, nil, errors.New("dtls: unsupported DTLS 1.3 epoch")
	}
	protected, err := dtls13UnprotectRecord(s.selectedCipherSuite, keys, raw)
	if err != nil {
		return nil, nil, err
	}
	rec := &record{ContentType: protected.ContentType, Version: DtlsVersion13, Epoch: uint16(protected.Epoch), Sequence: protected.Sequence, Length: uint16(len(protected.Data)), Data: protected.Data}
	var rem []byte
	if len(data) > len(raw) {
		rem = data[len(raw):]
	}
	return rec, rem, nil
}

func dtls13ClientHelloBinderInput(incomingHs *handshake) []byte {
	clone := newHandshake(handshakeType_ClientHello)
	clone.Header = incomingHs.Header
	clone.ClientHello.Init(incomingHs.ClientHello.sessionId, incomingHs.ClientHello.randomBytes, incomingHs.ClientHello.cookie, incomingHs.ClientHello.cipherSuites, incomingHs.ClientHello.compressionMethods)
	clone.ClientHello.EnableSupportedVersions(incomingHs.ClientHello.supportedVersions)
	clone.ClientHello.EnablePskKeyExchangeModes(incomingHs.ClientHello.pskKeyExchangeModes)
	if len(incomingHs.ClientHello.pskIdentities) > 0 && len(incomingHs.ClientHello.pskBinders) > 0 {
		clone.ClientHello.pskIdentities = append([]dtls13PSKIdentity(nil), incomingHs.ClientHello.pskIdentities...)
		for _, binder := range incomingHs.ClientHello.pskBinders {
			clone.ClientHello.pskBinders = append(clone.ClientHello.pskBinders, make([]byte, len(binder)))
		}
	}
	raw := clone.Bytes()
	if len(incomingHs.ClientHello.pskBinders) == 0 {
		return raw
	}
	return raw[:len(raw)-len(incomingHs.ClientHello.pskBinders[0])]
}

func (s *session) dtls13Summary() string {
	if s.dtls13 == nil {
		return ""
	}
	return fmt.Sprintf("dtls13 identity[%s] cipher[%s]", s.peerIdentity, s.selectedCipherSuite)
}
