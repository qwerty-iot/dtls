package dtls

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

const (
	dtls13LabelPrefix = "dtls13"

	tls13ExtBinderLabel = "ext binder"
	tls13ResBinderLabel = "res binder"
)

type dtls13TrafficKeys struct {
	Secret []byte
	Key    []byte
	IV     []byte
	SNKey  []byte
}

type dtls13KeySchedule struct {
	CipherSuite CipherSuite

	EarlySecret []byte
	BinderKey   []byte
	Handshake   []byte
	Master      []byte

	ClientHandshakeTrafficSecret   []byte
	ServerHandshakeTrafficSecret   []byte
	ClientApplicationTrafficSecret []byte
	ServerApplicationTrafficSecret []byte

	ClientHandshakeKeys   dtls13TrafficKeys
	ServerHandshakeKeys   dtls13TrafficKeys
	ClientApplicationKeys dtls13TrafficKeys
	ServerApplicationKeys dtls13TrafficKeys
}

func dtls13Hash() hash.Hash {
	return sha256.New()
}

func dtls13HashBytes(data ...[]byte) []byte {
	h := dtls13Hash()
	for _, b := range data {
		h.Write(b)
	}
	return h.Sum(nil)
}

func hkdfExtract(hash func() hash.Hash, salt []byte, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, hash().Size())
	}
	h := hmac.New(hash, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(hash func() hash.Hash, prk []byte, info []byte, length int) []byte {
	hashLen := hash().Size()
	n := (length + hashLen - 1) / hashLen
	var out []byte
	var t []byte
	for i := 1; i <= n; i++ {
		h := hmac.New(hash, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{byte(i)})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

func dtls13HkdfLabel(label string, context []byte, length int) []byte {
	fullLabel := append([]byte(dtls13LabelPrefix), []byte(label)...)
	w := newByteWriter()
	w.PutUint16(uint16(length))
	w.PutUint8(uint8(len(fullLabel)))
	w.PutBytes(fullLabel)
	w.PutUint8(uint8(len(context)))
	w.PutBytes(context)
	return w.Bytes()
}

func dtls13ExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	return hkdfExpand(dtls13Hash, secret, dtls13HkdfLabel(label, context, length), length)
}

func dtls13DeriveSecret(secret []byte, label string, messages ...[]byte) []byte {
	return dtls13ExpandLabel(secret, label, dtls13HashBytes(messages...), dtls13Hash().Size())
}

func dtls13TranscriptHash(messages ...[]byte) []byte {
	return dtls13HashBytes(messages...)
}

func dtls13FinishedVerifyData(baseKey []byte, transcriptHash []byte) []byte {
	finishedKey := dtls13ExpandLabel(baseKey, "finished", nil, dtls13Hash().Size())
	h := hmac.New(sha256.New, finishedKey)
	h.Write(transcriptHash)
	return h.Sum(nil)
}

func dtls13ExternalPSKBinder(psk []byte, truncatedClientHello []byte) []byte {
	earlySecret := hkdfExtract(dtls13Hash, nil, psk)
	binderKey := dtls13DeriveSecret(earlySecret, tls13ExtBinderLabel, nil)
	finishedKey := dtls13ExpandLabel(binderKey, "finished", nil, dtls13Hash().Size())
	h := hmac.New(sha256.New, finishedKey)
	h.Write(dtls13TranscriptHash(truncatedClientHello))
	return h.Sum(nil)
}

func dtls13MakeKeySchedule(cipherSuite CipherSuite, psk []byte, clientHello []byte, serverHello []byte, encryptedExtensions []byte, serverFinished []byte) *dtls13KeySchedule {
	zeroHash := dtls13HashBytes(nil)
	zeroSecret := make([]byte, dtls13Hash().Size())
	earlySecret := hkdfExtract(dtls13Hash, nil, psk)
	binderKey := dtls13DeriveSecret(earlySecret, tls13ExtBinderLabel, nil)
	derivedEarly := dtls13DeriveSecret(earlySecret, "derived", zeroHash)
	handshakeSecret := hkdfExtract(dtls13Hash, derivedEarly, zeroSecret)
	helloTranscript := dtls13TranscriptHash(clientHello, serverHello)
	clientHandshakeSecret := dtls13ExpandLabel(handshakeSecret, "c hs traffic", helloTranscript, dtls13Hash().Size())
	serverHandshakeSecret := dtls13ExpandLabel(handshakeSecret, "s hs traffic", helloTranscript, dtls13Hash().Size())
	derivedHandshake := dtls13DeriveSecret(handshakeSecret, "derived", zeroHash)
	masterSecret := hkdfExtract(dtls13Hash, derivedHandshake, zeroSecret)
	serverFinishedTranscript := dtls13TranscriptHash(clientHello, serverHello, encryptedExtensions, serverFinished)
	clientFinishedTranscript := serverFinishedTranscript
	clientApplicationSecret := dtls13ExpandLabel(masterSecret, "c ap traffic", clientFinishedTranscript, dtls13Hash().Size())
	serverApplicationSecret := dtls13ExpandLabel(masterSecret, "s ap traffic", serverFinishedTranscript, dtls13Hash().Size())

	return &dtls13KeySchedule{
		CipherSuite:                    cipherSuite,
		EarlySecret:                    earlySecret,
		BinderKey:                      binderKey,
		Handshake:                      handshakeSecret,
		Master:                         masterSecret,
		ClientHandshakeTrafficSecret:   clientHandshakeSecret,
		ServerHandshakeTrafficSecret:   serverHandshakeSecret,
		ClientApplicationTrafficSecret: clientApplicationSecret,
		ServerApplicationTrafficSecret: serverApplicationSecret,
		ClientHandshakeKeys:            dtls13TrafficKeysForSecret(cipherSuite, clientHandshakeSecret),
		ServerHandshakeKeys:            dtls13TrafficKeysForSecret(cipherSuite, serverHandshakeSecret),
		ClientApplicationKeys:          dtls13TrafficKeysForSecret(cipherSuite, clientApplicationSecret),
		ServerApplicationKeys:          dtls13TrafficKeysForSecret(cipherSuite, serverApplicationSecret),
	}
}

func dtls13TrafficKeysForSecret(cipherSuite CipherSuite, secret []byte) dtls13TrafficKeys {
	return dtls13TrafficKeys{
		Secret: secret,
		Key:    dtls13ExpandLabel(secret, "key", nil, cipherSuite.KeySize()),
		IV:     dtls13ExpandLabel(secret, "iv", nil, cipherSuite.IVSize()),
		SNKey:  dtls13ExpandLabel(secret, "sn", nil, cipherSuite.KeySize()),
	}
}
