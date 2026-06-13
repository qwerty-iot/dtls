package dtls

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDtls13HkdfLabelUsesDtlsPrefix(t *testing.T) {
	label := dtls13HkdfLabel("key", nil, 16)
	require.Equal(t, "00100964746c7331336b657900", hex.EncodeToString(label))
}

func TestDtls13ExternalPSKBinder(t *testing.T) {
	psk := []byte("secret")
	clientHello := []byte("client hello without binders")
	binder := dtls13ExternalPSKBinder(psk, clientHello)
	require.Len(t, binder, 32)
	require.True(t, hmacEqual(binder, dtls13ExternalPSKBinder(psk, clientHello)))
	require.False(t, hmacEqual(binder, dtls13ExternalPSKBinder([]byte("wrong"), clientHello)))
}

func TestDtls13RecordProtection(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	keys := dtls13TrafficKeysForSecret(CipherSuite_TLS_AES_128_GCM_SHA256, secret)
	raw, err := dtls13ProtectRecord(CipherSuite_TLS_AES_128_GCM_SHA256, keys, 3, 7, ContentType_Appdata, []byte("hello"))
	require.NoError(t, err)
	require.True(t, raw[0]&0xE0 == dtls13UnifiedHeaderFixedBits)

	rec, err := dtls13UnprotectRecord(CipherSuite_TLS_AES_128_GCM_SHA256, keys, raw)
	require.NoError(t, err)
	require.Equal(t, uint64(3), rec.Epoch)
	require.Equal(t, uint64(7), rec.Sequence)
	require.Equal(t, ContentType(ContentType_Appdata), rec.ContentType)
	require.Equal(t, []byte("hello"), rec.Data)

	raw[len(raw)-1] ^= 0x01
	_, err = dtls13UnprotectRecord(CipherSuite_TLS_AES_128_GCM_SHA256, keys, raw)
	require.Error(t, err)
}

func TestDtls13HelloExtensionsRoundTrip(t *testing.T) {
	hs := newHandshake(handshakeType_ClientHello)
	random := append([]byte{0, 0, 0, 1}, bytes.Repeat([]byte{0x11}, 28)...)
	require.NoError(t, hs.ClientHello.Init(nil, random, nil, []CipherSuite{CipherSuite_TLS_AES_128_GCM_SHA256}, []CompressionMethod{CompressionMethod_Null}))
	hs.ClientHello.EnableSupportedVersions([]uint16{DtlsVersion13, DtlsVersion12})
	hs.ClientHello.EnablePskKeyExchangeModes([]uint8{Dtls13PskKeyExchangeModePSKOnly})
	hs.ClientHello.EnableExternalPSK([]byte("identity"), bytes.Repeat([]byte{0x22}, 32))

	parsed, err := parseHandshake(hs.Bytes())
	require.NoError(t, err)
	require.True(t, parsed.ClientHello.SupportsVersion(DtlsVersion13))
	require.Equal(t, []uint8{Dtls13PskKeyExchangeModePSKOnly}, parsed.ClientHello.pskKeyExchangeModes)
	require.Equal(t, []byte("identity"), parsed.ClientHello.pskIdentities[0].Identity)
	require.Equal(t, bytes.Repeat([]byte{0x22}, 32), parsed.ClientHello.pskBinders[0])

	sh := newHandshake(handshakeType_ServerHello)
	sh.ServerHello.Init13(random, nil, CipherSuite_TLS_AES_128_GCM_SHA256, 0)
	parsed, err = parseHandshake(sh.Bytes())
	require.NoError(t, err)
	require.Equal(t, DtlsVersion13, parsed.ServerHello.supportedVersion)
	require.NotNil(t, parsed.ServerHello.selectedPsk)
	require.Equal(t, uint16(0), *parsed.ServerHello.selectedPsk)
}

func TestDtls13ExternalPSKClientServer(t *testing.T) {
	mks := NewKeystoreInMemory()
	mks.AddKey([]byte("dtls13Identity"), []byte("dtls13-psk-secret"))
	SetKeyStores([]Keystore{mks})

	server, err := NewUdpListener(":5693", time.Second*5)
	require.NoError(t, err)
	defer server.Shutdown()
	server.SetProtocolVersions(DtlsVersion13)
	server.AddCipherSuite(CipherSuite_TLS_AES_128_GCM_SHA256)
	server.AddCompressionMethod(CompressionMethod_Null)

	client, err := NewUdpListener(":0", time.Second*5)
	require.NoError(t, err)
	defer client.Shutdown()
	client.SetProtocolVersions(DtlsVersion13)
	client.AddCipherSuite(CipherSuite_TLS_AES_128_GCM_SHA256)
	client.AddCompressionMethod(CompressionMethod_Null)

	done := make(chan struct{})
	go func() {
		data, replyTo := server.Read()
		require.Equal(t, []byte("ping13"), data)
		require.NoError(t, replyTo.Write([]byte("pong13")))
		close(done)
	}()

	peer, err := client.AddPeerWithParams(&PeerParams{Addr: "127.0.0.1:5693", Identity: []byte("dtls13Identity"), HandshakeTimeout: time.Second * 5})
	require.NoError(t, err)
	require.Equal(t, "TLS_AES_128_GCM_SHA256(0x1301)", peer.CipherSuite())
	require.NoError(t, peer.Write([]byte("ping13")))
	reply, err := peer.Read(time.Second * 5)
	require.NoError(t, err)
	require.Equal(t, []byte("pong13"), reply)

	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("server did not receive DTLS 1.3 application data")
	}
}

func hmacEqual(a []byte, b []byte) bool {
	return bytes.Equal(a, b)
}
