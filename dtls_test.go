package dtls

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestDtlsSuite(t *testing.T) {
	suite.Run(t, new(DtlsSuite))
}

type DtlsSuite struct {
	suite.Suite
	server *Listener
	client *Listener
}

func (s *DtlsSuite) Log(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}

func (s *DtlsSuite) SetupSuite() {
	var err error
	SetLogLevel("info")
	//DebugAll()

	s.server, err = NewUdpListener(":5684", time.Second*5)
	assert.Nil(s.T(), err)
	s.server.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	s.server.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256)
	s.server.AddCompressionMethod(CompressionMethod_Null)
	assert.NotNil(s.T(), s.server)

	s.client, err = NewUdpListener(":0", time.Second*5)
	s.client.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	s.client.AddCompressionMethod(CompressionMethod_Null)
	assert.NotNil(s.T(), s.client)
	assert.Nil(s.T(), err)

	mks := NewKeystoreInMemory()
	psk, _ := hex.DecodeString("00112233445566")
	mks.AddKey([]byte("myIdentity"), psk)
	psk, _ = hex.DecodeString("7CCDE14A5CF3B71C0C08C8B7F9E5")
	mks.AddKey([]byte("oFIrQFrW8EWcZ5u7eGfrkw"), psk)
	SetKeyStores([]Keystore{mks})
}

/*func (s *DtlsSuite) TestConnect () {

	transport, err := s.client.AddPeer("127.0.0.1:5684", "oFIrQFrW8EWcZ5u7eGfrkw")
	assert.Nil(s.T(), err)
	s.Log("finished connecting")

	coapMsg, _ := hex.DecodeString("400222E1B2726411283A65703D636C69656E7431056C743D333003623D55FF3C2F312F303E2C3C2F322F303E2C3C2F322F313E2C3C2F322F323E2C3C2F322F333E")
	err = transport.Write(coapMsg)
	assert.Nil(s.T(), err)
	data, err := transport.Read(time.Second * 5)
	assert.NotNil(s.T(),data)
	assert.Nil(s.T(), err)

}*/

func (s *DtlsSuite) TestSimple() {

	go func() {
		cnt := 2
		for {
			s.Log("receiving packet")
			data, replyTo := s.server.Read()

			s.Log("received packet")

			assert.NotNil(s.T(), data)
			assert.NotNil(s.T(), replyTo)

			_ = replyTo.Write(data)
			cnt -= 1
			if cnt == 0 {
				break
			}
		}
		s.Log("ending reader")
	}()

	peer, err := s.client.AddPeer("127.0.0.1:5684", []byte("myIdentity"))
	assert.NotNil(s.T(), peer)
	assert.Nil(s.T(), err)
	s.Log("connected")

	seedData := randomBytes(20)

	_ = peer.Write(seedData)

	data, err := peer.Read(time.Second * 5)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), hex.EncodeToString(seedData), hex.EncodeToString(data))

	seedData = randomBytes(20)

	_ = peer.Write(seedData)

	data, err = peer.Read(time.Second * 5)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), hex.EncodeToString(seedData), hex.EncodeToString(data))

}

func (s *DtlsSuite) TestCbcCipher() {

	go func() {
		cnt := 2
		for {
			s.Log("receiving packet")
			data, replyTo := s.server.Read()

			s.Log("received packet")

			assert.NotNil(s.T(), data)
			assert.NotNil(s.T(), replyTo)

			_ = replyTo.Write(data)
			cnt -= 1
			if cnt == 0 {
				break
			}
		}
		s.Log("ending reader")
	}()

	client2, err := NewUdpListener(":0", time.Second*5)
	assert.NotNil(s.T(), client2)
	assert.Nil(s.T(), err)

	client2.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256)
	client2.AddCompressionMethod(CompressionMethod_Null)

	peer, err := client2.AddPeer("127.0.0.1:5684", []byte("myIdentity"))
	assert.NotNil(s.T(), peer)
	assert.Nil(s.T(), err)
	s.Log("connected")

	seedData := randomBytes(20)

	_ = peer.Write(seedData)

	data, err := peer.Read(time.Second * 5)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), hex.EncodeToString(seedData), hex.EncodeToString(data))

	seedData = randomBytes(20)

	_ = peer.Write(seedData)

	data, err = peer.Read(time.Second * 5)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), hex.EncodeToString(seedData), hex.EncodeToString(data))

}

func (s *DtlsSuite) TestReconnects() {
	go func() {
		cnt := 2
		for {
			s.Log("server receiving packet")
			data, replyTo := s.server.Read()

			s.Log("received packet")

			assert.NotNil(s.T(), data)
			assert.NotNil(s.T(), replyTo)

			replyTo.Write(data)
			cnt -= 1
			if cnt == 0 {
				break
			}
		}
		s.Log("ending reader")
	}()

	client2, err := NewUdpListener(":6000", time.Second*5)
	assert.NotNil(s.T(), client2)
	assert.Nil(s.T(), err)

	client2.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	client2.AddCompressionMethod(CompressionMethod_Null)

	transport, err := client2.AddPeer("127.0.0.1:5684", []byte("myIdentity"))
	assert.NotNil(s.T(), transport)
	assert.Nil(s.T(), err)
	s.Log("client2 connected")

	seedData := randomBytes(20)

	_ = transport.Write(seedData)

	data, err := transport.Read(time.Second * 5)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), hex.EncodeToString(seedData), hex.EncodeToString(data))

	err = client2.Shutdown()
	assert.Nil(s.T(), err)
	s.Log("client2 shutdown")

	client3, err := NewUdpListener(":6000", time.Second*5)
	assert.NotNil(s.T(), client3)
	assert.Nil(s.T(), err)

	client3.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	client3.AddCompressionMethod(CompressionMethod_Null)

	transport, err = client3.AddPeer("127.0.0.1:5684", []byte("myIdentity"))
	assert.NotNil(s.T(), transport)
	assert.Nil(s.T(), err)
	s.Log("client3 connected")

	seedData = randomBytes(20)

	_ = transport.Write(seedData)

	data, err = transport.Read(time.Second * 5)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), hex.EncodeToString(seedData), hex.EncodeToString(data))

	_ = client3.Shutdown()
	assert.Nil(s.T(), err)
}

/*
func (s *DtlsSuite) TestResume() {

	go func() {
		cnt := 2
		for {
			s.Log("receiving packet")
			data, replyTo := s.server.Read()

			s.Log("received packet")

			assert.NotNil(s.T(), data)
			assert.NotNil(s.T(), replyTo)

			_ = replyTo.Write(data)
			cnt -= 1
			if cnt == 0 {
				break
			}
		}
		s.Log("ending reader")
	}()

	client2, err := NewUdpListener(":6001", time.Second*5)
	assert.NotNil(s.T(), client2)
	assert.Nil(s.T(), err)

	client2.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	client2.AddCompressionMethod(CompressionMethod_Null)

	transport, err := client2.AddPeer("127.0.0.1:5684", []byte("myIdentity"))
	assert.NotNil(s.T(), transport)
	assert.Nil(s.T(), err)
	s.Log("connected")

	//save sessionId
	sessionId := transport.session.Id

	seedData := randomBytes(20)

	transport.Write(seedData)

	data, err := transport.Read(time.Second * 5)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), hex.EncodeToString(seedData), hex.EncodeToString(data))

	err = client2.Shutdown()
	assert.Nil(s.T(), err)

	client3, err := NewUdpListener(":6001", time.Second*5)
	assert.NotNil(s.T(), client3)
	assert.Nil(s.T(), err)

	client3.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	client3.AddCompressionMethod(CompressionMethod_Null)

	transport, err = client3.AddPeerWithParams(&PeerParams{Addr: "127.0.0.1:5684", peerIdentity: []byte("myIdentity"), SessionId: sessionId, HandshakeTimeout: time.Second * 20})
	assert.NotNil(s.T(), transport)
	assert.Nil(s.T(), err)

	s.Log("connected")
	assert.Equal(s.T(), hex.EncodeToString(transport.session.Id), hex.EncodeToString(sessionId))

	seedData = randomBytes(20)

	_ = transport.Write(seedData)

	data, err = transport.Read(time.Second * 5)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), hex.EncodeToString(seedData), hex.EncodeToString(data))

	_ = client3.Shutdown()
	assert.Nil(s.T(), err)

}
*/

func (s *DtlsSuite) TestFailedClient() {

	transport, err := s.client.AddPeerWithParams(&PeerParams{Addr: "127.0.0.1:5687", Identity: []byte("myIdentity"), HandshakeTimeout: time.Second * 5})
	assert.Nil(s.T(), transport)
	assert.EqualError(s.T(), err, "dtls: timed out waiting for handshake to complete")

	transport, err = s.client.AddPeerWithParams(&PeerParams{Addr: "127.0.0.1:5684", Identity: []byte("xxx"), HandshakeTimeout: time.Second * 5})
	assert.Nil(s.T(), transport)
	assert.EqualError(s.T(), err, "dtls: no psk could be found")
}

/*
func (s *DtlsSuite) TestLoopback () {

	transport, err := listener.AddPeer(listener.transport.Local, "oFIrQFrW8EWcZ5u7eGfrkw")
	assert.Nil(s.T(), err)
	s.Log("finished connecting")

	coapMsg, _ := hex.DecodeString("400222E1B2726411283A65703D636C69656E7431056C743D333003623D55FF3C2F312F303E2C3C2F322F303E2C3C2F322F313E2C3C2F322F323E2C3C2F322F333E")
	err = transport.Write(coapMsg)
	assert.Nil(s.T(), err)
	data, rsp := listener.Read()
	assert.NotNil(s.T(),data)
	c.Assert(rsp, NotNil)(

}*/

/*
func (s *DtlsSuite) TestLeshan () {

	leshan, err := NewUdpListener(":0", time.Second*5)
	c.Assert(leshan, NotNil)
	assert.Nil(s.T(), err)

	transport, err := s.client.AddPeer("leshan.eclipse.org:5684", "oFIrQFrW8EWcZ5u7eGfrkw")
	assert.NotNil(s.T(), transport)
	assert.Nil(s.T(), err)
	s.Log("connected")

	client, err := DtlsNewUdpClient("leshan.eclipse.org:5684")
	assert.Nil(s.T(), err)

	coapMsg, _ := hex.DecodeString("400222E1B2726411283A65703D636C69656E7431056C743D333003623D55FF3C2F312F303E2C3C2F322F303E2C3C2F322F313E2C3C2F322F323E2C3C2F322F333E")
	client.Write(coapMsg)
	client.Read()

}*/
