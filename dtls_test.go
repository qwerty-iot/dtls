package dtls

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&DtlsSuite{})

var server *Listener
var client *Listener

type DtlsSuite struct{}

func (s *DtlsSuite) SetUpSuite(c *C) {
	var err error

	SetLogLevel("debug")

	server, err = NewUdpListener(":5684", time.Second*5)
	server.AddCipherSuite(CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	server.AddCompressionMethod(CompressionMethod_Null)
	c.Assert(server, NotNil)
	c.Assert(err, IsNil)

	client, err = NewUdpListener(":0", time.Second*5)
	c.Assert(client, NotNil)
	c.Assert(err, IsNil)

	mks := NewKeystoreInMemory()
	SetKeyStores([]Keystore{mks})
	psk, _ := hex.DecodeString("00112233445566")
	mks.AddKey("myIdentity", psk)
}

/*
func (s *DtlsSuite) TestConnect(c *C) {

	peer, err := listener.AddPeer("127.0.0.1:5684", "oFIrQFrW8EWcZ5u7eGfrkw")
	c.Assert(err, IsNil)
	c.Log("finished connecting")

	coapMsg, _ := hex.DecodeString("400222E1B2726411283A65703D636C69656E7431056C743D333003623D55FF3C2F312F303E2C3C2F322F303E2C3C2F322F313E2C3C2F322F323E2C3C2F322F333E")
	err = peer.Write(coapMsg)
	c.Assert(err, IsNil)
	data, rsp := listener.Read()
	c.Assert(data, NotNil)
	c.Assert(rsp, NotNil)

}*/

func (s *DtlsSuite) TestSimple(c *C) {
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		data, replyTo := server.Read()

		c.Log("received packet")

		c.Assert(data, NotNil)
		c.Assert(replyTo, NotNil)

		replyTo.Write(data)
	}()

	peer, err := client.AddPeer("127.0.0.1:5684", "myIdentity")
	c.Assert(peer, NotNil)
	c.Assert(err, IsNil)
	c.Log("connected")

	seedData := randomBytes(20)

	peer.Write(seedData)

	data, err := peer.Read(time.Second * 5)
	c.Assert(err, IsNil)
	c.Assert(hex.EncodeToString(data), Equals, hex.EncodeToString(seedData))

	wg.Wait()
}

func (s *DtlsSuite) TestFailedClient(c *C) {

	peer, err := client.AddPeerWithParams(&PeerParams{Addr: "127.0.0.1:5687", Identity: "myIdentity", HandshakeTimeout: time.Second * 5})
	c.Assert(peer, IsNil)
	c.Assert(err.Error(), Equals, "dtls: timed out waiting for handshake to complete")

	peer, err = client.AddPeerWithParams(&PeerParams{Addr: "127.0.0.1:5684", Identity: "xxx", HandshakeTimeout: time.Second * 5})
	c.Assert(peer, IsNil)
	c.Assert(err.Error(), Equals, "dtls: no psk could be found")
}

/*
func (s *DtlsSuite) TestLoopback(c *C) {

	peer, err := listener.AddPeer(listener.transport.Local, "oFIrQFrW8EWcZ5u7eGfrkw")
	c.Assert(err, IsNil)
	c.Log("finished connecting")

	coapMsg, _ := hex.DecodeString("400222E1B2726411283A65703D636C69656E7431056C743D333003623D55FF3C2F312F303E2C3C2F322F303E2C3C2F322F313E2C3C2F322F323E2C3C2F322F333E")
	err = peer.Write(coapMsg)
	c.Assert(err, IsNil)
	data, rsp := listener.Read()
	c.Assert(data, NotNil)
	c.Assert(rsp, NotNil)(

}*/

/*
func (s *DtlsSuite) TestLeshan(c *C) {
	client, err := DtlsNewUdpClient("leshan.eclipse.org:5684")
	c.Assert(err, IsNil)

	psk, _ := hex.DecodeString("7CCDE14A5CF3B71C0C08C8B7F9E5")
	client.SetPskCredentials("oFIrQFrW8EWcZ5u7eGfrkw", psk)
	err = client.DoHandshake()
	c.Assert(err, IsNil)

	coapMsg, _ := hex.DecodeString("400222E1B2726411283A65703D636C69656E7431056C743D333003623D55FF3C2F312F303E2C3C2F322F303E2C3C2F322F313E2C3C2F322F323E2C3C2F322F333E")
	client.Write(coapMsg)
	client.Read()

}
*/
