package dtls

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/bocajim/dtls/common"
	"github.com/bocajim/dtls/keystore"
)

func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&DtlsSuite{})

var server *Listener
var client *Listener

type DtlsSuite struct{}

func (s *DtlsSuite) SetUpSuite(c *C) {
	var err error
	server, err = NewUdpListener(":5684", time.Second*5)
	c.Assert(server, NotNil)
	c.Assert(err, IsNil)

	client, err = NewUdpListener(":0", time.Second*5)
	c.Assert(client, NotNil)
	c.Assert(err, IsNil)

	mks := keystore.NewMemoryKeyStore()
	keystore.SetKeyStores([]keystore.KeyStore{mks})
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

	seedData := common.RandomBytes(20)

	peer.Write(seedData)

	data, replyFrom := client.Read()
	c.Assert(hex.EncodeToString(data), Equals, hex.EncodeToString(seedData))
	c.Assert(replyFrom, NotNil)
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
