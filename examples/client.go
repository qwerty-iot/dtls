package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/qwerty-iot/dtls/v2"
)

var ClientStopChannel chan string

func main() {

	ClientStopChannel = make(chan string, 1)
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for s := range c {
			ClientStopChannel <- fmt.Sprintf("Signal: %d.", s)
			time.Sleep(time.Second * 20)
			os.Exit(0)
		}
	}()

	dtls.SetLogLevel("debug")
	dtls.DebugAll()
	dtls.SetExportSecret("foobar")

	listener, err := dtls.NewUdpListener(":4444", time.Second*5)
	if err != nil {
		fmt.Printf("bad listener: %s\n", err.Error())
		os.Exit(1)
	}

	listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_GCM_SHA256)
	listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256)

	listener.AddCompressionMethod(dtls.CompressionMethod_Null)

	listener.EnableConnectionId(8)

	mks := dtls.NewKeystoreInMemory()
	psk, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	mks.AddKey([]byte("myid"), psk)
	dtls.SetKeyStores([]dtls.Keystore{mks})

	go ClientReader(listener)

	p, _ := listener.AddPeerWithParams(&dtls.PeerParams{Addr: "127.0.0.1:4433", Identity: []byte("myid"), HandshakeTimeout: time.Second * 20})

	p.Write([]byte("hello world"))

	_ = <-ClientStopChannel

	_ = listener.Shutdown()
}

func ClientReader(listener *dtls.Listener) {
	for {
		data, peer := listener.Read()
		fmt.Printf("%s: %s\n", peer.RemoteAddr(), string(data))
		peer.Write(data)
	}
}
