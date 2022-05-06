package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/qwerty-iot/dtls/v2"
)

var StopChannel chan string

type Backup struct {
	RemoteAddr string
	Cid        []byte
	Session    string
}

var sessions []Backup

func SessionImportCallback(peer *dtls.Peer) string {
	if cid := peer.SessionCid(); cid != nil {
		for _, s := range sessions {
			if string(s.Cid) == string(cid) {
				return s.Session
			}
		}
	} else {
		fmt.Println("No CID")
		ra := peer.RemoteAddr()
		for _, s := range sessions {
			if s.RemoteAddr == ra {
				return s.Session
			}
		}
	}
	return ""
}

func main() {

	StopChannel = make(chan string, 1)
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for s := range c {
			StopChannel <- fmt.Sprintf("Signal: %d.", s)
			time.Sleep(time.Second * 20)
			os.Exit(0)
		}
	}()

	dtls.SetLogLevel("debug")
	//dtls.DebugAll()
	dtls.SetExportSecret("foobar")
	dtls.SessionImportCallback = SessionImportCallback

	pj, _ := os.ReadFile("peers.json")
	if pj != nil && len(pj) > 0 {
		_ = json.Unmarshal(pj, &sessions)
	}

	/*cert, err := dtls.CertificateFromDisk("./examples/key.pem", "./examples/cert.pem")
	if err != nil {
		fmt.Printf("bad cert: %s\n", err.Error())
	}*/

	listener, err := dtls.NewUdpListener(":4433", time.Second*5)
	if err != nil {
		fmt.Printf("bad listener: %s\n", err.Error())
	}
	/*if cert != nil {
		listener.AddCipherSuite(dtls.CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
		listener.SetCertificate(*cert)
	}*/
	listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	//listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256)

	listener.AddCompressionMethod(dtls.CompressionMethod_Null)

	//listener.EnableConnectionId(8)

	// this code can be used to validate the certificate against a CA chain
	/*
		rootPEM, _ := ioutil.ReadFile("./examples/root.cert.pem")
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(rootPEM))
		if !ok {
			panic("failed to parse root certificate")
		}
		dtls.ValidateCertificateCallback = func(peer *dtls.Peer, certificate *x509.Certificate) error {
			opts := x509.VerifyOptions{
				Roots:         roots,
				Intermediates: x509.NewCertPool(),
			}
			if _, err := certificate.Verify(opts); err != nil {
				fmt.Printf("failed to verify certificate: " + err.Error() + "\n")
				return err
			} else {
				fmt.Printf("certificate is VALID!\n")
			}
			return nil
		}
	*/

	mks := dtls.NewKeystoreInMemory()
	psk, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mks.AddKey([]byte("mbedtls"), psk)
	dtls.SetKeyStores([]dtls.Keystore{mks})

	go Reader(listener)

	_ = <-StopChannel

	_ = listener.Shutdown()
	var backup []Backup
	listener.EachPeer(func(peer *dtls.Peer) {

		backup = append(backup, Backup{RemoteAddr: peer.RemoteAddr(), Cid: peer.SessionCid(), Session: peer.SessionExport()})
	})
	b, _ := json.Marshal(backup)
	_ = os.WriteFile("peers.json", b, 0644)
}

func Reader(listener *dtls.Listener) {
	for {
		data, peer := listener.Read()
		fmt.Printf("%s: %s\n", peer.RemoteAddr(), string(data))
		peer.Write(data)
	}
}
