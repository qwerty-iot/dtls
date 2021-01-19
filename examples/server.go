package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/qwerty-iot/dtls/v2"
)

func main() {

	dtls.SetLogLevel("debug")
	dtls.DebugAll()

	cert, err := dtls.CertificateFromDisk("./examples/key.pem", "./examples/cert.pem")
	if err != nil {
		fmt.Printf("bad cert: %s\n", err.Error())
	}

	listener, _ := dtls.NewUdpListener(":5684", time.Second*5)
	if cert != nil {
		listener.AddCipherSuite(dtls.CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
		listener.SetCertificate(*cert)
	}
	listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256)

	listener.AddCompressionMethod(dtls.CompressionMethod_Null)

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
	psk, _ := hex.DecodeString("11223344556677889900")
	mks.AddKey([]byte("mydevice"), psk)
	dtls.SetKeyStores([]dtls.Keystore{mks})

	time.Sleep(time.Hour)
}
