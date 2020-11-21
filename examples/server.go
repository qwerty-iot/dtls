package main

import (
	"encoding/hex"
	"github.com/tartabit/dtls/v2"
	"time"
)

func main() {

	dtls.SetLogLevel("debug")
	dtls.DebugAll()

	listener, _ := dtls.NewUdpListener(":5684", time.Second*5)
	//listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_CCM_8)
	listener.AddCipherSuite(dtls.CipherSuite_TLS_PSK_WITH_AES_128_CBC_SHA256)
	listener.AddCompressionMethod(dtls.CompressionMethod_Null)

	mks := dtls.NewKeystoreInMemory()
	psk, _ := hex.DecodeString("11223344556677889900")
	mks.AddKey("qwerty-x1gen8", psk)
	dtls.SetKeyStores([]dtls.Keystore{mks})

	time.Sleep(time.Hour)
}
