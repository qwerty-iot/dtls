dtls
======

[![Build Status](https://travis-ci.org/bocajim/dtls.svg?branch=master)](https://travis-ci.org/bocajim/dtls)
[![Coverage](http://gocover.io/_badge/github.com/bocajim/dtls)](http://gocover.io/github.com/bocajim/dtls)
[![GoDoc](https://godoc.org/github.com/bocajim/dtls?status.png)](http://godoc.org/github.com/bocajim/dtls)
https://github.com/bocajim/dtls

This package implements a [RFC-4347](https://tools.ietf.org/html/rfc4347) compliant DTLS client and server.  NOTE: This library is under active development and is not yet stable enough to be used in production.

Key Features
------------
* Pure go, no CGo
* Supports both client and server via UDP
* Supports TLS_PSK_WITH_AES_128_CCM_8 cipher [RFC-6655](https://tools.ietf.org/html/rfc6655)
* Supports pre-shared key authentication, does not support certificate based authentication
* Designed for OMA LWM2M comliance [LWM2M](http://technical.openmobilealliance.org/Technical/technical-information/release-program/current-releases/oma-lightweightm2m-v1-0)

Samples
-------
Keystore
```go
	mks := keystore.NewMemoryKeyStore()
	keystore.SetKeyStores([]keystore.KeyStore{mks})
	psk, _ := hex.DecodeString("00112233445566")
	mks.AddKey("myIdentity", psk)
```

Sample Client
```go
	listener, _ = NewUdpListener(":6000", time.Second*5)
	peer, err := listener.AddPeer("127.0.0.1:5684", "myIdentity")

	err = peer.Write("hello world")
	data, rsp := listener.Read()
```


Documentation
-------------

http://godoc.org/github.com/bocajim/dtls


License
-------

MIT

