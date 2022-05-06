dtls
======

[![Build Status](https://travis-ci.org/qwerty-iot/dtls.svg?branch=master)](https://travis-ci.org/qwerty-iot/dtls)
[![Coverage](http://gocover.io/_badge/github.com/qwerty-iot/dtls)](http://gocover.io/github.com/qwerty-iot/dtls)
[![GoDoc](https://godoc.org/github.com/qwerty-iot/dtls?status.png)](http://godoc.org/github.com/qwerty-iot/dtls)
[![License](https://img.shields.io/github/license/qwerty-iot/dtls)](https://opensource.org/licenses/MPL-2.0)
[![ReportCard](http://goreportcard.com/badge/github.com/qwerty-iot/dtls)](http://goreportcard.com/report/qwerty-iot/dtls)

https://github.com/qwerty-iot/dtls

Renamed from https://github.com/bocajim/dtls

This package implements a [RFC-4347](https://tools.ietf.org/html/rfc4347) compliant DTLS client and server.

Key Features
------------

* Pure go, no CGo
* Supports both client and server via UDP
* Supports TLS_PSK_WITH_AES_128_CCM_8 cipher [RFC-6655](https://tools.ietf.org/html/rfc6655)
* Supports TLS_PSK_WITH_AES_128_CBC_SHA256 cipher [RFC-5487](https://tools.ietf.org/html/rfc5487)
* Supports TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 cipher [RFC-7251](https://tools.ietf.org/html/rfc7251)
* Supports pre-shared key authentication
* Supports certificate based authentication
* Supports DTLS session resumption
* Supports persisting session data for resumption later
* Designed for OMA LWM2M
  comliance [LWM2M](http://technical.openmobilealliance.org/Technical/technical-information/release-program/current-releases/oma-lightweightm2m-v1-0)
* Support for Connection
  ID [RFC-9146 (Nov/19 draft)](https://datatracker.ietf.org/doc/html/draft-ietf-tls-dtls-connection-id-05)

TODO
----

* Implement session renegotiation
* Implement packet retransmission for handshake
* Implement out of order handshake processing
* Implement replay detection
* Implement client hello stateless cookie handling
* Improve parallel processing of incoming packets
* Implement Connection ID for latest RFC-9146 draft

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

Generating Certificates
-----------------------
The following commands can be used to generate certificates for testing:

```bash
# generate private key
openssl ecparam -out key.pem -name prime256v1 -genkey

# generate certificate
openssl req -new -key key.pem -x509 -nodes -days 3650 -out cert.pem
```

Documentation
-------------

http://godoc.org/github.com/qwerty-iot/dtls

License
-------

Mozilla Public License Version 2.0

NOTE: License was changed from MIT on 11/20/2020.

