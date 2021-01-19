// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"path/filepath"
	"strings"
)

func CertificateFromDisk(keyPath string, certificatePath string) (*tls.Certificate, error) {
	privateKey, err := privateKeyLoad(keyPath)
	if err != nil {
		return nil, err
	}

	certificate, err := certificateLoad(certificatePath)
	if err != nil {
		return nil, err
	}

	certificate.PrivateKey = privateKey

	return certificate, nil
}

func privateKeyLoad(path string) (crypto.PrivateKey, error) {
	rawData, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(rawData)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("dtls: private key has invalid format")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := key.(type) {
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("dtls: invalid private key type")
		}
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("dtls: no private key found")
}

func certificateLoad(path string) (*tls.Certificate, error) {
	rawData, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var certificate tls.Certificate

	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, errors.New("dtls: certificate has invalid format")
		}

		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		rawData = rest
	}

	if len(certificate.Certificate) == 0 {
		return nil, errors.New("dtls: no certificates found")
	}

	return &certificate, nil
}
