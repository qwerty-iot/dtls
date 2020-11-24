package dtls

import "encoding/hex"

type Keystore interface {
	GetPsk(identity []byte, remoteAddr string) ([]byte, error)
}

var keystores []Keystore = []Keystore{NewKeystoreInMemory()}

func SetKeyStores(ks []Keystore) {
	keystores = ks
}

func GetPskFromKeystore(identity []byte, remoteAddr string) []byte {
	for _, ks := range keystores {
		if psk, err := ks.GetPsk(identity, remoteAddr); psk != nil {
			return psk
		} else if err != nil {
			return nil
		}
	}
	return nil
}

type KeystoreInMemory struct {
	keys map[string][]byte
}

func NewKeystoreInMemory() *KeystoreInMemory {
	return &KeystoreInMemory{keys: make(map[string][]byte)}
}

func (ks *KeystoreInMemory) AddKey(identity []byte, psk []byte) {
	ks.keys[hex.EncodeToString(identity)] = psk
	return
}

func (ks *KeystoreInMemory) GetPsk(identity []byte, remoteAddr string) ([]byte, error) {
	psk, found := ks.keys[hex.EncodeToString(identity)]
	if !found {
		return nil, nil
	}
	return psk, nil
}
