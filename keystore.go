package dtls

type Keystore interface {
	GetPsk(identity string) []byte
}

var keystores []Keystore = []Keystore{NewKeystoreInMemory()}

func SetKeyStores(ks []Keystore) {
	keystores = ks
}

func GetPskFromKeystore(identity string) []byte {
	for _, ks := range keystores {
		if psk := ks.GetPsk(identity); psk != nil {
			return psk
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

func (ks *KeystoreInMemory) AddKey(identity string, psk []byte) {
	ks.keys[identity] = psk
	return
}

func (ks *KeystoreInMemory) GetPsk(identity string) []byte {
	psk, found := ks.keys[identity]
	if !found {
		return nil
	}
	return psk
}
