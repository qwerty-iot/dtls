package keystore

type KeyStore interface {
	GetPsk(identity string) []byte
}

var keystores []KeyStore

func SetKeyStores(ks []KeyStore) {
	keystores = ks
}

func GetPsk(identity string) []byte {
	for _, ks := range keystores {
		if psk := ks.GetPsk(identity); psk != nil {
			return psk
		}
	}
	return nil
}
