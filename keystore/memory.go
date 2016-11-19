package keystore

type MemoryKeyStore struct {
	keys map[string][]byte
}

func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{keys: make(map[string][]byte)}
}

func (ks *MemoryKeyStore) AddKey(identity string, psk []byte) {
	ks.keys[identity] = psk
	return
}

func (ks *MemoryKeyStore) GetPsk(identity string) []byte {
	psk, found := ks.keys[identity]
	if !found {
		return nil
	}
	return psk
}
