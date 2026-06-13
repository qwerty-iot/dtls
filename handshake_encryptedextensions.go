package dtls

import "fmt"

type encryptedExtensions struct {
	raw []byte
}

func (h *encryptedExtensions) Init() {
	h.raw = nil
}

func (h *encryptedExtensions) Parse(rdr *byteReader, size int) error {
	if size > 0 {
		h.raw = rdr.GetBytes(size)
	}
	return nil
}

func (h *encryptedExtensions) Bytes() []byte {
	w := newByteWriter()
	w.PutUint16(0)
	return w.Bytes()
}

func (h *encryptedExtensions) Print() string {
	return fmt.Sprintf("extensions[%d]", len(h.raw))
}
