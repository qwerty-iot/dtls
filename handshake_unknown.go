package dtls

type unknown struct {
}

func (h *unknown) Init() {
	return
}

func (h *unknown) Parse(rdr *byteReader) error {
	return nil
}

func (h *unknown) Bytes() []byte {
	return nil
}

func (h *unknown) Print() string {
	return ""
}
