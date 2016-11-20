package dtls

type serverHelloDone struct {
}

func (h *serverHelloDone) Init() {
	return
}

func (h *serverHelloDone) Parse(rdr *byteReader) error {
	return nil
}

func (h *serverHelloDone) Bytes() []byte {
	return nil
}

func (h *serverHelloDone) Print() string {
	return ""
}
