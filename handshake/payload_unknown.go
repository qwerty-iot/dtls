package handshake

import (
	"io"
)

type unknown struct {
}

func (h *unknown) Init() {
}

func (h *unknown) Parse(rdr io.Reader) error {
	return nil
}

func (h *unknown) Bytes() []byte {
	return nil
}

func (h *unknown) Print() string {
	return ""
}
