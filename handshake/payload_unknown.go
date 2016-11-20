package handshake

import (
	"github.com/bocajim/dtls/common"
)

type unknown struct {
}

func (h *unknown) Init() {
	return
}

func (h *unknown) Parse(rdr *common.Reader) error {
	return nil
}

func (h *unknown) Bytes() []byte {
	return nil
}

func (h *unknown) Print() string {
	return ""
}
