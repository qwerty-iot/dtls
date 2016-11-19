package handshake

import (
	"github.com/bocajim/dtls/common"
)

type serverHelloDone struct {
}

func (h *serverHelloDone) Init() {
}

func (h *serverHelloDone) Parse(rdr *common.Reader) error {
	return nil
}

func (h *serverHelloDone) Bytes() []byte {
	return nil
}

func (h *serverHelloDone) Print() string {
	return ""
}
