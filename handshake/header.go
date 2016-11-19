package handshake

import (
	"fmt"

	"github.com/bocajim/dtls/common"
)

type Header struct {
	HandshakeType HandshakeType
	Length        uint32
	Sequence      uint16
	FragmentOfs   uint32
	FragmentLen   uint32
}

func (h *Header) Parse(rdr *common.Reader) error {
	h.HandshakeType = HandshakeType(rdr.GetUint8())
	h.Length = rdr.GetUint24()
	h.Sequence = rdr.GetUint16()
	h.FragmentOfs = rdr.GetUint24()
	h.FragmentLen = rdr.GetUint24()
	return nil
}

func (h *Header) Bytes() []byte {
	w := common.NewWriter()
	w.PutUint8(uint8(h.HandshakeType))
	w.PutUint24(h.Length)
	w.PutUint16(h.Sequence)
	w.PutUint24(h.FragmentOfs)
	w.PutUint24(h.FragmentLen)

	return w.Bytes()
}

func (h *Header) SetLength(length int) {
	h.Length = uint32(length)
	h.FragmentLen = h.Length
	return
}

func (h *Header) Print() string {
	return fmt.Sprintf("handshakeType[%s] length[%d] sequence[%d] fragmentOfs[%d] fragmentLen[%d]", TypeToString(h.HandshakeType), h.Length, h.Sequence, h.FragmentOfs, h.FragmentLen)
}
