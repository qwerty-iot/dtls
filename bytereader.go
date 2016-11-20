package dtls

import (
	"bytes"
	"encoding/binary"
	"io"
)

type byteReader struct {
	rdr io.Reader
}

func newByteReader(data []byte) *byteReader {
	return &byteReader{rdr: bytes.NewReader(data)}
}

func (r *byteReader) GetUint8() uint8 {
	raw := make([]byte, 1)
	r.rdr.Read(raw)
	return raw[0]
}

func (r *byteReader) GetUint16() uint16 {
	raw := make([]byte, 2)
	r.rdr.Read(raw)
	return binary.BigEndian.Uint16(raw)
}

func (r *byteReader) GetUint24() uint32 {
	raw := make([]byte, 3, 4)
	r.rdr.Read(raw)
	raw = append(raw, 0x00)
	u24 := binary.BigEndian.Uint32(raw)
	return u24 >> 8
}

func (r *byteReader) GetUint32() uint32 {
	raw := make([]byte, 4)
	r.rdr.Read(raw)
	return binary.BigEndian.Uint32(raw)
}

func (r *byteReader) GetBytes(l int) []byte {
	raw := make([]byte, l)
	r.rdr.Read(raw)
	return raw
}
