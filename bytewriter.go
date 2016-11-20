package dtls

import (
	"bytes"
	"encoding/binary"
)

type byteWriter struct {
	buf *bytes.Buffer
}

func newByteWriter() *byteWriter {
	return &byteWriter{buf: new(bytes.Buffer)}
}

func (w *byteWriter) Bytes() []byte {
	return w.buf.Bytes()
}

func (w *byteWriter) PadTo(l int) {
	if w.buf.Len() < l {
		buf := make([]byte, l-w.buf.Len())
		w.PutBytes(buf)
	}
}

func (w *byteWriter) PutUint8(value uint8) {
	binary.Write(w.buf, binary.BigEndian, value)
	return
}

func (w *byteWriter) PutUint16(value uint16) {
	binary.Write(w.buf, binary.BigEndian, value)
	return
}

func (w *byteWriter) PutUint24(value uint32) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	w.buf.Write(buf[1:])
	return
}

func (w *byteWriter) PutUint32(value uint32) {
	binary.Write(w.buf, binary.BigEndian, value)
	return
}

func (w *byteWriter) PutUint48(value uint64) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	w.buf.Write(buf[2:])
	return
}

func (w *byteWriter) PutString(value string) {
	binary.Write(w.buf, binary.BigEndian, value)
	return
}

func (w *byteWriter) PutBytes(value []byte) {
	w.buf.Write(value)
	return
}
