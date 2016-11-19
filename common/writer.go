package common

import (
	"bytes"
	"encoding/binary"
)

type Writer struct {
	buf *bytes.Buffer
}

func NewWriter() *Writer {
	return &Writer{buf: new(bytes.Buffer)}
}

func (w *Writer) Bytes() []byte {
	return w.buf.Bytes()
}

func (w *Writer) PadTo(l int) {
	if w.buf.Len() < l {
		buf := make([]byte, l-w.buf.Len())
		w.PutBytes(buf)
	}
}

func (w *Writer) PutUint8(value uint8) {
	binary.Write(w.buf, binary.BigEndian, value)
	return
}

func (w *Writer) PutUint16(value uint16) {
	binary.Write(w.buf, binary.BigEndian, value)
	return
}

func (w *Writer) PutUint24(value uint32) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	w.buf.Write(buf[1:])
	return
}

func (w *Writer) PutUint32(value uint32) {
	binary.Write(w.buf, binary.BigEndian, value)
	return
}

func (w *Writer) PutUint48(value uint64) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	w.buf.Write(buf[2:])
	return
}

func (w *Writer) PutString(value string) {
	binary.Write(w.buf, binary.BigEndian, value)
	return
}

func (w *Writer) PutBytes(value []byte) {
	w.buf.Write(value)
	return
}
