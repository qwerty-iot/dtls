package dtls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type ContentType uint8

const (
	ContentType_ChangeCipherSpec ContentType = 20
	ContentType_Alert                        = 21
	ContentType_Handshake                    = 22
	ContentType_Appdata                      = 23
)

type record struct {
	ContentType ContentType
	Version     uint16
	Epoch       uint16
	Sequence    uint64
	Length      uint16
	Data        []byte
}

func newRecord(contentType ContentType, epoch uint16, sequence uint64, data []byte) *record {
	return &record{ContentType: contentType, Version: DtlsVersion12, Epoch: epoch, Sequence: sequence, Data: data, Length: uint16(len(data))}
}

func parseRecord(raw []byte) (*record, []byte, error) {

	rawLen := len(raw)
	if rawLen < 13 {
		return nil, nil, errors.New("dtls: record too small")
	}

	r := &record{}
	r.ContentType = ContentType(raw[0])
	r.Version = binary.BigEndian.Uint16(raw[1:])
	i64 := binary.BigEndian.Uint64(raw[3:])
	r.Epoch = uint16(i64 >> 48)
	r.Sequence = i64 & 0x0000ffffffffffff
	r.Length = binary.BigEndian.Uint16(raw[11:])

	//if int(r.Length) < rawLen-13 {
	//	return nil, nil, errors.New("dtls: record data size does not match length")
	//}
	r.Data = raw[13 : 13+r.Length]

	var rem []byte
	if rawLen > 13+int(r.Length) {
		rem = raw[13+int(r.Length):]
	}
	return r, rem, nil
}

func (r *record) SetData(data []byte) {
	r.Data = data
	r.Length = uint16(len(data))
}

func (r *record) Bytes() []byte {
	w := newByteWriter()
	w.PutUint8(uint8(r.ContentType))
	w.PutUint16(r.Version)
	w.PutUint16(r.Epoch)
	w.PutUint48(r.Sequence)
	w.PutUint16(r.Length)
	w.PutBytes(r.Data)
	return w.Bytes()
}

func (r *record) IsHandshake() bool {
	if r.ContentType == ContentType_Handshake {
		return true
	}
	return false
}

func (r *record) Print() string {
	return fmt.Sprintf("contentType[%d] version[%X] epoch[%d] seq[%d] length[%d] data[%X]", r.ContentType, r.Version, r.Epoch, r.Sequence, r.Length, r.Data)
}
