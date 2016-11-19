package record

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bocajim/dtls/common"
)

type ContentType uint8

const (
	ContentType_ChangeCipherSpec ContentType = 20
	ContentType_Alert                        = 21
	ContentType_Handshake                    = 22
	ContentType_Appdata                      = 23
	DtlsVersion12                uint16      = 0xFEFD
)

type Record struct {
	ContentType ContentType
	Version     uint16
	Epoch       uint16
	Sequence    uint64
	Length      uint16
	Data        []byte
}

func New(contentType ContentType) *Record {
	return &Record{ContentType: contentType, Version: DtlsVersion12}
}

func ParseRecord(raw []byte) (*Record, []byte, error) {

	rawLen := len(raw)
	if rawLen < 13 {
		return nil, nil, errors.New("dtls: record too small")
	}

	r := &Record{}
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

func (r *Record) SetData(data []byte) {
	r.Data = data
	r.Length = uint16(len(data))
}

func (r *Record) Bytes() []byte {
	w := common.NewWriter()
	w.PutUint8(uint8(r.ContentType))
	w.PutUint16(r.Version)
	w.PutUint16(r.Epoch)
	w.PutUint48(r.Sequence)
	w.PutUint16(r.Length)
	w.PutBytes(r.Data)
	return w.Bytes()
}

func (r *Record) IsHandshake() bool {
	if r.ContentType == ContentType_Handshake {
		return true
	}
	return false
}

func (r *Record) Print() string {
	return fmt.Sprintf("contentType[%d] version[%X] epoch[%d] seq[%d] length[%d] data[%X]", r.ContentType, r.Version, r.Epoch, r.Sequence, r.Length, r.Data)
}
