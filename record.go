// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"errors"
	"fmt"
)

type ContentType uint8

const (
	ContentType_ChangeCipherSpec ContentType = 20
	ContentType_Alert                        = 21
	ContentType_Handshake                    = 22
	ContentType_Appdata                      = 23
	ContentType_Appdata_Cid                  = 25
)

type record struct {
	ContentType ContentType
	Version     uint16
	Epoch       uint16
	Sequence    uint64
	Length      uint16
	Cid         []byte
	Data        []byte
}

func newRecord(contentType ContentType, epoch uint16, sequence uint64, cid []byte, data []byte) *record {
	return &record{ContentType: contentType, Version: DtlsVersion12, Epoch: epoch, Sequence: sequence, Cid: cid, Data: data, Length: uint16(len(data))}
}

func parseRecord(raw []byte) (*record, []byte, error) {

	rawLen := len(raw)
	if rawLen < 13 {
		return nil, nil, errors.New("dtls: record too small")
	}

	br := newByteReader(raw)

	r := &record{}
	r.ContentType = ContentType(br.GetUint8())
	r.Version = br.GetUint16()
	i64 := br.GetUint64()
	r.Epoch = uint16(i64 >> 48)
	r.Sequence = i64 & 0x0000ffffffffffff
	if r.ContentType == ContentType_Appdata_Cid {
		cidLen := br.GetUint8()
		if cidLen > 0 {
			cid := br.GetBytes(int(cidLen))
			r.Cid = append([]byte{cidLen}, cid...)
		}
	}
	r.Length = br.GetUint16()

	if r.Version != DtlsVersion12 && r.Version != DtlsVersion10 {
		return nil, nil, errors.New("dtls version not supported")
	}

	//if int(r.Length) < rawLen-13 {
	//	return nil, nil, errors.New("dtls: record data size does not match length")
	//}
	r.Data = br.GetBytes(int(r.Length))

	var rem []byte
	if rawLen > br.Offset() {
		rem = raw[br.Offset():]
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
	if r.ContentType == ContentType_Appdata_Cid && r.Cid != nil {
		w.PutBytes(r.Cid)
	}
	w.PutUint16(r.Length)
	w.PutBytes(r.Data)
	return w.Bytes()
}

func (r *record) IsHandshake() bool {
	if r.ContentType == ContentType_Handshake || r.ContentType == ContentType_ChangeCipherSpec {
		return true
	}
	return false
}

func (r *record) IsAppData() bool {
	if r.ContentType == ContentType_Appdata || r.ContentType == ContentType_Appdata_Cid {
		return true
	}
	return false
}

func (r *record) IsAlert() bool {
	if r.ContentType == ContentType_Alert {
		return true
	}
	return false
}

func (r *record) TypeString() string {
	switch r.ContentType {
	case ContentType_ChangeCipherSpec:
		return "ChangeCipherSpec(20)"
	case ContentType_Alert:
		return "Alert(21)"
	case ContentType_Handshake:
		return "Handshake(22)"
	case ContentType_Appdata:
		return "AppData(23)"
	case ContentType_Appdata_Cid:
		return "AppData_Cid(25)"
	default:
		return fmt.Sprintf("Unknown(%d)", r.ContentType)
	}
}

func (r *record) Print() string {
	return fmt.Sprintf("contentType[%s] version[%X] epoch[%d] seq[%d] length[%d] data[%X]", r.TypeString(), r.Version, r.Epoch, r.Sequence, r.Length, r.Data)
}
