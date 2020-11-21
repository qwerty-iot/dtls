package dtls

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestRecordSuite(t *testing.T) {
	suite.Run(t, new(RecordSuite))
}

type RecordSuite struct {
	suite.Suite
}

func (s *RecordSuite) Log(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}

func (s *RecordSuite) TestRecordDecode() {
	rb, _ := hex.DecodeString("16fefd000000000000000100560100004a000100000000004afefd00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db60020d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d80002c0a80100")

	rec, rem, err := parseRecord(rb)

	assert.Nil(s.T(), err)
	assert.Nil(s.T(), rem)
	assert.NotNil(s.T(), rec)

	assert.Equal(s.T(), ContentType(ContentType_Handshake), rec.ContentType)
	assert.Equal(s.T(), DtlsVersion12, rec.Version)
	assert.Equal(s.T(), uint16(0), rec.Epoch)
	assert.Equal(s.T(), uint64(1), rec.Sequence)
	assert.Equal(s.T(), uint16(0x56), rec.Length)
	assert.Equal(s.T(), 86, len(rec.Data))
	assert.Equal(s.T(), true, rec.IsHandshake())

}

func (s *RecordSuite) TestRecordEncode() {
	data := randomBytes(40)
	newRec := newRecord(ContentType_Handshake, 1, 22, data)

	rec, rem, err := parseRecord(newRec.Bytes())

	assert.Nil(s.T(), err)
	assert.Nil(s.T(), rem)
	assert.NotNil(s.T(), rec)

	assert.Equal(s.T(), ContentType(ContentType_Handshake), rec.ContentType)
	assert.Equal(s.T(), DtlsVersion12, rec.Version)
	assert.Equal(s.T(), uint16(1), rec.Epoch)
	assert.Equal(s.T(), uint64(22), rec.Sequence)
	assert.Equal(s.T(), uint16(len(data)), rec.Length)
	assert.Equal(s.T(), len(data), len(rec.Data))
	assert.Equal(s.T(), true, rec.IsHandshake())

}

func (s *RecordSuite) TestMultiRecordDecode() {
	rb, _ := hex.DecodeString("16fefd00000000000000010052020000460001000000000046fefd58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e892058218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85c0a80016fefd0000000000000002000c0e0000000002000000000000")

	rec, rem, err := parseRecord(rb)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), rem)
	assert.NotNil(s.T(), rec)

	assert.Equal(s.T(), ContentType(ContentType_Handshake), rec.ContentType)
	assert.Equal(s.T(), DtlsVersion12, rec.Version)
	assert.Equal(s.T(), uint16(0), rec.Epoch)
	assert.Equal(s.T(), uint64(1), rec.Sequence)
	assert.Equal(s.T(), uint16(0x52), rec.Length)
	assert.Equal(s.T(), 82, len(rec.Data))
	assert.Equal(s.T(), true, rec.IsHandshake())

	rec, rem, err = parseRecord(rem)

	assert.Nil(s.T(), err)
	assert.Nil(s.T(), rem)
	assert.NotNil(s.T(), rec)

	assert.Equal(s.T(), ContentType(ContentType_Handshake), rec.ContentType)
	assert.Equal(s.T(), DtlsVersion12, rec.Version)
	assert.Equal(s.T(), uint16(0), rec.Epoch)
	assert.Equal(s.T(), uint64(2), rec.Sequence)
	assert.Equal(s.T(), uint16(0xc), rec.Length)
	assert.Equal(s.T(), 12, len(rec.Data))
	assert.Equal(s.T(), true, rec.IsHandshake())

}

func (s *RecordSuite) TestIsHandshake() {
	data := randomBytes(40)
	newRec := newRecord(ContentType_Handshake, 1, 22, data)

	rec, _, _ := parseRecord(newRec.Bytes())
	assert.Equal(s.T(), true, rec.IsHandshake())

	data = randomBytes(40)
	newRec = newRecord(ContentType_Appdata, 1, 22, data)

	rec, _, _ = parseRecord(newRec.Bytes())
	assert.Equal(s.T(), false, rec.IsHandshake())
}

func (s *RecordSuite) TestPrint() {
	newRec := newRecord(ContentType_Handshake, 1, 22, nil)

	rec, _, _ := parseRecord(newRec.Bytes())
	assert.Equal(s.T(), "contentType[Handshake(22)] version[FEFD] epoch[1] seq[22] length[0] data[]", rec.Print())
}

func (s *RecordSuite) TestUnderflow() {
	newRec := newRecord(ContentType_Handshake, 1, 22, nil)

	data := newRec.Bytes()

	_, _, err := parseRecord(data[:10])
	assert.NotNil(s.T(), err)
}
