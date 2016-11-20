package record

import (
	"encoding/hex"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/bocajim/dtls/common"
)

func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&RecordSuite{})

type RecordSuite struct{}

func (s *RecordSuite) SetUpSuite(c *C) {
}

func (s *RecordSuite) TestRecordDecode(c *C) {
	rb, _ := hex.DecodeString("16fefd000000000000000100560100004a000100000000004afefd00000001145b1fb384c7e5ba7585664c931759ab2305c5e5f7b776635e176db60020d76679b19ce7b6060c71dd9e55830ca2a8e02652a5b66ebe9a9c652ee75342d80002c0a80100")

	rec, rem, err := ParseRecord(rb)

	c.Assert(err, IsNil)
	c.Assert(rem, IsNil)
	c.Assert(rec, NotNil)

	c.Assert(rec.ContentType, Equals, ContentType(ContentType_Handshake))
	c.Assert(rec.Version, Equals, common.DtlsVersion12)
	c.Assert(rec.Epoch, Equals, uint16(0))
	c.Assert(rec.Sequence, Equals, uint64(1))
	c.Assert(rec.Length, Equals, uint16(0x56))
	c.Assert(len(rec.Data), Equals, 86)
	c.Assert(rec.IsHandshake(), Equals, true)

}

func (s *RecordSuite) TestRecordEncode(c *C) {

	newRec := New(ContentType_Handshake)
	newRec.Epoch = 1
	newRec.Sequence = 22

	data := common.RandomBytes(40)
	newRec.SetData(data)

	rec, rem, err := ParseRecord(newRec.Bytes())

	c.Assert(err, IsNil)
	c.Assert(rem, IsNil)
	c.Assert(rec, NotNil)

	c.Assert(rec.ContentType, Equals, ContentType(ContentType_Handshake))
	c.Assert(rec.Version, Equals, common.DtlsVersion12)
	c.Assert(rec.Epoch, Equals, uint16(1))
	c.Assert(rec.Sequence, Equals, uint64(22))
	c.Assert(rec.Length, Equals, uint16(len(data)))
	c.Assert(len(rec.Data), Equals, len(data))
	c.Assert(rec.IsHandshake(), Equals, true)

}

func (s *RecordSuite) TestMultiRecordDecode(c *C) {
	rb, _ := hex.DecodeString("16fefd00000000000000010052020000460001000000000046fefd58218d545f4507f138c23097f5e754cf43cff524d0015aceda2be2d3794e1e892058218d541a9e9b958203308bc0d650408a6070dd1f99437db5bcc5d709322a85c0a80016fefd0000000000000002000c0e0000000002000000000000")

	rec, rem, err := ParseRecord(rb)

	c.Assert(err, IsNil)
	c.Assert(rem, NotNil)
	c.Assert(rec, NotNil)

	c.Assert(rec.ContentType, Equals, ContentType(ContentType_Handshake))
	c.Assert(rec.Version, Equals, common.DtlsVersion12)
	c.Assert(rec.Epoch, Equals, uint16(0))
	c.Assert(rec.Sequence, Equals, uint64(1))
	c.Assert(rec.Length, Equals, uint16(0x52))
	c.Assert(len(rec.Data), Equals, 82)
	c.Assert(rec.IsHandshake(), Equals, true)

	rec, rem, err = ParseRecord(rem)

	c.Assert(err, IsNil)
	c.Assert(rem, IsNil)
	c.Assert(rec, NotNil)

	c.Assert(rec.ContentType, Equals, ContentType(ContentType_Handshake))
	c.Assert(rec.Version, Equals, common.DtlsVersion12)
	c.Assert(rec.Epoch, Equals, uint16(0))
	c.Assert(rec.Sequence, Equals, uint64(2))
	c.Assert(rec.Length, Equals, uint16(0xc))
	c.Assert(len(rec.Data), Equals, 12)
	c.Assert(rec.IsHandshake(), Equals, true)

}

func (s *RecordSuite) TestIsHandshake(c *C) {
	newRec := New(ContentType_Handshake)
	newRec.Epoch = 1
	newRec.Sequence = 22

	data := common.RandomBytes(40)
	newRec.SetData(data)

	rec, _, _ := ParseRecord(newRec.Bytes())
	c.Assert(rec.IsHandshake(), Equals, true)

	newRec = New(ContentType_Appdata)
	newRec.Epoch = 1
	newRec.Sequence = 22

	data = common.RandomBytes(40)
	newRec.SetData(data)

	rec, _, _ = ParseRecord(newRec.Bytes())
	c.Assert(rec.IsHandshake(), Equals, false)
}

func (s *RecordSuite) TestPrint(c *C) {
	newRec := New(ContentType_Handshake)
	newRec.Epoch = 1
	newRec.Sequence = 22

	rec, _, _ := ParseRecord(newRec.Bytes())
	c.Assert(rec.Print(), Equals, "contentType[22] version[FEFD] epoch[1] seq[22] length[0] data[]")
}

func (s *RecordSuite) TestUnderflow(c *C) {
	newRec := New(ContentType_Handshake)
	newRec.Epoch = 1
	newRec.Sequence = 22

	data := newRec.Bytes()

	_, _, err := ParseRecord(data[:10])
	c.Assert(err, NotNil)
}
