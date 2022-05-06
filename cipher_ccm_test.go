package dtls

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestCipherCcmSuite(t *testing.T) {
	suite.Run(t, new(CipherCcmSuite))
}

type CipherCcmSuite struct {
	suite.Suite
}

func (s *CipherCcmSuite) Log(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}

func (s *CipherCcmSuite) TestEncryption() {

	iv := randomBytes(4)
	key := randomBytes(16)
	data := randomBytes(50)

	ccm := CipherCcm{peer: nil}
	cipherText, err := ccm.Encrypt(&record{Epoch: 5, Sequence: 10, ContentType: 1, Data: data}, key, iv, nil, nil)
	assert.Nil(s.T(), err)

	clearText, err := ccm.Decrypt(&record{Epoch: 5, Sequence: 10, ContentType: 1, Data: cipherText}, key, iv, nil)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), hex.EncodeToString(data), hex.EncodeToString(clearText))
}
