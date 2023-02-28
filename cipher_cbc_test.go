package dtls

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestCipherCbcSuite(t *testing.T) {
	suite.Run(t, new(CipherCbcSuite))
}

type CipherCbcSuite struct {
	suite.Suite
}

func (s *CipherCbcSuite) Log(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}

func (s *CipherCbcSuite) TestEncryption() {

	iv := randomBytes(16)
	key := randomBytes(16)
	mac := randomBytes(32)
	data := randomBytes(50)

	cbc := CipherCBC{peer: nil}
	cipherText, err := cbc.Encrypt(nil, &record{Epoch: 5, Sequence: 10, ContentType: 1, Data: data}, key, iv, mac)
	assert.Nil(s.T(), err)

	clearText, err := cbc.Decrypt(nil, &record{Epoch: 5, Sequence: 10, ContentType: 1, Data: cipherText}, key, iv, mac)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), hex.EncodeToString(data), hex.EncodeToString(clearText))
}
