package dtls

import (
    "encoding/hex"
    "fmt"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
)

func TestCipherGcmSuite(t *testing.T) {
    suite.Run(t, new(CipherGcmSuite))
}

type CipherGcmSuite struct {
    suite.Suite
}

func (s *CipherGcmSuite) Log(msg string, args ...interface{}) {
    fmt.Printf(msg+"\n", args...)
}

func (s *CipherGcmSuite) TestEncryption() {

    iv := randomBytes(4)
    key := randomBytes(16)
    data := randomBytes(50)

    gcm := CipherGcm{peer: nil}
    cipherText, err := gcm.Encrypt(nil, &record{Epoch: 5, Sequence: 10, ContentType: 1, Data: data}, key, iv, nil)
    assert.Nil(s.T(), err)

    clearText, err := gcm.Decrypt(nil, &record{Epoch: 5, Sequence: 10, ContentType: 1, Data: cipherText}, key, iv, nil)
    assert.Nil(s.T(), err)

    assert.Equal(s.T(), hex.EncodeToString(data), hex.EncodeToString(clearText))
}
