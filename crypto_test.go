package dtls

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestCryptoSuite(t *testing.T) {
	suite.Run(t, new(CryptoSuite))
}

type CryptoSuite struct {
	suite.Suite
}

func (s *CryptoSuite) Log(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}

func (s *CryptoSuite) TestNonce() {
	iv, _ := hex.DecodeString("F21CE4E5")
	nonce := newNonce(iv, 1, 0)
	assert.Equal(s.T(), "f21ce4e50001000000000000", hex.EncodeToString(nonce))
}

func (s *CryptoSuite) TestAad() {
	aad := newAad(5, 10, 1, 26)
	assert.Equal(s.T(), "000500000000000a01fefd001a", hex.EncodeToString(aad))
}

func (s *CryptoSuite) TestGeneratePrf() {
	ms, _ := hex.DecodeString("20A8A0E9172B0F7A1F370CF082B2FAD79BBC5F0757452B176695124960074985ED9D444A5D188D3397C74B3277EB1B0F")
	hash, _ := hex.DecodeString("777DBBC320A905D5BA76AD9323A986256991DD99FCDD265F4202A39C12C87F8F")

	prf := generatePrf(ms, []byte(" finished"), hash, "client", 12)

	assert.Equal(s.T(), "8c6ccb73e751bd05b36636af", hex.EncodeToString(prf))
}
