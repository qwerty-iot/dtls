package dtls

import (
	"fmt"
	"reflect"
)

type finished struct {
	data []byte
}

/*
  dtls_prf(peer->handshake_params->tmp.master_secret,
	   DTLS_MASTER_SECRET_LENGTH,
	   label, labellen,
	   PRF_LABEL(finished), PRF_LABEL_SIZE(finished),
	   hash, length,
	   p, DTLS_FIN_LENGTH);

	dtls_prf(const unsigned char *key, size_t keylen,
	 const unsigned char *label, size_t labellen,
	 const unsigned char *random1, size_t random1len,
	 const unsigned char *random2, size_t random2len,
	 unsigned char *buf, size_t buflen)
*/

func (h *finished) Init(masterSecret []byte, hash []byte, label string) {
	h.data = generatePrf(masterSecret, []byte(" finished"), hash, label, 12)
}

func (h *finished) Parse(rdr *byteReader) error {
	h.data = rdr.GetBytes(12)

	return nil
}

func (h *finished) Match(masterSecret []byte, hash []byte, label string) bool {
	mac := generatePrf(masterSecret, []byte(" finished"), hash, label, 12)
	if reflect.DeepEqual(mac, h.data) {
		return true
	} else {
		return false
	}
}

func (h *finished) Bytes() []byte {
	w := newByteWriter()
	w.PutBytes(h.data)

	return w.Bytes()
}

func (h *finished) Print() string {
	return fmt.Sprintf("data[%X]", h.data)
}
