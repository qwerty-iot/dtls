// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
    "crypto/aes"
    "crypto/cipher"
    "errors"
)

// CipherGcm implements TLS_PSK_WITH_AES_128_GCM_SHA256 for DTLS 1.2
type CipherGcm struct {
    peer *Peer
}

func (c CipherGcm) GetPrfSize() int {
    // 16 (client key) + 16 (server key) + 4 (client IV) + 4 (server IV)
    return 48
}

func (c CipherGcm) GenerateKeyBlock(masterSecret []byte, rawKeyBlock []byte) *KeyBlock {
    // Mirror CCM layout: 16-byte write keys, 4-byte IV salts
    return &KeyBlock{MasterSecret: masterSecret, ClientWriteKey: rawKeyBlock[0:16], ServerWriteKey: rawKeyBlock[16:32], ClientIV: rawKeyBlock[32:36], ServerIV: rawKeyBlock[36:40]}
}

func (c CipherGcm) Encrypt(s *session, rec *record, key []byte, iv []byte, mac []byte) ([]byte, error) {
    // AEAD GCM: nonce is 12 bytes (4-byte static IV salt + 8-byte explicit from epoch/seq)
    nonce := newNonce(iv, rec.Epoch, rec.Sequence)
    aad := newAad(s, rec.Epoch, rec.Sequence, uint8(rec.ContentType), s.peerCid, uint16(len(rec.Data)))

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    if len(nonce) != gcm.NonceSize() {
        return nil, errors.New("dtls: invalid nonce length")
    }

    if DebugEncryption && c.peer != nil {
        logDebug(c.peer, rec, "encrypt nonce[%X] key[%X] aad[%X]", nonce, key, aad)
        logDebug(c.peer, rec, "encrypt clearText[%X][%d]", rec.Data, len(rec.Data))
    }

    // Seal appends ciphertext and 16-byte tag
    cipherText := gcm.Seal(nil, nonce, rec.Data, aad)

    // Prepend explicit nonce (epoch+sequence) to ciphertext
    w := newByteWriter()
    w.PutUint16(rec.Epoch)
    w.PutUint48(rec.Sequence)
    w.PutBytes(cipherText)
    out := w.Bytes()

    if DebugEncryption && c.peer != nil {
        logDebug(c.peer, rec, "encrypt cipherText[%X][%d]", out, len(out))
    }
    return out, nil
}

func (c CipherGcm) Decrypt(s *session, rec *record, key []byte, iv []byte, mac []byte) ([]byte, error) {
    // First 8 bytes are explicit nonce (epoch+sequence)
    explicit := rec.Data[:8]
    data := rec.Data[8:]

    nonce := newNonceFromBytes(iv, explicit)
    // AAD uses the plaintext length; data includes ciphertext+tag(16)
    // rec.Data = 8 (explicit) + plaintext + 16 (tag) => plaintext = len(rec.Data) - 24
    aad := newAad(s, rec.Epoch, rec.Sequence, uint8(rec.ContentType), s.cid, uint16(len(rec.Data)-24))

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    if len(nonce) != gcm.NonceSize() {
        return nil, errors.New("dtls: invalid nonce length")
    }

    if DebugEncryption && c.peer != nil {
        logDebug(c.peer, rec, "decrypt nonce[%X] key[%X] aad[%X]", nonce, key, aad)
        logDebug(c.peer, rec, "decrypt cipherText[%X][%d]", data, len(data))
    }

    // Open returns the plaintext if authentication succeeds
    clearText, err := gcm.Open(nil, nonce, data, aad)
    if err != nil {
        if DebugEncryption && c.peer != nil {
            logWarn(c.peer, nil, err, "decrypt failed")
        }
        return nil, err
    }

    if DebugEncryption && c.peer != nil {
        logDebug(c.peer, rec, "decrypt clearText[%X][%d]", clearText, len(clearText))
    }

    return clearText, nil
}
