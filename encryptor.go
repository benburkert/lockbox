package lockbox

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/nacl/box"
)

// Encryptor encrypts data with an encryption (public) key.
type Encryptor struct {
	PK     *[32]byte // public key
	Reader io.Reader // random data source
}

// NewEncryptor returns an Encryptor for the encryption (public) key PEM block.
func NewEncryptor(ekey *pem.Block) (*Encryptor, error) {
	if ekey.Type != typeEncryptionKey {
		return nil, errors.New("lockbox: invalid encryption key file")
	}

	pk := new([32]byte)
	copy(pk[:], ekey.Bytes)

	return &Encryptor{
		PK:     pk,
		Reader: rand.Reader,
	}, nil
}

// LoadEncryptor returns an Encryptor for the encryption (public) key file.
func LoadEncryptor(ekeyFile string) (*Encryptor, error) {
	f, err := os.Open(ekeyFile)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	b, rest := pem.Decode(data)
	if b == nil || len(rest) != 0 {
		return nil, errors.New("lockbox: invalid encryption key file")
	}

	return NewEncryptor(b)
}

// Encrypt returns the encrypted contents of data in a single PEM encoded
// block. The block type is 'LOCKBOX DATA' with base64 encoded headers:
//
//   Fingerprint: the identifying fingerprint of the decryption key
//   Public-Key:  public key portion of the keypair generated for encryption
//   Nonce:       nonce value used during encryption & decryption
func (e *Encryptor) Encrypt(data []byte) ([]byte, error) {
	var nonce [24]byte
	e.Reader.Read(nonce[:])
	pk, sk, err := box.GenerateKey(e.Reader)
	if err != nil {
		return nil, err
	}

	ct := box.Seal(nil, data, &nonce, e.PK, sk)
	b := &pem.Block{
		Type: typeData,
		Headers: map[string]string{
			hdrFingerprint: b64.EncodeToString(e.PK[:]),
			hdrPublicKey:   b64.EncodeToString(pk[:]),
			hdrNonce:       b64.EncodeToString(nonce[:]),
		},
		Bytes: ct,
	}
	return pem.EncodeToMemory(b), nil
}
