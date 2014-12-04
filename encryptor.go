package lockbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/nacl/box"
)

var b64 = base64.StdEncoding

type Encryptor struct {
	pk *[32]byte

	r io.Reader
}

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

	return encryptorFromBlock(b)
}

func encryptorFromBlock(b *pem.Block) (*Encryptor, error) {
	if b.Type != "LOCKBOX ENCRYPTION KEY" {
		return nil, errors.New("lockbox: invalid encryption key file")
	}

	pk := new([32]byte)
	copy(pk[:], b.Bytes)

	return &Encryptor{
		pk: pk,
		r:  rand.Reader,
	}, nil
}

func (e *Encryptor) Encrypt(data []byte) ([]byte, error) {
	var nonce [24]byte
	e.r.Read(nonce[:])
	pk, sk, err := box.GenerateKey(e.r)
	if err != nil {
		return nil, err
	}

	ct := box.Seal(nil, data, &nonce, e.pk, sk)
	hdrs := map[string]string{
		"Fingerprint": b64.EncodeToString(e.pk[:]),
		"Public-Key":  b64.EncodeToString(pk[:]),
		"Nonce":       b64.EncodeToString(nonce[:]),
	}
	b := &pem.Block{
		Type:    "LOCKBOX DATA",
		Headers: hdrs,
		Bytes:   ct,
	}
	return pem.EncodeToMemory(b), nil
}
