package lockbox

import (
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Decryptor decrypts data with a decryption (secret) key.
type Decryptor struct {
	PK, SK *[32]byte // public key, secret key
}

// NewDecryptor returns a Decryptor for decrypting data encrypted with the
// encryption (public) key corresponding to the decryption (private) key.
func NewDecryptor(dkey *pem.Block) (*Decryptor, error) {
	if dkey.Type != typeDecryptionKey {
		return nil, errors.New("lockbox: invalid decryption key file")
	}

	pk, sk := new([32]byte), new([32]byte)
	copy(sk[:], dkey.Bytes)
	curve25519.ScalarBaseMult(pk, sk)

	return &Decryptor{
		PK: pk,
		SK: sk,
	}, nil
}

// LoadDecryptor returns a Decryptor for the decryption (private) key file.
func LoadDecryptor(dkeyFile string) (*Decryptor, error) {
	f, err := os.Open(dkeyFile)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	b, rest := pem.Decode(data)
	if b == nil || len(rest) != 0 {
		return nil, errors.New("lockbox: invalid decryption key file")
	}

	return NewDecryptor(b)
}

// Decrypt returns the cleartext contents of the PEM encoded block of lockbox
// encrypted ciphertext in data.
func (d *Decryptor) Decrypt(data []byte) ([]byte, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("lockbox: pem decoding failed")
	}
	if b.Type != typeData {
		return nil, errors.New("lockbox: invalid data")
	}

	fp := b.Headers[hdrFingerprint]
	if fp != b64.EncodeToString(d.PK[:]) {
		return nil, errors.New("lockbox: fingerprints did not match")
	}

	var nonce [24]byte
	bnonce, err := b64.DecodeString(b.Headers[hdrNonce])
	if err != nil {
		return nil, err
	}
	if len(bnonce) != 24 {
		return nil, errors.New("lockbox: invalid nonce")
	}
	copy(nonce[:], bnonce)

	var pk [32]byte
	bpk, err := b64.DecodeString(b.Headers[hdrPublicKey])
	if err != nil {
		return nil, err
	}
	if len(bpk) != 32 {
		return nil, errors.New("lockbox: invalid decryption public key")
	}
	copy(pk[:], bpk)

	msg, ok := box.Open(nil, b.Bytes, &nonce, &pk, d.SK)
	if !ok {
		return nil, errors.New("lockbox: decryption failed")
	}

	return msg, nil
}
