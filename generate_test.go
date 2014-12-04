package lockbox

import (
	"bytes"

	"testing"
)

func TestGenerateKeyWithZeros(t *testing.T) {
	ekey, dkey, err := GenerateKey(zeros)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ekey, zeroEKey) {
		t.Errorf("got %x, want %x", ekey, zeroEKey)
	}

	if !bytes.Equal(dkey, zeroDKey) {
		t.Errorf("got %x, want %x", dkey, zeroDKey)
	}
}

type zeroReader struct{}

func (r *zeroReader) Read(p []byte) (n int, err error) {
	l := len(p)
	b := make([]byte, l)
	return copy(p, b), nil
}

var (
	zeros    = &zeroReader{}
	zeroDKey = []byte(`-----BEGIN LOCKBOX DECRYPTION KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END LOCKBOX DECRYPTION KEY-----
`)
	zeroEKey = []byte(`-----BEGIN LOCKBOX ENCRYPTION KEY-----
L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=
-----END LOCKBOX ENCRYPTION KEY-----
`)
)
