package lockbox

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"
)

func TestGenerateKeyWithZeros(t *testing.T) {
	ekey, dkey, err := generateKey(zeros)
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

func TestGenerateKeyIdempotent(t *testing.T) {
	r1, pw := io.Pipe()
	r2 := io.TeeReader(rand.Reader, pw)

	var ekey1, dkey1, ekey2, dkey2 []byte
	var err1, err2 error

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		ekey1, dkey1, err1 = generateKey(r1)
		if err1 != nil {
			t.Fatal(err1)
		}
		wg.Done()
	}()

	go func() {
		ekey2, dkey2, err2 = generateKey(r2)
		if err2 != nil {
			t.Fatal(err2)
		}
		wg.Done()
	}()

	wg.Wait()

	if !bytes.Equal(ekey1, ekey2) {
		t.Errorf("got different encryption keys, %x != %x", ekey1, ekey2)
	}

	if !bytes.Equal(dkey1, dkey2) {
		t.Errorf("got different decryption keys, %x != %x", dkey1, dkey2)
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
	zeroDKey = []byte(`-----BEGIN LOCKBOX SECRET DECRYPTION KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END LOCKBOX SECRET DECRYPTION KEY-----
`)
	zeroEKey = []byte(`-----BEGIN LOCKBOX PUBLIC ENCRYPTION KEY-----
L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=
-----END LOCKBOX PUBLIC ENCRYPTION KEY-----
`)
)
