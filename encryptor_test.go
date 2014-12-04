package lockbox

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"io"
	"sync"
	"testing"
)

func TestEncryptionWithZeros(t *testing.T) {
	var pk [32]byte
	b, _ := pem.Decode(zeroEKey)
	copy(pk[:], b.Bytes)

	e := &Encryptor{
		PK:     &pk,
		Reader: zeros,
	}

	got, err := e.Encrypt([]byte("Kill all humans"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, zeroData) {
		t.Errorf("got %s, want %s", got, zeroData)
	}
}

func TestEncryptionIdempotent(t *testing.T) {
	var pk [32]byte
	ekey, _, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bpk, _ := pem.Decode(ekey)
	copy(pk[:], bpk.Bytes)

	r1, pw := io.Pipe()
	r2 := io.TeeReader(rand.Reader, pw)

	e1 := &Encryptor{
		PK:     &pk,
		Reader: r1,
	}

	e2 := &Encryptor{
		PK:     &pk,
		Reader: r2,
	}

	data := []byte("Kill all humans")
	var b1, b2 []byte

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		var err error
		b1, err = e1.Encrypt(data)
		if err != nil {
			t.Fatal(err)
		}
		wg.Done()
	}()

	go func() {
		var err error
		b2, err = e2.Encrypt(data)
		if err != nil {
			t.Fatal(err)
		}
		wg.Done()
	}()

	wg.Wait()

	if !bytes.Equal(b1, b2) {
		t.Errorf("got different ciphertext, %s != %s", string(b1), string(b2))
	}
}

var (
	zeroData = []byte(`-----BEGIN LOCKBOX DATA-----
Fingerprint: L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=
Nonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Public-Key: L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=

6T2MTdkreObuoRGrEmDtQND93PnAgJoC2JEYy2QX1Q==
-----END LOCKBOX DATA-----
`)
)
