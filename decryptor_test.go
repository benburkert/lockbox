package lockbox

import (
	"bytes"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestDecryptionWithZeros(t *testing.T) {
	pk, sk := zeroKey()

	d := &Decryptor{
		PK: &pk,
		SK: &sk,
	}

	want := []byte("Kill all humans")
	got, err := d.Decrypt(zeroData)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("got '%s', want '%s'", got, want)
	}
}

func TestDecryptionRoundtrip(t *testing.T) {
	ekey, dkey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	eb, _ := pem.Decode(ekey)
	db, _ := pem.Decode(dkey)

	e, err := NewEncryptor(eb)
	if err != nil {
		t.Fatal(err)
	}

	d, err := NewDecryptor(db)
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("Kill all humans")
	data, err := e.Encrypt(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := d.Decrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("got '%s', want '%s'", got, want)
	}
}

func zeroKey() (sk, pk [32]byte) {
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk, sk
}
