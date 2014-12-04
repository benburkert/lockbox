package lockbox

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestDecryptionWithZeros(t *testing.T) {
	sk := [32]byte{0}
	var pk [32]byte
	curve25519.ScalarBaseMult(&pk, &sk)

	d := &Decryptor{
		pk: &pk,
		sk: &sk,
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
