package lockbox

import (
	"bytes"
	"encoding/pem"

	"testing"
)

func TestEncryptionWithZeros(t *testing.T) {
	var zk [32]byte
	b, _ := pem.Decode(zeroEKey)
	copy(zk[:], b.Bytes)

	e := &Encryptor{
		pk: &zk,
		r:  zeros,
	}

	got, err := e.Encrypt([]byte("Kill all humans"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, zeroData) {
		t.Errorf("got %s, want %s", got, zeroData)
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
