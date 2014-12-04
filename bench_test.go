package lockbox

import (
	"crypto/rand"

	"encoding/pem"
	"io"
	"testing"
)

var (
	enc *Encryptor
	dec *Decryptor
)

func init() {
	ekey, dkey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	eb, _ := pem.Decode(ekey)
	db, _ := pem.Decode(dkey)

	enc, err = encryptorFromBlock(eb)
	if err != nil {
		panic(err)
	}

	dec, err = decryptorFromBlock(db)
	if err != nil {
		panic(err)
	}
}

func BenchmarkLockboxEncrypt128(b *testing.B)  { lbEncrypt(128, b) }
func BenchmarkLockboxEncrypt1024(b *testing.B) { lbEncrypt(1024, b) }
func BenchmarkLockboxEncrypt4096(b *testing.B) { lbEncrypt(4096, b) }
func BenchmarkLockboxEncrypt64KB(b *testing.B) { lbEncrypt(65536, b) }

func lbEncrypt(s int, b *testing.B) {
	data := make([]byte, s)
	io.ReadAtLeast(rand.Reader, data, s)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		enc.Encrypt(data)
	}
}

func BenchmarkLockboxDencrypt128(b *testing.B)  { lbDecrypt(128, b) }
func BenchmarkLockboxDencrypt1024(b *testing.B) { lbDecrypt(1024, b) }
func BenchmarkLockboxDencrypt4096(b *testing.B) { lbDecrypt(4096, b) }
func BenchmarkLockboxDencrypt64KB(b *testing.B) { lbDecrypt(65536, b) }

func lbDecrypt(s int, b *testing.B) {
	buf := make([]byte, s)
	io.ReadAtLeast(rand.Reader, buf, s)
	data, err := enc.Encrypt(buf)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dec.Decrypt(data)
	}
}
