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

	chunks = map[string][]byte{
		"1B":   make([]byte, 1),
		"64B":  make([]byte, 64),
		"1KB":  make([]byte, 1024),
		"64KB": make([]byte, 65536),
		"1MB":  make([]byte, 1048576),
		"64MB": make([]byte, 67108864),
	}
)

func init() {
	ekey, dkey, err := GenerateKey()
	if err != nil {
		panic(err)
	}

	eb, _ := pem.Decode(ekey)
	db, _ := pem.Decode(dkey)

	enc, err = NewEncryptor(eb)
	if err != nil {
		panic(err)
	}

	dec, err = NewDecryptor(db)
	if err != nil {
		panic(err)
	}
}

func BenchmarkLockboxEncrypt1B(b *testing.B)   { lbEncrypt("1B", b) }
func BenchmarkLockboxEncrypt64B(b *testing.B)  { lbEncrypt("64B", b) }
func BenchmarkLockboxEncrypt1KB(b *testing.B)  { lbEncrypt("1KB", b) }
func BenchmarkLockboxEncrypt64KB(b *testing.B) { lbEncrypt("64KB", b) }
func BenchmarkLockboxEncrypt1MB(b *testing.B)  { lbEncrypt("1MB", b) }
func BenchmarkLockboxEncrypt64MB(b *testing.B) { lbEncrypt("64MB", b) }

func lbEncrypt(key string, b *testing.B) {
	data, ok := chunks[key]
	if !ok {
		b.Fatalf("missing chunk %s", key)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		enc.Encrypt(data)
	}
}

func BenchmarkLockboxDecrypt1B(b *testing.B)   { lbDecrypt("1B", b) }
func BenchmarkLockboxDecrypt64B(b *testing.B)  { lbDecrypt("64B", b) }
func BenchmarkLockboxDecrypt1KB(b *testing.B)  { lbDecrypt("1KB", b) }
func BenchmarkLockboxDecrypt64KB(b *testing.B) { lbDecrypt("64KB", b) }
func BenchmarkLockboxDecrypt1MB(b *testing.B)  { lbDecrypt("1MB", b) }
func BenchmarkLockboxDecrypt64MB(b *testing.B) { lbDecrypt("64MB", b) }

func lbDecrypt(key string, b *testing.B) {
	chunk, ok := chunks[key]
	if !ok {
		b.Fatalf("missing chunk %s", key)
	}
	data, err := enc.Encrypt(chunk)
	if err != nil {
		panic(err)
	}

	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dec.Decrypt(data)
	}
}

func mustRandomBytes(s int) []byte {
	buf := make([]byte, s)
	if _, err := io.ReadAtLeast(rand.Reader, buf, s); err != nil {
		panic(err)
	}
	return buf
}
