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
		"128B":  mustRandomBytes(128),
		"4KB":   mustRandomBytes(4096),
		"64KB":  mustRandomBytes(65536),
		"512KB": mustRandomBytes(524288),
		"1MB":   mustRandomBytes(1048576),
		"4MB":   mustRandomBytes(4194304),
	}
)

func init() {
	ekey, dkey, err := GenerateKey(rand.Reader)
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

func BenchmarkLockboxEncrypt128B(b *testing.B)  { lbEncrypt("128B", b) }
func BenchmarkLockboxEncrypt4KB(b *testing.B)   { lbEncrypt("4KB", b) }
func BenchmarkLockboxEncrypt64KB(b *testing.B)  { lbEncrypt("64KB", b) }
func BenchmarkLockboxEncrypt512KB(b *testing.B) { lbEncrypt("512KB", b) }
func BenchmarkLockboxEncrypt1MB(b *testing.B)   { lbEncrypt("1MB", b) }
func BenchmarkLockboxEncrypt4MB(b *testing.B)   { lbEncrypt("4MB", b) }

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

func BenchmarkLockboxDecrypt128(b *testing.B)   { lbDecrypt("128B", b) }
func BenchmarkLockboxDecrypt4096(b *testing.B)  { lbDecrypt("4KB", b) }
func BenchmarkLockboxDecrypt64KB(b *testing.B)  { lbDecrypt("64KB", b) }
func BenchmarkLockboxDecrypt512KB(b *testing.B) { lbDecrypt("512KB", b) }
func BenchmarkLockboxDecrypt1MB(b *testing.B)   { lbDecrypt("1MB", b) }
func BenchmarkLockboxDecrypt4MB(b *testing.B)   { lbDecrypt("4MB", b) }

func lbDecrypt(key string, b *testing.B) {
	chunk, ok := chunks[key]
	if !ok {
		b.Fatalf("missing chunk %s", key)
	}
	data, err := enc.Encrypt(chunk)
	if err != nil {
		panic(err)
	}
	b.SetBytes(int64(len(data)))

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
