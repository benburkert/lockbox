package lockbox

import (
	"encoding/pem"
	"io"

	"golang.org/x/crypto/nacl/box"
)

func GenerateKey(rand io.Reader) (ekey, dkey []byte, err error) {
	pk, sk, err := box.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	pkb := &pem.Block{
		Type:  "LOCKBOX ENCRYPTION KEY",
		Bytes: pk[:],
	}
	skb := &pem.Block{
		Type:  "LOCKBOX DECRYPTION KEY",
		Bytes: sk[:],
	}

	ekey = pem.EncodeToMemory(pkb)
	dkey = pem.EncodeToMemory(skb)
	return
}
