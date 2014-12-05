package lockbox

import (
	"encoding/pem"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// GenerateKey returns a new pem encoded keypair.
func GenerateKey(rand io.Reader) (ekey, dkey []byte, err error) {
	pk, sk, err := box.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	pkb := &pem.Block{
		Type:  typeEncryptionKey,
		Bytes: pk[:],
	}
	skb := &pem.Block{
		Type:  typeDecryptionKey,
		Bytes: sk[:],
	}

	ekey = pem.EncodeToMemory(pkb)
	dkey = pem.EncodeToMemory(skb)
	return
}
