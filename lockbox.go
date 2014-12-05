/*
Package lockbox simplified asymmetric encryption with NaCl.

Lockbox uses NaCl's box API for public-key cryptography to provide a simplified
API for asymmetric encryption. It is designed with the following goals:

* Provide a simple convention for managing encryption & decryption keys. An
encryption key is a PEM encoded NaCl box public key with title "LOCKBOX PUBLIC
ENCRYPTION KEY", stored with the file extension ".ekey". A decryption key is a
PEM encoded NaCl box private key with title "LOCKBOX SECRET DECRYPTION KEY",
stored with the file extension ".dkey".

* Provide a simplified API for setup & encryption/decryption. The Encryptor &
Decryptor types are constructed with their corresponding key. The types have a
single Encrypt/Decrypt method that take a cleartext/ciphertext byte slice
parameter and returns a ciphertext/cleartext byte slice.

* Design the Encryptor so that it cannot decrypt the output of Encrypt once the
function has returned. Isolating the role of decryption from encryption should
be straightforward and easy.

Installation

Install lockbox via go get:

	$ go get github.com/benburkert/lockbox/cmd/...

Example Command Usage

Generate a new keypair:

	$ lockbox generate testpair
	$ cat testpair.ekey
	cat testpair.ekey
	-----BEGIN LOCKBOX PUBLIC ENCRYPTION KEY-----
	WSm+Qpliu+flFoKJoa8UQpAM9Lo2HwtQNdXAJec4gCo=
	-----END LOCKBOX PUBLIC ENCRYPTION KEY-----
	$ cat testpair.dkey
	-----BEGIN LOCKBOX SECRET DECRYPTION KEY-----
	8G2vsOGuyr7ut5J4G6Jat+bsft9BBoCOTHTdPjIS+1s=
	-----END LOCKBOX SECRET DECRYPTION KEY-----

Encrypt a message:

	$ echo "Kill all humans" | lockbox encrypt testpair.ekey > data.pem
	$ cat data.pem
	-----BEGIN LOCKBOX DATA-----
	Fingerprint: WSm+Qpliu+flFoKJoa8UQpAM9Lo2HwtQNdXAJec4gCo=
	Nonce: 14VYjF6Cli6zltBKyDgkkQIaWfDf1mBd
	Public-Key: miZx64bMBx1NsOELM79Dx4y7FoVi7NgE+sdqz3zJ21A=

	EDx6j97EMoNiBUBWqnHHnP7+3Hj2HNhgz4X5L9lVObQ=
	-----END LOCKBOX DATA-----

Decrypt the message:

	$ lockbox decrypt testpair.dkey < data.pem
	Kill all humans


Example Package Usage

Encrypt & print a message:

	encryptor := lockbox.LoadEncryptor("testpair.ekey")
	data, err := encryptor.Encrypt([]byte("Kill all humans"))
	fmt.Println(data)

Decrypt & print the message:

	decryptor := lockbox.LoadDecryptor("testpair.dkey")
	cleartext, err := decryptor.Decrypt(data)
	fmt.Println(cleartext)

Caveats

Lockbox does not prevent a hostile party with access to the encryption key
from replacing a message with a forgery. In this case, the decryptor is unable
to detect if a message is a forgery. Lockbox data should only be transported
over secure channels.

*/
package lockbox

import "encoding/base64"

var (
	b64 = base64.StdEncoding

	typeEncryptionKey = "LOCKBOX PUBLIC ENCRYPTION KEY"
	typeDecryptionKey = "LOCKBOX SECRET DECRYPTION KEY"
	typeData          = "LOCKBOX DATA"

	hdrFingerprint = "Fingerprint"
	hdrPublicKey   = "Public-Key"
	hdrNonce       = "Nonce"
)
