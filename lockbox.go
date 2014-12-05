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
