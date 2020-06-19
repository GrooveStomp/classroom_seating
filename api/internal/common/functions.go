package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func SymmetricEncryptBase64Encode(key, data string) string {
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(data))
	hex.EncodeToString(hash.Sum(nil))
	encoded := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	return encoded
}
