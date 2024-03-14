package dcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

func NewKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func NewSalt() ([]byte, error) {
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func Encode(data []byte, key []byte, pwd []byte, salt []byte) ([]byte, error) {
	encoded, err := encodeAES(data, key)
	if err != nil {
		return nil, err
	}
	return encodeAES(encoded, kdf(pwd, salt))
}

func Decode(encoded []byte, key []byte, pwd []byte, salt []byte) ([]byte, error) {
	decoded, err := decodeAES(encoded, kdf(pwd, salt))
	if err != nil {
		return nil, err
	}
	return decodeAES(decoded, key)
}

func kdf(pwd []byte, salt []byte) []byte {
	return pbkdf2.Key(pwd, salt, 4096, 32, sha1.New)
}

func encodeAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	encoded := gcm.Seal(nil, nonce, data, nil)
	return encoded, nil
}

func decodeAES(encoded []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	return gcm.Open(nil, nonce, encoded, nil)
}
