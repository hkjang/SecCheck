package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

type Box struct{ key []byte }

func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	return &Box{key: append([]byte(nil), key...)}, nil
}

func (b *Box) Encrypt(plain, additional []byte) (string, error) {
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := append(nonce, gcm.Seal(nil, nonce, plain, additional)...)
	return base64.RawStdEncoding.EncodeToString(out), nil
}

func (b *Box) Decrypt(encoded string, additional []byte) ([]byte, error) {
	in, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(in) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	return gcm.Open(nil, in[:gcm.NonceSize()], in[gcm.NonceSize():], additional)
}

func RandomBytes(n int) ([]byte, error) {
	v := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, v)
	return v, err
}

func Token(n int) (string, error) {
	v, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(v), nil
}

func SHA256(v []byte) []byte {
	s := sha256.Sum256(v)
	return s[:]
}
