package xsecrets

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// RSAEncryptBytes encrypts raw []byte with the given RSA public key.
func RSAEncryptBytes(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cipherBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa encryption failed: %w", err)
	}
	return cipherBytes, nil
}

// RSADecryptBytes decrypts raw RSA-encrypted []byte using private key.
func RSADecryptBytes(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	plain, err :=  rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa decryption failed: %w", err)
	}
	return plain, nil
}
