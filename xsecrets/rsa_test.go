package xsecrets_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/eugene-ruby/xencryptor/xsecrets"
	"github.com/stretchr/testify/require"
)

func Test_RSAEncryptDecryptBytes(t *testing.T) {
	// Generate RSA keypair (2048 bits)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKey := &privKey.PublicKey

	// Message to encrypt
	original := []byte("secret 123")

	// Encrypt with public key
	encrypted, err := xsecrets.RSAEncryptBytes(pubKey, original)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	// Decrypt with private key
	decrypted, err := xsecrets.RSADecryptBytes(encrypted, privKey)
	require.NoError(t, err)
	require.Equal(t, original, decrypted)
}
