package xsecrets

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// GenerateKeyPair generates RSA private and public key PEM bytes in memory.
func GenerateKeyPair() ([]byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	pemPrivateBytes := pem.EncodeToMemory(privBlock)

	// Encode public key to PEM
	pubASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}
	pemPublicBytes := pem.EncodeToMemory(pubBlock)

	return pemPrivateBytes, pemPublicBytes, nil
}

// GeneratePEMFiles generates RSA keys and saves them into PEM files.
func GeneratePEMFiles(name string) error {
	privPEM, pubPEM, err := GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create key pair: %w", err)
	}

	// Save private key
	err = os.WriteFile(name+".pem", privPEM, 0600)
	if err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save public key
	err = os.WriteFile(name+"_pub.pem", pubPEM, 0644)
	if err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// EncryptPrivateRSA encrypts an RSA private key PEM using a derived AES key.
// It expects a valid PEM-encoded RSA private key as input.
// The masterKey and label are used to derive the AES encryption key.
func EncryptPrivateRSA(plain []byte, masterKey, label string) (string, error) {
	pemBlock, _ := pem.Decode(plain)
	if pemBlock == nil {
		return "", fmt.Errorf("empty private key")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("invalid PEM block type: got %s", pemBlock.Type)
	}

	enKey := DeriveKey([]byte(masterKey), label)
	cipherText, err := EncryptBase64WithKey(plain, enKey)
	if err != nil {
		return "", fmt.Errorf("encrypt failed: %w", err)
	}

	return cipherText, nil
}

// DecryptPrivateRSA decrypts an encrypted RSA private key string back to a *rsa.PrivateKey.
// It expects a base64-encoded encrypted key and uses the masterKey and label
// to derive the AES decryption key.
func DecryptPrivateRSA(encPrivateKey, masterKey, label string) (*rsa.PrivateKey, error) {
	enKey := DeriveKey([]byte(masterKey), label)
	decryptedBytes, err := DecryptBase64WithKey(encPrivateKey, enKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	pemBlock, _ := pem.Decode(decryptedBytes)
	if pemBlock == nil {
		return nil, errors.New("empty private key")
	} else if pemBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid PEM block for private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key failed: %w", err)
	}

	return privateKey, nil
}
