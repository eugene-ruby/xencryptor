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

func GeneratePEMFiles(name string) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privFile, err := os.Create(name + ".pem")
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	if err := pem.Encode(privFile, privBlock); err != nil {
		return fmt.Errorf("failed to write private key PEM: %w", err)
	}

	pubFile, err := os.Create(name + "_pub.pem")
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()

	pubASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}
	if err := pem.Encode(pubFile, pubBlock); err != nil {
		return fmt.Errorf("failed to write public key PEM: %w", err)
	}

	return nil
}

func EncryptPrivateRSA(plain []byte, masterKey, label string) (string, error) {

	pemBlock, _ := pem.Decode(plain)
	if pemBlock == nil {
		return "", fmt.Errorf("empty private key")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("invalid PEM block type: got %s", pemBlock.Type)
	}

	enKey := DeriveKey([]byte(masterKey), label)
	cipherText, err := EncryptWithKey(plain, enKey)
	if err != nil {
		return "", fmt.Errorf("encrypt failed: %w", err)
	}

	return cipherText, nil
}

func DecryptPrivateRSA(encPrivateKey, masterKey, label string) (*rsa.PrivateKey, error) {
	enKey := DeriveKey([]byte(masterKey), label)
	plaintext, err := DecryptWithKey(encPrivateKey, enKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	pemBlock, _ := pem.Decode([]byte(plaintext))
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
