package xsecrets

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptDecryptPrivateRSA verifies that EncryptPrivateRSA and DecryptPrivateRSA
// correctly round-trip a generated RSA private key in PEM format.
func TestEncryptDecryptPrivateRSA(t *testing.T) {
	// Generate a new RSA private key for testing
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal the private key into PKCS#1 DER format and wrap in a PEM block
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}
	origPEM := pem.EncodeToMemory(pemBlock)

	masterKey := "testmasterkey"
	label := "testlabel"

	// Encrypt the PEM bytes
	cipherText, err := EncryptPrivateRSA(origPEM, masterKey, label)
	if err != nil {
		t.Fatalf("EncryptPrivateRSA failed: %v", err)
	}

	// Decrypt back to *rsa.PrivateKey
	privKey, err := DecryptPrivateRSA(cipherText, masterKey, label)
	if err != nil {
		t.Fatalf("DecryptPrivateRSA failed: %v", err)
	}

	// Marshal the decrypted key back to PEM
	der2 := x509.MarshalPKCS1PrivateKey(privKey)
	pemBlock2 := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der2,
	}
	decodedPEM := pem.EncodeToMemory(pemBlock2)

	// Compare original and round-tripped PEM
	if !bytes.Equal(origPEM, decodedPEM) {
		t.Errorf("Roundtrip PEM mismatch.\nOriginal:\n%s\nDecoded:\n%s", origPEM, decodedPEM)
	}
}

// TestEncryptPrivateRSA_Empty ensures that EncryptPrivateRSA returns an error
// when provided with an empty input.
func TestEncryptPrivateRSA_Empty(t *testing.T) {
	_, err := EncryptPrivateRSA([]byte(""), "key", "label")
	if err == nil {
		t.Error("Expected error for empty private key input, got nil")
	}
}

// TestDecryptPrivateRSA_Invalid checks that DecryptPrivateRSA errors on invalid ciphertext.
func TestDecryptPrivateRSA_Invalid(t *testing.T) {
	_, err := DecryptPrivateRSA("not_base64_or_ciphertext", "key", "label")
	if err == nil {
		t.Error("Expected error for invalid ciphertext, got nil")
	}
}

// TestGeneratePEMFiles checks that GeneratePEMFiles creates valid PEM files
// for both private and public RSA keys.
func TestGeneratePEMFiles(t *testing.T) {
	// Create a temporary directory for output files
	tmpDir, err := os.MkdirTemp("", "pemtest")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Use a base name inside the temp directory
	baseName := filepath.Join(tmpDir, "testkey")

	// Generate the PEM files
	if err := GeneratePEMFiles(baseName); err != nil {
		t.Fatalf("GeneratePEMFiles failed: %v", err)
	}

	privPath := baseName + ".pem"
	pubPath := baseName + "_pub.pem"

	// Ensure both files exist
	for _, path := range []string{privPath, pubPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Fatalf("expected file %s to exist", path)
		} else if err != nil {
			t.Fatalf("stat %s failed: %v", path, err)
		}
	}

	// Read and validate the private key PEM
	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("failed to read private key file: %v", err)
	}
	privBlock, _ := pem.Decode(privBytes)
	if privBlock == nil || privBlock.Type != "RSA PRIVATE KEY" {
		t.Fatalf("invalid private key PEM block: %v", privBlock)
	}
	if _, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes); err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	// Read and validate the public key PEM
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("failed to read public key file: %v", err)
	}
	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("invalid public key PEM block: %v", pubBlock)
	}
	if _, err := x509.ParsePKIXPublicKey(pubBlock.Bytes); err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
}
