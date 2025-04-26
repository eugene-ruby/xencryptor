package xsecrets

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// TestDeriveKey verifies that DeriveKey is deterministic, returns 32 bytes,
// and yields different results for different labels.
func TestDeriveKey(t *testing.T) {
	master := []byte("supersecretmaster")
	labelA := "labelA"
	labelB := "labelB"

	key1 := DeriveKey(master, labelA)
	key2 := DeriveKey(master, labelA)
	if !bytes.Equal(key1, key2) {
		t.Errorf("DeriveKey: keys for same master and label differ\nkey1: %x\nkey2: %x", key1, key2)
	}

	if len(key1) != 32 {
		t.Errorf("DeriveKey: expected key length 32, got %d", len(key1))
	}

	key3 := DeriveKey(master, labelB)
	if bytes.Equal(key1, key3) {
		t.Errorf("DeriveKey: keys for different labels should differ\nlabelA: %x\nlabelB: %x", key1, key3)
	}
}

// TestEncryptBase64WithKey_DecryptBase64WithKey checks full cycle with base64 encoding.
func TestEncryptBase64WithKey_DecryptBase64WithKey(t *testing.T) {
	master := []byte("anothermaster")
	label := "testlabel"
	key := DeriveKey(master, label)

	plaintext := "The quick brown fox jumps over the lazy dog"

	// Encrypt to base64 string
	cipherTextBase64, err := EncryptBase64WithKey([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("EncryptBase64WithKey failed: %v", err)
	}

	// Ensure ciphertext is base64-encoded
	if _, err := base64.RawURLEncoding.DecodeString(cipherTextBase64); err != nil {
		t.Errorf("EncryptBase64WithKey: output is not valid base64: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptBase64WithKey(cipherTextBase64, key)
	if err != nil {
		t.Fatalf("DecryptBase64WithKey failed: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("Round-trip plaintext mismatch\nexpected: %s\ngot: %s", plaintext, decrypted)
	}
}

// TestEncryptBytesWithKey_DecryptBytesWithKey checks encryption without base64 layer.
func TestEncryptBytesWithKey_DecryptBytesWithKey(t *testing.T) {
	master := []byte("simplemaster")
	label := "testbytes"
	key := DeriveKey(master, label)

	plaintext := "Hello world!"

	// Encrypt to raw bytes
	cipherTextBytes, err := EncryptBytesWithKey([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("EncryptBytesWithKey failed: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptBytesWithKey(cipherTextBytes, key)
	if err != nil {
		t.Fatalf("DecryptBytesWithKey failed: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("Round-trip plaintext mismatch\nexpected: %s\ngot: %s", plaintext, decrypted)
	}
}

// TestDecryptBase64WithKey_InvalidBase64 checks error on invalid base64 input.
func TestDecryptBase64WithKey_InvalidBase64(t *testing.T) {
	key := DeriveKey([]byte("mk"), "lbl")
	_, err := DecryptBase64WithKey("not_base64!", key)
	if err == nil {
		t.Errorf("Expected base64 decode error, got: %v", err)
	}
}

// TestDecryptBase64WithKey_WrongKey checks decryption fails with wrong key.
func TestDecryptBase64WithKey_WrongKey(t *testing.T) {
	master := []byte("mk1")
	label := "lbl"
	key1 := DeriveKey(master, label)

	otherMaster := []byte("mk2")
	key2 := DeriveKey(otherMaster, label)

	plaintext := "sample text"

	cipherTextBase64, err := EncryptBase64WithKey([]byte(plaintext), key1)
	if err != nil {
		t.Fatalf("EncryptBase64WithKey failed: %v", err)
	}

	_, err = DecryptBase64WithKey(cipherTextBase64, key2)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key, but it succeeded")
	}
}
