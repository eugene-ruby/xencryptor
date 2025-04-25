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

// TestEncryptDecryptWithKey ensures that EncryptWithKey and DecryptWithKey are inverses
// for a given key and plaintext.
func TestEncryptDecryptWithKey(t *testing.T) {
	master := []byte("anothermaster")
	label := "testlabel"
	key := DeriveKey(master, label)

	plaintext := []byte("The quick brown fox jumps over the lazy dog")

	// Encrypt the plaintext
	cipherText, err := EncryptWithKey(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}

	// Ensure ciphertext is base64-encoded
	if _, err := base64.RawURLEncoding.DecodeString(cipherText); err != nil {
		t.Errorf("EncryptWithKey: output is not valid base64: %v", err)
	}

	// Decrypt with the same key
	decrypted, err := DecryptWithKey(cipherText, key)
	if err != nil {
		t.Fatalf("DecryptWithKey failed: %v", err)
	}

	if !bytes.Equal([]byte(decrypted), plaintext) {
		t.Errorf("Round-trip plaintext mismatch\nexpected: %s\ngot: %s", plaintext, decrypted)
	}
}

// TestDecryptWithKey_InvalidBase64 checks error on non-base64 input.
func TestDecryptWithKey_InvalidBase64(t *testing.T) {
	key := DeriveKey([]byte("mk"), "lbl")
	_, err := DecryptWithKey("not_base64!", key)
	if err == nil {
		t.Errorf("Expected base64 decode error, got: %v", err)
	}
}

// TestDecryptWithKey_WrongKey verifies that decryption with a wrong key fails.
func TestDecryptWithKey_WrongKey(t *testing.T) {
	master := []byte("mk1")
	label := "lbl"
	key1 := DeriveKey(master, label)

	otherMaster := []byte("mk2")
	key2 := DeriveKey(otherMaster, label)

	plaintext := []byte("sample text")
	cipherText, err := EncryptWithKey(plaintext, key1)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}

	// Attempt decrypt with a different key
	_, err = DecryptWithKey(cipherText, key2)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key, but it succeeded")
	}
}
