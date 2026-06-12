package storage

import (
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptColumn(t *testing.T) {
	// 1. Test standard encryption/decryption with default key
	plaintext := "my-highly-secret-private-key-12345"
	ciphertext, err := EncryptColumn(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt column: %v", err)
	}

	if ciphertext == plaintext {
		t.Fatalf("encryption did not modify plaintext")
	}

	decrypted, err := DecryptColumn(ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt column: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted output %q does not match plaintext %q", decrypted, plaintext)
	}

	// 2. Test custom key set
	customKey := make([]byte, 32)
	_, _ = rand.Read(customKey)
	SetDBEncryptionKey(customKey)

	ciphertext2, err := EncryptColumn(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt with custom key: %v", err)
	}

	decrypted2, err := DecryptColumn(ciphertext2)
	if err != nil {
		t.Fatalf("failed to decrypt with custom key: %v", err)
	}

	if decrypted2 != plaintext {
		t.Errorf("custom key decrypted output %q does not match plaintext %q", decrypted2, plaintext)
	}

	// 3. Test backward compatibility: plaintext strings should be returned as-is
	legacyPlaintext := "unencrypted-legacy-private-key-6789"
	legacyDecrypted, err := DecryptColumn(legacyPlaintext)
	if err != nil {
		t.Fatalf("DecryptColumn failed on legacy data: %v", err)
	}

	if legacyDecrypted != legacyPlaintext {
		t.Errorf("legacy decryption altered plaintext: got %q, want %q", legacyDecrypted, legacyPlaintext)
	}

	// 4. Test empty string handling
	emptyEncrypted, err := EncryptColumn("")
	if err != nil {
		t.Fatalf("failed to encrypt empty string: %v", err)
	}
	if emptyEncrypted != "" {
		t.Errorf("expected empty encryption output to be empty string, got %q", emptyEncrypted)
	}

	emptyDecrypted, err := DecryptColumn("")
	if err != nil {
		t.Fatalf("failed to decrypt empty string: %v", err)
	}
	if emptyDecrypted != "" {
		t.Errorf("expected empty decryption output to be empty string, got %q", emptyDecrypted)
	}

	// Reset key back to nil for other tests
	DBEncryptionKey = nil
}
