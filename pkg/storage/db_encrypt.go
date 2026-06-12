package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
)

var DBEncryptionKey []byte

// SetDBEncryptionKey sets the database encryption key (stable per node).
func SetDBEncryptionKey(key []byte) {
	if len(key) == 32 {
		DBEncryptionKey = make([]byte, 32)
		copy(DBEncryptionKey, key)
	} else {
		hasher := sha256.New()
		hasher.Write(key)
		DBEncryptionKey = hasher.Sum(nil)
	}
}

// getEncryptionKey returns the set key or a default stable fallback key.
func getEncryptionKey() []byte {
	if len(DBEncryptionKey) == 32 {
		return DBEncryptionKey
	}
	// Fallback key derived from static string (ensures tests work out-of-the-box)
	hasher := sha256.New()
	hasher.Write([]byte("meshsage-default-sqlite-encrypt-key-stable-32bytes"))
	return hasher.Sum(nil)
}

// EncryptColumn encrypts selective column data. Returns formatted ciphertext with "enc:" prefix.
func EncryptColumn(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key := getEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptColumn decrypts selective column data. If not prefixed with "enc:", returns as-is (backward compatibility).
func DecryptColumn(data string) (string, error) {
	if data == "" {
		return "", nil
	}
	if !strings.HasPrefix(data, "enc:") {
		// Legacy unencrypted data, return as-is
		return data, nil
	}
	ciphertextB64 := data[4:]
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return data, nil // fallback as-is
	}
	key := getEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return data, nil // fallback as-is
	}
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return data, nil // fallback as-is
	}
	return string(plaintext), nil
}
