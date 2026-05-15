package crypto

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// GenerateEphemeralKeypair creates a new X25519 keypair for a session.
func GenerateEphemeralKeypair() (privateKey []byte, publicKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, err
	}
	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

// DeriveSharedSecret computes the X25519 shared secret and derives a 32-byte AES key using HKDF.
func DeriveSharedSecret(privateKey []byte, peerPublicKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Use HKDF to expand the shared secret into a robust 32-byte AES key
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("p2p-core-e2ee-v1"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %w", err)
	}

	return aesKey, nil
}

// EncryptMessage encrypts a plaintext string using AES-GCM and a 32-byte key.
func EncryptMessage(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 1. Compress the plaintext using gzip
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(plaintext)); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	compressedPlaintext := b.Bytes()

	// 2. Encrypt
	ciphertext := aesGCM.Seal(nonce, nonce, compressedPlaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts a base64 encoded string using AES-GCM and a 32-byte key.
func DecryptMessage(key []byte, b64Ciphertext string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	// 1. Decrypt
	compressedPlaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	// 2. Decompress using gzip
	b := bytes.NewReader(compressedPlaintext)
	gz, err := gzip.NewReader(b)
	if err != nil {
		// Fallback: If it fails to decompress, it might be an old uncompressed message.
		return string(compressedPlaintext), nil
	}
	defer gz.Close()

	plaintext, err := io.ReadAll(gz)
	if err != nil {
		// Fallback for partial/corrupted gzip
		return string(compressedPlaintext), nil
	}

	return string(plaintext), nil
}

// DeriveKeyFromPassword generates a 32-byte AES key from a password string.
func DeriveKeyFromPassword(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// HKDFExpand generates a key of desired length from a secret.
func HKDFExpand(secret []byte, info string, length int) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, secret, nil, []byte(info))
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// RatchetStep advances a chain key to produce a message key and a new chain key.
// This is the core of the Symmetric-Key Ratchet in Double Ratchet.
func RatchetStep(chainKey []byte) (messageKey []byte, nextChainKey []byte, err error) {
	// HKDF(ChainKey) -> [MessageKey (32 bytes), NextChainKey (32 bytes)]
	res, err := HKDFExpand(chainKey, "p2p-core-ratchet-v1", 64)
	if err != nil {
		return nil, nil, err
	}
	return res[:32], res[32:], nil
}

// EncryptMessageRaw encrypts plaintext using AES-GCM and returns raw bytes
func EncryptMessageRaw(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }

	gcm, err := cipher.NewGCM(block)
	if err != nil { return nil, err }

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return nil, err }

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptMessageRaw decrypts raw ciphertext using AES-GCM
func DecryptMessageRaw(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }

	gcm, err := cipher.NewGCM(block)
	if err != nil { return nil, err }

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, actualCiphertext, nil)
}

