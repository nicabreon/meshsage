package storage

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// SavePrivateKey marshals the private key and saves it to a file.
func SavePrivateKey(priv crypto.PrivKey, path string) error {
	bytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Save with read/write permissions for the owner only (0600) for security
	err = os.WriteFile(path, bytes, 0600)
	if err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	return nil
}

// LoadPrivateKey reads a file and unmarshals the private key.
func LoadPrivateKey(path string) (crypto.PrivKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	priv, err := crypto.UnmarshalPrivateKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	return priv, nil
}

// LoadOrGenerateE2EEKey loads an existing X25519 private key or generates a new one
func LoadOrGenerateE2EEKey(filename string) ([]byte, error) {
	if _, statErr := os.Stat(filename); os.IsNotExist(statErr) {
		// Generate new 32-byte key
		privKey := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, privKey); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filename, privKey, 0600); err != nil {
			return nil, err
		}
		return privKey, nil
	}

	// Load existing key
	return os.ReadFile(filename)
}
