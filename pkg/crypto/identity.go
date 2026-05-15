package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// GenerateKeyPair creates a new Ed25519 keypair for the node identity.
func GenerateKeyPair() (crypto.PrivKey, crypto.PubKey, error) {
	priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return priv, pub, nil
}

// GetPeerID generates a peer ID from a public key.
func GetPeerID(pub crypto.PubKey) (peer.ID, error) {
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to get peer ID from public key: %w", err)
	}
	return id, nil
}

// Sign creates a signature for a message using the private key.
func Sign(priv crypto.PrivKey, message []byte) ([]byte, error) {
	return priv.Sign(message)
}

// Verify checks if a signature is valid for a message and public key.
func Verify(pub crypto.PubKey, message []byte, signature []byte) (bool, error) {
	return pub.Verify(message, signature)
}
