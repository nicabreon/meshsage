package crypto

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/assert"
)

func TestZKPKeypairDerivation(t *testing.T) {
	// Generate a libp2p private key (Ed25519)
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
	assert.NoError(t, err)

	k, x, y, err := DeriveZKPKeypair(priv)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	assert.NotNil(t, x)
	assert.NotNil(t, y)

	// Verify derived public key point is on P-256 curve
	curve := elliptic.P256()
	assert.True(t, curve.IsOnCurve(x, y))

	// Verify derivation is deterministic
	k2, x2, y2, err := DeriveZKPKeypair(priv)
	assert.NoError(t, err)
	assert.Equal(t, k.Cmp(k2), 0)
	assert.Equal(t, x.Cmp(x2), 0)
	assert.Equal(t, y.Cmp(y2), 0)
}

func TestRingSignatureLifecycle(t *testing.T) {
	// 1. Setup a ring of 5 public keys
	d := 5
	privKeys := make([]*big.Int, d)
	ring := make([]PubKeyPoint, d)

	for i := 0; i < d; i++ {
		p2pPriv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
		assert.NoError(t, err)

		k, x, y, err := DeriveZKPKeypair(p2pPriv)
		assert.NoError(t, err)

		privKeys[i] = k
		ring[i] = PubKeyPoint{X: x, Y: y}
	}

	msg := []byte("Hello Anonymous World!")

	// 2. Generate signature using signer index 2
	signerIndex := 2
	sig, err := GenerateRingSignature(msg, ring, signerIndex, privKeys[signerIndex])
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	// 3. Verify signature
	valid := VerifyRingSignature(msg, ring, sig)
	assert.True(t, valid, "Ring signature should be valid")

	// 4. Verify invalid message fails
	invalidMsg := []byte("Different Message")
	valid = VerifyRingSignature(invalidMsg, ring, sig)
	assert.False(t, valid, "Ring signature should fail verification with invalid message")

	// 5. Verify invalid ring fails
	invalidRing := make([]PubKeyPoint, len(ring))
	copy(invalidRing, ring)
	// Modify one public key in the ring
	invalidRing[0] = PubKeyPoint{X: big.NewInt(123), Y: big.NewInt(456)}
	valid = VerifyRingSignature(msg, invalidRing, sig)
	assert.False(t, valid, "Ring signature should fail verification with modified ring")
}

func TestRingSignatureLinkability(t *testing.T) {
	d := 3
	privKeys := make([]*big.Int, d)
	ring := make([]PubKeyPoint, d)

	for i := 0; i < d; i++ {
		p2pPriv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
		assert.NoError(t, err)

		k, x, y, err := DeriveZKPKeypair(p2pPriv)
		assert.NoError(t, err)

		privKeys[i] = k
		ring[i] = PubKeyPoint{X: x, Y: y}
	}

	msg1 := []byte("Message One")
	msg2 := []byte("Message Two")

	// Signer at index 1 signs two different messages
	sig1, err := GenerateRingSignature(msg1, ring, 1, privKeys[1])
	assert.NoError(t, err)
	sig2, err := GenerateRingSignature(msg2, ring, 1, privKeys[1])
	assert.NoError(t, err)

	// Verify key images are identical (linkability)
	assert.True(t, bytes.Equal(sig1.KeyImageX, sig2.KeyImageX), "KeyImageX should be identical for the same signer")
	assert.True(t, bytes.Equal(sig1.KeyImageY, sig2.KeyImageY), "KeyImageY should be identical for the same signer")

	// Signer at index 2 signs the first message
	sig3, err := GenerateRingSignature(msg1, ring, 2, privKeys[2])
	assert.NoError(t, err)

	// Verify key image is different for different signers
	assert.False(t, bytes.Equal(sig1.KeyImageX, sig3.KeyImageX), "KeyImageX should be different for different signers")
}
