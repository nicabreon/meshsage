package crypto

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// PubKeyPoint represents a public key point on an elliptic curve.
// Defined here (separate from experimental ZKP code) so that other packages
// (e.g. storage, protocol) can reference the type without importing experimental code.
type PubKeyPoint struct {
	X *big.Int
	Y *big.Int
}

// DeriveZKPKeypair derives a deterministic P-256 private key and public key point
// from a libp2p private key. Used to derive a stable ZKP identity for pre-key uploads.
func DeriveZKPKeypair(priv crypto.PrivKey) (k *big.Int, x *big.Int, y *big.Int, err error) {
	raw, err := priv.Raw()
	if err != nil {
		return nil, nil, nil, err
	}

	h := sha256.Sum256(raw)
	curve := elliptic.P256()
	n := curve.Params().N

	k = new(big.Int).SetBytes(h[:])
	k.Mod(k, n)
	if k.Sign() == 0 {
		k.SetInt64(1)
	}

	x, y = curve.ScalarBaseMult(k.Bytes())
	return k, x, y, nil
}
