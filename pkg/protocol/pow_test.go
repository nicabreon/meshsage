package protocol

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPoWMiningAndVerification(t *testing.T) {
	sender := "12D3KooWFZTmWWGaeNFY7ro95DtiSoV5txAqv6iZCERy6vLWTA95"
	recipient := "12D3KooWHPz1n31QZg51n39gZ"
	content := "Hello, World!"
	timestamp := time.Now().Unix()

	baseHash := CalculateBaseHash(sender, recipient, content, timestamp)

	// Test with low difficulty to ensure fast mining in tests
	difficulty := 8
	nonce := MinePoW(baseHash, difficulty)

	assert.True(t, VerifyPoW(baseHash, difficulty, nonce), "Mined nonce should satisfy difficulty target")
	assert.False(t, VerifyPoW(baseHash, difficulty, nonce+1), "Arbitrary nonce should not satisfy difficulty target")
}
