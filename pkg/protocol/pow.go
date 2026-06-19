package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// PoWInfo carries difficulty and nonce parameters
type PoWInfo struct {
	Difficulty int    `json:"difficulty"`
	Nonce      uint64 `json:"nonce"`
}

// CalculateBaseHash calculates the baseline message hash used for PoW mining/verification
func CalculateBaseHash(sender, recipient, content string, timestamp int64) [32]byte {
	h := sha256.New()
	h.Write([]byte(sender))
	h.Write([]byte(recipient))
	h.Write([]byte(content))

	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestamp))
	h.Write(tsBytes)

	var base [32]byte
	copy(base[:], h.Sum(nil))
	return base
}

// VerifyPoW verifies if the nonce solves the Hashcash puzzle for the given base hash and difficulty
func VerifyPoW(baseHash [32]byte, difficulty int, nonce uint64) bool {
	if difficulty <= 0 {
		return true
	}

	h := sha256.New()
	h.Write(baseHash[:])

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, nonce)
	h.Write(nonceBytes)

	hash := h.Sum(nil)
	return countLeadingZeroBits(hash) >= difficulty
}

// MinePoW finds a nonce that satisfies the difficulty target for the given base hash
func MinePoW(baseHash [32]byte, difficulty int) uint64 {
	if difficulty <= 0 {
		return 0
	}

	var nonce uint64
	nonceBytes := make([]byte, 8)

	for nonce < math.MaxUint64 {
		h := sha256.New()
		h.Write(baseHash[:])

		binary.BigEndian.PutUint64(nonceBytes, nonce)
		h.Write(nonceBytes)

		hash := h.Sum(nil)
		if countLeadingZeroBits(hash) >= difficulty {
			return nonce
		}
		nonce++
	}
	return 0
}

// countLeadingZeroBits returns the number of leading zero bits in a 32-byte hash
func countLeadingZeroBits(hash []byte) int {
	zeros := 0
	for _, b := range hash {
		if b == 0 {
			zeros += 8
		} else {
			// Count leading zeros in this byte from MSB to LSB
			for i := 7; i >= 0; i-- {
				if ((b >> i) & 1) == 0 {
					zeros++
				} else {
					break
				}
			}
			break
		}
	}
	return zeros
}
