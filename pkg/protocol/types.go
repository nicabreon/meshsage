package protocol

import (
	"crypto/sha256"
	"encoding/binary"
)

// MessageEnvelope adalah struktur dasar untuk semua data yang mengalir antar node.
// Kita menggunakan tag JSON satu huruf agar ukuran paket tetap sangat kecil.
type MessageEnvelope struct {
	ID        string `json:"i"`           // Unique Message ID
	Type      string `json:"t"`           // "text", "status", "file", "group"
	Content   string `json:"c,omitempty"` // Isi pesan atau payload
	Timestamp int64  `json:"n"`           // Unix timestamp (nanoseconds)
	Status    string `json:"s,omitempty"` // "delivered", "read"
	RefID     string `json:"r,omitempty"` // Merujuk ke Message ID lain (untuk ACK/Reply)
	Sender    string `json:"u,omitempty"` // Alias pengirim (opsional)
	Signature string `json:"g,omitempty"` // Digital Signature (Ed25519)
	PoWNonce  uint64 `json:"w,omitempty"` // PoW Nonce
	PoWDiff   int    `json:"d,omitempty"` // PoW Difficulty
}

// CalculateBaseHash calculates the baseline message hash used for PoW mining/verification
func (env *MessageEnvelope) CalculateBaseHash() [32]byte {
	// Temporarily clear PoW fields to get the baseline representation
	nonce := env.PoWNonce
	diff := env.PoWDiff
	env.PoWNonce = 0
	env.PoWDiff = 0

	h := sha256.New()
	h.Write([]byte(env.ID))
	h.Write([]byte(env.Type))
	h.Write([]byte(env.Content))
	h.Write([]byte(env.Sender))

	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(env.Timestamp))
	h.Write(tsBytes)

	// Restore
	env.PoWNonce = nonce
	env.PoWDiff = diff

	var base [32]byte
	copy(base[:], h.Sum(nil))
	return base
}

// MinePoW finds a nonce that satisfies the difficulty target
func (env *MessageEnvelope) MinePoW(difficulty int) {
	if difficulty <= 0 {
		return
	}
	baseHash := env.CalculateBaseHash()
	env.PoWNonce = MinePoW(baseHash, difficulty)
	env.PoWDiff = difficulty
}

// VerifyPoW verifies if the envelope satisfies the required PoW difficulty
func (env *MessageEnvelope) VerifyPoW() bool {
	if env.PoWDiff <= 0 {
		return true
	}
	baseHash := env.CalculateBaseHash()
	return VerifyPoW(baseHash, env.PoWDiff, env.PoWNonce)
}

const (
	MsgTypeText            = "text"
	MsgTypeStatus          = "status"
	MsgTypeFile            = "file"
	MsgTypeGroup           = "group"
	MsgTypeHandshakeAck    = "hshk_ack" // Silent bidirectional handshake confirmation (never shown to user)
	MsgTypeProfileKeyShare = "profile_key_share"
	MsgTypeProfileUpdate   = "profile_update"

	StatusDelivered = "delivered"
	StatusRead      = "read"
)
