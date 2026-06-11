package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

func SendStatusUpdate(ctx context.Context, h host.Host, targetID peer.ID, refID string, status string) error {
	msgID := fmt.Sprintf("st-%x", sha256.Sum256([]byte(refID+status)))[:8]

	// DIGITAL SIGNATURE: Tanda tangani (Content + ID) agar konsisten
	privKey := h.Peerstore().PrivKey(h.ID())
	dataToSign := []byte(status + msgID) // Di sini status bertindak sebagai Content
	sigBytes, _ := privKey.Sign(dataToSign)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	msgEnv := MessageEnvelope{
		ID:        msgID,
		Type:      MsgTypeStatus,
		Status:    status,
		Content:   status, // Masukkan ke Content juga agar verifikasi di sisi penerima cocok
		RefID:     refID,
		Timestamp: time.Now().UnixNano(),
		Signature: sigB64,
	}

	// Gunakan sendSecureEnvelope agar ia sadar sesi (Double Ratchet)
	return sendSecureEnvelope(ctx, h, privKey, targetID, msgEnv)
}
