package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/nicabreon/meshsage/pkg/logger"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

// sendRequestX3DH sends a lightweight signal to the target peer asking them
// to clear their local session and re-initiate a fresh X3DH handshake.
// This is used instead of RESET to break the mutual-reset deadlock.
//
// Rate-limited: maksimal 1 sinyal per peer per 30 detik. Ini mencegah
// REQUEST_X3DH storm ketika banyak pesan dari mailbox gagal didekripsi
// secara bersamaan — semua pesan gagal tersebut akan dicoba kirim REQUEST_X3DH
// tapi hanya 1 yang benar-benar terkirim, sisanya di-skip.
func sendRequestX3DH(ctx context.Context, h host.Host, targetID peer.ID) {
	const cooldownDuration = 30 * time.Second
	peerKey := targetID.String()

	now := time.Now()
	if lastVal, ok := x3dhRequestCooldown.Load(peerKey); ok {
		if lastTime, ok := lastVal.(time.Time); ok && now.Sub(lastTime) < cooldownDuration {
			logger.Debug().
				Str("targetID", peerKey).
				Dur("remaining", cooldownDuration-now.Sub(lastTime)).
				Msg("sendRequestX3DH: skipped (cooldown active)")
			return
		}
	}
	x3dhRequestCooldown.Store(peerKey, now)

	logger.Info().Str("targetID", peerKey).Msg("Sending REQUEST_X3DH signal to peer")
	_ = transmitEnvelope(ctx, h, targetID, "REQUEST_X3DH")
}

// sendHandshakeAck is called by the X3DH receiver (B) after successfully decrypting
// the initiator's (A's) first X3DH message. It sends a silent MsgTypeHandshakeAck
// envelope back to A via Double Ratchet, which:
//  1. Forces B to use its newly established send-chain (proving B's session is live).
//  2. Causes A to perform a DH ratchet step on receipt, completing the full
//     bidirectional Double Ratchet session without any user-visible interaction.
//
// If the ACK cannot be delivered (peer offline), it falls back to mailbox storage
// like any other message — the session will self-heal via the normal X3DH auto-recovery.
func sendHandshakeAck(ctx context.Context, h host.Host, targetID peer.ID) {
	privKey := h.Peerstore().PrivKey(h.ID())
	if privKey == nil {
		logger.Warn().Str("targetID", targetID.String()).Msg("sendHandshakeAck: local private key not available, skipping ACK")
		return
	}
	ackID := fmt.Sprintf("hshk-%x", sha256.Sum256([]byte(targetID.String()+time.Now().String())))[:12]
	ackEnv := MessageEnvelope{
		ID:        ackID,
		Type:      MsgTypeHandshakeAck,
		Timestamp: time.Now().UnixNano(),
	}
	if err := sendSecureEnvelope(ctx, h, privKey, targetID, ackEnv); err != nil {
		logger.Debug().Err(err).Str("targetID", targetID.String()).Msg("sendHandshakeAck: failed to send ACK (peer may be offline, will recover on next message)")
	} else {
		logger.Info().Str("targetID", targetID.String()).Msg("sendHandshakeAck: X3DH ACK sent — bidirectional session is now complete")
		// Automatically send profile key share right after ACK is sent
		go func() {
			time.Sleep(100 * time.Millisecond) // Let it settle
			if err := SendProfileKeyShare(ctx, h, targetID); err != nil {
				logger.Warn().Err(err).Str("targetID", targetID.String()).Msg("Failed to auto-send profile key share after ACK")
			}
		}()
	}
}

// ProbeSessionWarmup is proactively called when a known chat peer connects.
// It sends a silent handshake ACK to warm up the Double Ratchet session
// and verify bidirectional health before the user actually sends a message.
func ProbeSessionWarmup(ctx context.Context, h host.Host, priv crypto.PrivKey, targetID peer.ID) {
	if priv == nil {
		logger.Warn().Str("targetID", targetID.String()).Msg("ProbeSessionWarmup: local private key not available, skipping probe")
		return
	}
	if !corestore.HasSession(targetID.String()) {
		logger.Debug().Str("targetID", targetID.String()).Msg("ProbeSessionWarmup: no session exists, skipping probe")
		return
	}
	probeID := fmt.Sprintf("probe-%x", sha256.Sum256([]byte(targetID.String()+time.Now().String())))[:12]
	probeEnv := MessageEnvelope{
		ID:        probeID,
		Type:      MsgTypeHandshakeAck,
		Timestamp: time.Now().UnixNano(),
	}
	logger.Info().Str("targetID", targetID.String()).Msg("ProbeSessionWarmup: sending proactive session warm-up probe")
	if err := sendSecureEnvelope(ctx, h, priv, targetID, probeEnv); err != nil {
		logger.Debug().Err(err).Str("targetID", targetID.String()).Msg("ProbeSessionWarmup: failed to send probe (peer might have gone offline)")
	} else {
		logger.Info().Str("targetID", targetID.String()).Msg("ProbeSessionWarmup: session warm-up probe successfully sent")
		// Proactively share our E2EE profile key whenever we warm up the session
		go func() {
			time.Sleep(200 * time.Millisecond) // Let it settle
			if err := SendProfileKeyShare(ctx, h, targetID); err != nil {
				logger.Warn().Err(err).Str("targetID", targetID.String()).Msg("Failed to auto-send profile key share on warm-up probe success")
			}
		}()
	}
}

// InitiateSession triggers a silent X3DH handshake to proactively establish
// a Double Ratchet session with a peer (e.g. when adding them to contacts).
func InitiateSession(ctx context.Context, h host.Host, priv crypto.PrivKey, target peer.ID) error {
	privKey := h.Peerstore().PrivKey(h.ID())
	if privKey == nil {
		return fmt.Errorf("local private key not found in peerstore")
	}

	// If session already exists, send a warmup probe to verify health
	if corestore.HasSession(target.String()) {
		logger.Info().Str("targetID", target.String()).Msg("Session already exists, sending proactive warmup probe instead")
		ProbeSessionWarmup(ctx, h, priv, target)
		return nil
	}

	ackID := fmt.Sprintf("hshk-%x", sha256.Sum256([]byte(target.String()+time.Now().String())))[:12]
	ackEnv := MessageEnvelope{
		ID:        ackID,
		Type:      MsgTypeHandshakeAck,
		Timestamp: time.Now().UnixNano(),
	}

	logger.Info().Str("targetID", target.String()).Msg("Initiating proactive Double Ratchet session via silent handshake ack")
	return sendSecureEnvelope(ctx, h, privKey, target, ackEnv)
}

// SendSessionReset sends a signed session reset signal to a target peer,
// and deletes the local session state to force a new X3DH handshake next time.
func SendSessionReset(ctx context.Context, h host.Host, targetID peer.ID) error {
	privKey := h.Peerstore().PrivKey(h.ID())
	if privKey == nil {
		return fmt.Errorf("local private key not found in peerstore")
	}
	timestamp := time.Now().Unix()
	dataToSign := []byte(fmt.Sprintf("RESET:%d:%s:%s", timestamp, h.ID().String(), targetID.String()))
	sigBytes, err := privKey.Sign(dataToSign)
	if err != nil {
		logger.Error().Err(err).Str("targetID", targetID.String()).Msg("Failed to sign RESET signal")
		return err
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
	resetEnvelope := fmt.Sprintf("RESET:%d:%s", timestamp, sigB64)

	// Delete local session first to clean up local state
	_ = corestore.DeleteSession(targetID.String())

	logger.Info().Str("targetID", targetID.String()).Msg("Sending E2EE Session Reset signal to peer")
	return transmitEnvelope(ctx, h, targetID, resetEnvelope)
}
