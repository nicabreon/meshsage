package protocol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	"github.com/nicabreon/meshsage/pkg/logger"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

const MessagingProtocolID = "/p2p-core/msg/1.0.0"

// sessionLocks menyimpan mutex per-peer untuk mencegah race condition
// saat concurrent goroutine mengakses Double Ratchet session state.
var (
	localHost    host.Host
	sessionLocks sync.Map // map[peerID string]*sync.Mutex

	// x3dhRequestCooldown mencegah REQUEST_X3DH storm:
	// ketika banyak pesan gagal didekripsi secara bersamaan (misal saat mailbox fetch
	// mendapat 9 pesan dan semua gagal karena tidak ada sesi), setiap pesan akan
	// memanggil sendRequestX3DH. Tanpa cooldown ini, 9 REQUEST_X3DH dikirim
	// ke sender yang sama dalam milidetik → sender membalas 9 handshake → loop.
	// Map ini menyimpan waktu terakhir REQUEST_X3DH dikirim per peerID.
	// Cooldown: 30 detik per peer.
	x3dhRequestCooldown sync.Map // map[peerID string]time.Time
)

// sentMsg adalah pesan yang sudah dikirim oleh node ini, disimpan untuk kemungkinan retry
// jika receiver mengalami masalah sesi dan meminta X3DH ulang.
type sentMsg struct {
	env    MessageEnvelope
	sentAt time.Time
}

const (
	maxSentPerPeer = 20               // max pesan tersimpan per peer
	sentMsgTTL     = 10 * time.Minute // pesan lebih lama dari ini tidak di-retry
)

var (
	sentMsgMu  sync.Mutex
	sentMsgBuf = make(map[string][]sentMsg) // peerID → []sentMsg
)

// trackSentMessage menyimpan pesan yang baru dikirim ke buffer per-peer.
// Dipanggil oleh SendMessage setelah berhasil mengirim.
func trackSentMessage(peerID string, env MessageEnvelope) {
	sentMsgMu.Lock()
	defer sentMsgMu.Unlock()

	list := sentMsgBuf[peerID]
	now := time.Now()
	// Buang yang sudah kadaluarsa
	filtered := list[:0]
	for _, m := range list {
		if now.Sub(m.sentAt) < sentMsgTTL {
			filtered = append(filtered, m)
		}
	}
	// Jaga batas ukuran: hapus yang terlama
	if len(filtered) >= maxSentPerPeer {
		filtered = filtered[1:]
	}
	filtered = append(filtered, sentMsg{env: env, sentAt: now})
	sentMsgBuf[peerID] = filtered
}

// retrySentMessages dipanggil saat REQUEST_X3DH diterima dari peer.
// Setelah X3DH baru berhasil dibentuk, kirim ulang semua pesan yang
// sebelumnya sudah dikirim ke peer tersebut dalam TTL window.
func retrySentMessages(ctx context.Context, h host.Host, priv crypto.PrivKey, targetID peer.ID) {
	peerID := targetID.String()
	sentMsgMu.Lock()
	list, ok := sentMsgBuf[peerID]
	if !ok || len(list) == 0 {
		sentMsgMu.Unlock()
		return
	}
	now := time.Now()
	toResend := make([]MessageEnvelope, 0, len(list))
	for _, m := range list {
		if now.Sub(m.sentAt) < sentMsgTTL {
			toResend = append(toResend, m.env)
		}
	}
	// Hapus buffer setelah diambil
	delete(sentMsgBuf, peerID)
	sentMsgMu.Unlock()

	if len(toResend) == 0 {
		return
	}
	logger.Info().Str("peerID", peerID[:8]).Int("count", len(toResend)).Msg("Retrying sent messages after X3DH re-handshake")
	for _, env := range toResend {
		// Jeda kecil agar session state sudah tersimpan ke DB
		time.Sleep(80 * time.Millisecond)
		if err := sendSecureEnvelope(ctx, h, priv, targetID, env); err != nil {
			logger.Warn().Err(err).Str("peerID", peerID[:8]).Str("msgID", env.ID).Msg("Retry sent message failed")
		} else {
			logger.Info().Str("peerID", peerID[:8]).Str("msgID", env.ID).Msg("Sent message retried successfully after X3DH")
		}
	}
}

// getSessionLock mengembalikan mutex khusus untuk peerID tertentu.
func getSessionLock(peerID string) *sync.Mutex {
	val, _ := sessionLocks.LoadOrStore(peerID, &sync.Mutex{})
	return val.(*sync.Mutex)
}

func SetupMessaging(h host.Host) {
	localHost = h
	h.SetStreamHandler(MessagingProtocolID, handleStream)
}

func handleStream(s network.Stream) {
	defer s.Close()
	senderID := s.Conn().RemotePeer()

	buf := bufio.NewReader(s)
	var length uint32
	if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
		logger.Warn().Err(err).Msg("handleStream: failed to read length prefix")
		return
	}

	envelopeBytes := make([]byte, length)
	if _, err := io.ReadFull(buf, envelopeBytes); err != nil {
		logger.Warn().Err(err).Msg("handleStream: failed to read envelope payload")
		return
	}

	// Track incoming bytes (4-byte length prefix + envelope payload)
	AddBytesRecv(4 + len(envelopeBytes))

	ProcessSecureEnvelope(context.Background(), localHost, senderID, string(envelopeBytes), "")

	// Kirim balik "OK\n" sebagai tanda terima (ACK)
	_, _ = s.Write([]byte("OK\n"))
}

// ProcessSecureEnvelope menangani dekripsi X3DH dan pemrosesan JSON payload
func ProcessSecureEnvelope(ctx context.Context, h host.Host, senderID peer.ID, envelope string, msgHash string) {
	success := false

	// Detect and unwrap SignedMailboxEnvelope if present
	actualEnvelope := envelope
	if strings.HasPrefix(envelope, "{") {
		var signedEnv SignedMailboxEnvelope
		if err := json.Unmarshal([]byte(envelope), &signedEnv); err == nil && signedEnv.Payload != "" {
			actualEnvelope = signedEnv.Payload
		}
	}
	envelope = actualEnvelope

	envHashBytes := sha256.Sum256([]byte(envelope))
	envHash := fmt.Sprintf("%x", envHashBytes)

	defer func() {
		if success {
			_ = corestore.SaveProcessedEnvelope(envHash)
		}
		if msgHash != "" {
			if success {
				processedMailboxMessages.Store(msgHash, true)
				_ = corestore.SaveProcessedMailboxMessage(msgHash)
			} else {
				processedMailboxMessages.Delete(msgHash)
				_ = corestore.DeleteProcessedMailboxMessage(msgHash)
			}
		}
	}()

	if corestore.IsEnvelopeProcessed(envHash) {
		logger.Info().Str("envHash", envHash[:8]).Msg("ProcessSecureEnvelope: Envelope ciphertext already processed, skipping duplicate")
		success = true
		return
	}

	envType := "UNKNOWN"
	if strings.HasPrefix(envelope, "RESET:") {
		envType = "RESET"
	} else if strings.HasPrefix(envelope, "REQUEST_X3DH") {
		envType = "REQUEST_X3DH"
	} else if strings.HasPrefix(envelope, "DR:") {
		envType = "DR"
	} else if strings.HasPrefix(envelope, "X3DH:") {
		envType = "X3DH"
	}
	logger.Info().Str("senderID", senderID.String()).Str("type", envType).Msg("ProcessSecureEnvelope: processing incoming envelope")

	var aesKey []byte
	var encryptedPayloadB64 string
	var isX3DH bool
	var keyID string

	if strings.HasPrefix(envelope, "RESET:") {
		parts := strings.SplitN(envelope, ":", 3)
		if len(parts) != 3 {
			logger.Error().Msg("Invalid RESET envelope format")
			return
		}
		timestampStr := parts[1]
		sigB64 := parts[2]

		// Try ExtractPublicKey first (works for Ed25519 inline peer IDs)
		// Fall back to peerstore if not available (e.g. RSA, secp256k1)
		pubKey, err := senderID.ExtractPublicKey()
		if err != nil || pubKey == nil {
			pubKey = h.Peerstore().PubKey(senderID)
			if pubKey == nil {
				logger.Warn().Str("senderID", senderID.String()).Msg("RESET: sender public key not available, accepting reset without verification")
				// Accept the reset unconditionally if we have no way to verify
				if delErr := corestore.DeleteSession(senderID.String()); delErr != nil {
					logger.Error().Err(delErr).Str("senderID", senderID.String()).Msg("RESET: failed to delete session state (unverified)")
				}
				// Ask sender to restart X3DH
				go sendRequestX3DH(ctx, h, senderID)
				success = true
				return
			}
		}

		dataToVerify := []byte(fmt.Sprintf("RESET:%s:%s:%s", timestampStr, senderID.String(), h.ID().String()))
		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			logger.Error().Err(err).Msg("RESET: failed to decode signature")
			return
		}

		valid, err := pubKey.Verify(dataToVerify, sigBytes)
		if err != nil || !valid {
			logger.Warn().Str("senderID", senderID.String()).Msg("RESET: invalid signature detected")
			return
		}

		// Signature is valid! Delete the session state for the sender
		logger.Info().Str("senderID", senderID.String()).Msg("RESET: Session reset request verified. Deleting session state.")
		if err := corestore.DeleteSession(senderID.String()); err != nil {
			logger.Error().Err(err).Str("senderID", senderID.String()).Msg("RESET: failed to delete session state")
		}
		// Ask sender to re-initiate X3DH so both sides are in sync
		go sendRequestX3DH(ctx, h, senderID)
		success = true
		return
	}

	if strings.HasPrefix(envelope, "REQUEST_X3DH") {
		// Counterparty's pre-key was not found or their session is corrupt.
		// Clear our local session and automatically re-initiate a fresh X3DH
		// so the handshake completes without requiring the user to send a message.
		logger.Info().Str("senderID", senderID.String()).Msg("REQUEST_X3DH: Clearing local session and auto-reinitiating fresh X3DH handshake.")
		_ = corestore.DeleteSession(senderID.String())
		_ = corestore.ClearSkippedKeys(senderID.String())
		// Re-initiate after a brief delay to give the remote node time to upload
		// fresh pre-keys if they just started up (avoids immediate 'no pre-key' failure).
		// After X3DH re-handshake completes, retry any recently sent messages
		// that the receiver couldn't decrypt (their ratchet key was stale).
		go func(target peer.ID) {
			time.Sleep(2 * time.Second)
			sendHandshakeAck(ctx, h, target)
			// X3DH ACK selesai → session baru sudah tersedia di kedua sisi.
			// Tunggu sebentar untuk memastikan ACK diterima dan session di-save,
			// lalu re-send semua pesan yang sebelumnya gagal di-decrypt oleh receiver.
			privKey := h.Peerstore().PrivKey(h.ID())
			if privKey != nil {
				time.Sleep(500 * time.Millisecond)
				retrySentMessages(ctx, h, privKey, target)
			}
		}(senderID)
		success = true
		return
	}

	if strings.HasPrefix(envelope, "DR:") {
		// 1. Jalur Double Ratchet (Per-message Keys)
		parts := strings.SplitN(envelope, ":", 2)
		if len(parts) < 2 {
			logger.Error().Msg("ProcessSecureEnvelope: DR envelope format invalid (missing parts)")
			return
		}

		// Format DR:RatchetPub|PN|N|Ciphertext
		rawPayload, _ := base64.StdEncoding.DecodeString(parts[1])
		payloadStr := string(rawPayload)
		headerParts := strings.SplitN(payloadStr, "|", 4)

		if len(headerParts) == 4 {
			counter, _ := strconv.ParseUint(headerParts[2], 10, 32)

			// BUG-03: Lock per-peer agar tidak ada race condition pada session state
			sessionMu := getSessionLock(senderID.String())
			sessionMu.Lock()
			defer sessionMu.Unlock()

			// A. Cek Skipped Keys dulu
			skippedKey, skippedErr := corestore.GetSkippedKey(senderID.String(), uint32(counter))
			if skippedErr == nil {
				logger.Info().Str("peerID", senderID.String()).Uint32("counter", uint32(counter)).Msg("DR: Using skipped message key")
				// BUG-02 FIX: Gunakan DecryptMessage (bukan DecryptMessageRaw) karena
				// EncryptWithRatchet menggunakan EncryptMessage yang menyertakan gzip.
				plaintext, decErr := corecrypto.DecryptMessage(skippedKey, headerParts[3])
				if decErr == nil {
					// Skipped key berhasil — pesan sudah didekripsi
					if processDecryptedPayload(ctx, h, senderID, []byte(plaintext), msgHash) {
						success = true
					}
					return
				}
				// Skipped key stale/corrupt dari epoch lama (GetSkippedKey sudah hapus atomik).
				// JANGAN return — fall through ke jalur ratchet normal di bawah.
				// Counter yang sama di session baru harus bisa didekripsi via ratchet biasa.
				logger.Warn().Str("peerID", senderID.String()).Uint32("counter", uint32(counter)).Err(decErr).Msg("DR: Stale skipped key failed, falling through to normal ratchet")
			}

			// B. Jalur Standard Ratchet
			// Dicapai saat: (1) tidak ada skipped key, atau (2) skipped key stale/gagal decrypt.
			remoteIdentityB64, rootB64, sendB64, recvB64, remoteRatchetB64, localRatchetPrivB64, localRatchetPubB64, n, m, pn, err := corestore.LoadSession(senderID.String())
			if err != nil || rootB64 == "" {
				logger.Error().Str("peerID", senderID.String()).Msg("No session found for E2EE decryption. Sending REQUEST_X3DH to sender.")
				// Do NOT send RESET here (we have nothing to reset).
				// Instead, ask the sender to start fresh X3DH.
				go sendRequestX3DH(ctx, h, senderID)
				pushDecryptionErrorToUI(senderID, "No E2EE session found for decryption (requires X3DH handshake)")
				return
			}

			rootKey, _ := base64.StdEncoding.DecodeString(rootB64)
			sendChain, _ := base64.StdEncoding.DecodeString(sendB64)
			recvChain, _ := base64.StdEncoding.DecodeString(recvB64)
			remoteRatchetPub, _ := base64.StdEncoding.DecodeString(remoteRatchetB64)
			localRatchetPriv, _ := base64.StdEncoding.DecodeString(localRatchetPrivB64)
			localRatchetPub, _ := base64.StdEncoding.DecodeString(localRatchetPubB64)

			if len(recvChain) == 0 {
				recvChain = rootKey
			}

			session := &corecrypto.SessionState{
				PeerID:              senderID.String(),
				RootKey:             rootKey,
				SendChainKey:        sendChain,
				RecvChainKey:        recvChain,
				RemoteRatchetPubkey: remoteRatchetPub,
				LocalRatchetPrivkey: localRatchetPriv,
				LocalRatchetPubkey:  localRatchetPub,
				N:                   n,
				M:                   m,
				PN:                  pn,
			}

			plaintext, skipped, err := session.DecryptWithRatchet(payloadStr)
			if err != nil {
				logger.Error().Str("peerID", senderID.String()).Err(err).Msg("DR Decryption failed. Clearing session and requesting fresh X3DH.")
				_ = corestore.DeleteSession(senderID.String())
				_ = corestore.ClearSkippedKeys(senderID.String())
				go sendRequestX3DH(ctx, h, senderID)
				pushDecryptionErrorToUI(senderID, "Double Ratchet decryption failed: "+err.Error())
				return
			}

			// Berhasil dekripsi! Simpan state baru
			// BUG-1 FIX: If the session.RemoteRatchetPubkey changed during DecryptWithRatchet,
			// a DH ratchet step occurred. Clear ALL old skipped keys — they belong to the old
			// epoch and will permanently fail decryption.
			oldRemoteRatchet, _ := base64.StdEncoding.DecodeString(remoteRatchetB64)
			if !bytes.Equal(oldRemoteRatchet, session.RemoteRatchetPubkey) {
				if clearErr := corestore.ClearSkippedKeys(senderID.String()); clearErr != nil {
					logger.Warn().Err(clearErr).Str("peerID", senderID.String()).Msg("DR: Failed to clear stale skipped keys after DH step")
				} else {
					logger.Debug().Str("peerID", senderID.String()).Msg("DR: DH ratchet step detected — cleared stale skipped keys")
				}
			}
			corestore.SaveSession(senderID.String(), remoteIdentityB64,
				base64.StdEncoding.EncodeToString(session.RootKey),
				base64.StdEncoding.EncodeToString(session.SendChainKey),
				base64.StdEncoding.EncodeToString(session.RecvChainKey),
				base64.StdEncoding.EncodeToString(session.RemoteRatchetPubkey),
				base64.StdEncoding.EncodeToString(session.LocalRatchetPrivkey),
				base64.StdEncoding.EncodeToString(session.LocalRatchetPubkey),
				session.N, session.M, session.PN)

			// Simpan skipped keys
			for c, k := range skipped {
				corestore.SaveSkippedKey(senderID.String(), c, k)
			}

			logger.Info().Str("senderID", senderID.String()).Msg("ProcessSecureEnvelope: Double Ratchet envelope decrypted successfully")
			if processDecryptedPayload(ctx, h, senderID, []byte(plaintext), msgHash) {
				success = true
			}
			return
		} else {
			logger.Error().Int("parts", len(headerParts)).Msg("ProcessSecureEnvelope: DR payload header format invalid (must have 4 parts)")
			return
		}

	} else if strings.HasPrefix(envelope, "X3DH:") {
		// 2. Jalur Handshake X3DH (Lengkap)
		logger.Info().Str("peerID", senderID.String()).Msg("Receiving new X3DH Handshake")
		// Format baru: X3DH:keyID:ePub:senderRatchetPub:encryptedPayload
		parts := strings.SplitN(envelope, ":", 5)
		if len(parts) < 4 {
			logger.Error().Int("parts", len(parts)).Msg("ProcessSecureEnvelope: X3DH envelope format invalid (too few parts)")
			return
		}

		isX3DH = true
		keyID = parts[1]
		ePubB64 := parts[2]
		// Dukung format lama (4 parts) dan baru (5 parts dengan ratchetPub)
		var senderRatchetPubB64 string
		if len(parts) == 5 {
			senderRatchetPubB64 = parts[3]
			encryptedPayloadB64 = parts[4]
		} else {
			encryptedPayloadB64 = parts[3]
		}

		privKeyB64, err := corestore.FindPrivateKeyByID(keyID)
		if err != nil || privKeyB64 == "" {
			logger.Error().Str("keyID", keyID).Str("senderID", senderID.String()).Msg("Receiver's Pre-Key not found (expired or rotated). Requesting fresh X3DH from sender.")
			// Tell sender to fetch a fresh pre-key and retry with a new X3DH handshake.
			go sendRequestX3DH(ctx, h, senderID)
			pushDecryptionErrorToUI(senderID, "Receiver's pre-key not found in local DB (expired or rotated)")
			return
		}
		privKeyBytes, _ := base64.StdEncoding.DecodeString(privKeyB64)
		ePubBytes, _ := base64.StdEncoding.DecodeString(ePubB64)
		logger.Debug().Msg("Deriving shared secret from receiver's Pre-Key...")
		aesKey, err = corecrypto.DeriveSharedSecret(privKeyBytes, ePubBytes)
		if err != nil {
			logger.Error().Err(err).Msg("ProcessSecureEnvelope: X3DH DeriveSharedSecret failed")
			return
		}

		// Inisialisasi ratchet keys di sisi receiver
		bobPreKeyPub, err := corecrypto.DerivePublicKey(privKeyBytes)
		if err != nil {
			logger.Error().Err(err).Msg("ProcessSecureEnvelope: X3DH DerivePublicKey failed")
			return
		}
		bobPreKeyPubB64 := base64.StdEncoding.EncodeToString(bobPreKeyPub)

		// Lakukan DH Receive Step awal menggunakan privKeyBytes (Bob_PreKey_Priv) dan senderRatchetPub
		recvRootKey := aesKey
		recvChainKey := []byte{}
		if senderRatchetPubB64 != "" {
			senderRatchetPubBytes, decErr := base64.StdEncoding.DecodeString(senderRatchetPubB64)
			if decErr == nil {
				recvChainSecret, dhErr := corecrypto.DeriveSharedSecret(privKeyBytes, senderRatchetPubBytes)
				if dhErr == nil {
					res, err := corecrypto.HKDFExpand(recvChainSecret, "p2p-core-dh-ratchet", 64)
					if err == nil {
						recvRootKey = res[:32]
						recvChainKey = res[32:]
					}
				}
			}
		}

		// Generate local ratchet keypair baru untuk Bob
		localRatchetPriv, localRatchetPub, _ := corecrypto.GenerateEphemeralKeypair()
		localRatchetPrivB64 := base64.StdEncoding.EncodeToString(localRatchetPriv)
		localRatchetPubB64 := base64.StdEncoding.EncodeToString(localRatchetPub)

		// Lakukan DH Send Step awal
		sendRootKey := recvRootKey
		sendChainKey := []byte{}
		if senderRatchetPubB64 != "" {
			senderRatchetPubBytes, decErr := base64.StdEncoding.DecodeString(senderRatchetPubB64)
			if decErr == nil {
				sharedSecretSend, dhErr := corecrypto.DeriveSharedSecret(localRatchetPriv, senderRatchetPubBytes)
				if dhErr == nil {
					resSend, err := corecrypto.HKDFExpand(sharedSecretSend, "p2p-core-dh-ratchet", 64)
					if err == nil {
						sendRootKey = resSend[:32]
						sendChainKey = resSend[32:]
					}
				}
			}
		}

		rootKeyB64 := base64.StdEncoding.EncodeToString(sendRootKey)
		sendChainB64 := base64.StdEncoding.EncodeToString(sendChainKey)
		recvChainB64 := base64.StdEncoding.EncodeToString(recvChainKey)

		logger.Info().Str("rootKey", rootKeyB64[:6]).Msg("Initial session established")
		// BUG-1 FIX: Clear ALL stale skipped keys from old epochs before saving new session.
		// Old skipped keys (keyed by peerID+counter) belong to a different ratchet epoch
		// and will always fail decryption with "cipher: message authentication failed".
		if clearErr := corestore.ClearSkippedKeys(senderID.String()); clearErr != nil {
			logger.Warn().Err(clearErr).Str("peerID", senderID.String()).Msg("X3DH: Failed to clear stale skipped keys")
		} else {
			logger.Debug().Str("peerID", senderID.String()).Msg("X3DH: Cleared stale skipped keys for new session")
		}
		// Simpan dengan SendChainKey, RecvChainKey dan ratchet keys terisi lengkap
		corestore.SaveSession(senderID.String(), bobPreKeyPubB64, rootKeyB64, sendChainB64, recvChainB64, senderRatchetPubB64, localRatchetPrivB64, localRatchetPubB64, 0, 0, 0)
	} else {
		snippet := envelope
		if len(snippet) > 50 {
			snippet = snippet[:50] + "..."
		}
		logger.Warn().Str("senderID", senderID.String()).Str("envelope", snippet).Msg("ProcessSecureEnvelope: unknown or unhandled envelope type")
		pushDecryptionErrorToUI(senderID, "Unknown envelope prefix (envelope: "+snippet+")")
		return
	}

	// 3. Dekripsi Payload
	encryptedPayload, _ := base64.StdEncoding.DecodeString(encryptedPayloadB64)
	plaintextBytes, err := corecrypto.DecryptMessageRaw(aesKey, encryptedPayload)
	if err != nil {
		logger.Error().Str("peerID", senderID.String()).Err(err).Msg("E2EE X3DH Decryption failed (message authentication failed). Clearing bad session and requesting fresh X3DH.")
		// Clear the bad session we just saved so next attempt starts clean
		_ = corestore.DeleteSession(senderID.String())
		_ = corestore.ClearSkippedKeys(senderID.String())
		// Ask sender to restart with a new X3DH
		go sendRequestX3DH(ctx, h, senderID)
		pushDecryptionErrorToUI(senderID, "X3DH decryption failed: "+err.Error())
		return
	}

	// If this was an X3DH handshake, delete the consumed pre-key only after successful decryption
	if isX3DH {
		if err := corestore.DeletePreKeyByID(keyID); err != nil {
			logger.Warn().Err(err).Str("keyID", keyID).Msg("Failed to delete consumed pre-key from local DB")
		} else {
			logger.Info().Str("keyID", keyID).Msg("Successfully deleted consumed pre-key from local DB after handshake decryption")
		}
	}

	// X3DH Handshake ACK: send a silent ack back to the initiator.
	// This forces B to encrypt using its newly established send-chain,
	// which in turn causes A to perform a DH ratchet step when it decrypts
	// the ACK — completing the bidirectional Double Ratchet session fully
	// without any user-visible message being shown on either side.
	go sendHandshakeAck(ctx, h, senderID)

	logger.Info().Str("senderID", senderID.String()).Msg("ProcessSecureEnvelope: X3DH envelope decrypted successfully")
	if processDecryptedPayload(ctx, h, senderID, plaintextBytes, msgHash) {
		success = true
	}
}

func processDecryptedPayload(ctx context.Context, h host.Host, senderID peer.ID, plaintextBytes []byte, msgHash string) bool {
	// 4. Unmarshal JSON
	var env MessageEnvelope
	if err := json.Unmarshal(plaintextBytes, &env); err != nil {
		logger.Error().Err(err).Str("plaintext", string(plaintextBytes)).Msg("processDecryptedPayload: failed to unmarshal decrypted JSON payload")
		pushDecryptionErrorToUI(senderID, "Failed to parse decrypted message JSON: "+err.Error())
		return false
	}
	logger.Info().Str("msgID", env.ID).Str("type", env.Type).Msg("processDecryptedPayload: successfully unmarshaled decrypted JSON envelope")

	// 5. Verifikasi Signature
	if env.Signature != "" {
		pubKey, err := senderID.ExtractPublicKey()
		if err == nil {
			dataToVerify := []byte(env.Content + env.ID)
			sigBytes, _ := base64.StdEncoding.DecodeString(env.Signature)
			valid, _ := pubKey.Verify(dataToVerify, sigBytes)
			if !valid {
				logger.Warn().Str("peerID", senderID.String()).Msg("INVALID SIGNATURE detected!")
				return false
			}
			logger.Debug().Str("peerID", senderID.String()).Msg("Message signature verified")
		}
	}

	// 6. Handle Content
	logger.Info().Str("msgID", env.ID).Str("senderID", senderID.String()).Msg("processDecryptedPayload: payload verification succeeded, handling content")
	return handleIncomingPayload(ctx, h, senderID, env, msgHash)
}

func pushDecryptionErrorToUI(senderID peer.ID, errStr string) {
	if MessageCallback != nil {
		ts := time.Now().Format("02/01 15:04:05")
		errID := fmt.Sprintf("err-%x", sha256.Sum256([]byte(errStr+time.Now().String())))[:8]
		content := "[Error: Failed to decrypt message: " + errStr + "]"

		// Simpan error ini ke SQLite database lokal agar tersimpan di chat history
		if localHost != nil {
			_ = corestore.SaveMessage(senderID.String(), localHost.ID().String(), content, "", "", "")
		}

		MessageCallback(MessageEvent{
			Type:      "direct",
			MsgID:     errID,
			Timestamp: ts,
			Sender:    senderID.String(),
			Content:   content,
			UnixTime:  time.Now().UnixNano() / 1e6,
		})
	}
}

func handleIncomingPayload(ctx context.Context, h host.Host, senderID peer.ID, env MessageEnvelope, msgHash string) bool {
	if env.Sender != "" {
		aliasHash := GetAliasCoordinate(env.Sender)
		pubKey := h.Peerstore().PubKey(senderID)
		var pubKeyBytes []byte
		if pubKey != nil {
			pubKeyBytes, _ = pubKey.Raw()
		}
		_ = corestore.SaveAlias(aliasHash, env.Sender, senderID.String(), pubKeyBytes)
		logger.Info().Str("alias", env.Sender).Str("peerID", senderID.String()).Msg("handleIncomingPayload: saved/updated sender alias locally")
	}

	switch env.Type {
	case MsgTypeHandshakeAck:
		// Silent: X3DH bidirectional handshake completed. No UI display.
		// Receiving this ACK means both sides now have a fully operational
		// Double Ratchet session in both directions.
		logger.Info().Str("peerID", senderID.String()).Msg("X3DH handshake ACK received: bidirectional session established")
		return true

	case MsgTypeStatus:
		logger.Displayf("[Status Report] Peer %s marked your message %s as: %s\n",
			FormatPeerID(senderID.String()), env.RefID, env.Status)
		// Forward to Flutter via StatusCallback
		if StatusCallback != nil {
			StatusCallback(StatusEvent{
				RefID:  env.RefID,
				Status: env.Status,
				Sender: senderID.String(),
			})
		}
		return true

	case MsgTypeText:
		// Check for Group Key Request (GCMD:GREQ:groupID)
		if strings.HasPrefix(env.Content, "GCMD:GREQ:") {
			parts := strings.SplitN(env.Content, ":", 3)
			if len(parts) == 3 {
				groupID := parts[2]
				logger.Info().
					Str("group", groupID).
					Str("requester", FormatPeerID(senderID.String())).
					Msg("[GREQ] Received direct key request, sharing local key")

				localKey, err := corestore.GetGroupLocalKey(groupID)
				if err == nil {
					go shareKeyWithMember(ctx, h, h.Peerstore().PrivKey(h.ID()), groupID, senderID.String(), localKey)
				}
				return true
			}
		}

		// Check for Group Key sharing (GKEY:groupID:base64Key1,base64Key2,...)
		if strings.HasPrefix(env.Content, "GKEY:") {
			parts := strings.SplitN(env.Content, ":", 3)
			if len(parts) == 3 {
				groupID := parts[1]
				keysStr := parts[2]
				keyB64s := strings.Split(keysStr, ",")

				// Process from oldest to newest so the newest becomes the active key
				savedCount := 0
				for i := len(keyB64s) - 1; i >= 0; i-- {
					keyBytes, errDec := base64.StdEncoding.DecodeString(keyB64s[i])
					if errDec == nil {
						corestore.SaveGroupSenderKey(groupID, senderID.String(), keyBytes)
						savedCount++
					}
				}

				logger.Info().
					Str("group", groupID).
					Str("peerID", senderID.String()).
					Int("keysCount", savedCount).
					Msg("Received and saved Group Session Key(s) (via Double Ratchet)")
				// Flush any buffered messages that were waiting for this key
				go FlushPendingGroupMessages(groupID, senderID.String())
				return true
			}
		}

		// Check for Group Invitation (GINVITE:<json>)
		if strings.HasPrefix(env.Content, "GINVITE:") {
			inviteStr := strings.TrimPrefix(env.Content, "GINVITE:")
			logger.Debug().Str("inviteStr", inviteStr).Msg("Received GINVITE message, parsing...")
			var invite struct {
				Meta    corestore.GroupMetadata `json:"meta"`
				Members []string                `json:"members"`
				GKey    string                  `json:"gkey"`
			}
			if err := json.Unmarshal([]byte(inviteStr), &invite); err != nil {
				logger.Error().Err(err).Msg("Failed to unmarshal GINVITE JSON")
				return true
			}

			// Verify Creator Signature
			creatorID, errDec := peer.Decode(invite.Meta.CreatorID)
			if errDec != nil {
				logger.Error().Err(errDec).Str("creator", invite.Meta.CreatorID).Msg("Failed to decode creator peer ID")
				return true
			}
			pubKey := h.Peerstore().PubKey(creatorID)
			var errExtract error
			if pubKey == nil {
				pubKey, errExtract = creatorID.ExtractPublicKey()
				if errExtract != nil {
					logger.Error().Err(errExtract).Str("creator", invite.Meta.CreatorID).Msg("Failed to extract creator public key")
					return true
				}
			}

			dataToVerify := []byte(invite.Meta.GroupID + invite.Meta.GroupAlias + invite.Meta.CreatorID + fmt.Sprintf("%d", invite.Meta.CreatedAt))
			sigBytes, _ := base64.StdEncoding.DecodeString(invite.Meta.Signature)
			valid, errVerify := pubKey.Verify(dataToVerify, sigBytes)
			if errVerify != nil {
				logger.Error().Err(errVerify).Msg("Error verifying GINVITE signature")
				return true
			}
			if !valid {
				logger.Error().Str("group", invite.Meta.GroupAlias).Msg("Received GINVITE with INVALID signature!")
				return true
			}

			errJoin := JoinGroupProper(ctx, h, h.Peerstore().PrivKey(h.ID()),
				invite.Meta.GroupID, invite.Meta.GroupAlias, invite.Meta.CreatorID, invite.Meta.GroupType, invite.Meta.Signature, invite.Meta.CreatedAt, invite.Members)
			if errJoin != nil {
				logger.Error().Err(errJoin).Str("group", invite.Meta.GroupAlias).Msg("Failed to join group in GINVITE handler")
			}

			if invite.GKey != "" {
				keyBytes, _ := base64.StdEncoding.DecodeString(invite.GKey)
				_ = corestore.SaveGroupSenderKey(invite.Meta.GroupID, invite.Meta.CreatorID, keyBytes)
				// Flush any buffered messages waiting for the creator's key
				go FlushPendingGroupMessages(invite.Meta.GroupID, invite.Meta.CreatorID)
			}
			return true
		}

		// Check for Group Message prefix (Offline Fan-out)
		if strings.HasPrefix(env.Content, "GRPM:") {
			parts := strings.SplitN(env.Content, ":", 3)
			if len(parts) == 3 {
				return ProcessGroupMessage(parts[1], []byte(parts[2]), msgHash)
			}
		}

		// Persist to SQLite only for actual user-visible chat messages
		corestore.SaveMessage(senderID.String(), h.ID().String(), env.Content, env.ID, msgHash, "direct")

		logger.Info().Str("senderID", senderID.String()).Str("msgID", env.ID).Msg("Received standard text message successfully")

		ts := time.Now().Format("02/01 15:04:05")
		logger.Displayf("\033[92m[%s] [Message from %s]: %s\033[0m\n", ts, FormatSender(senderID.String()), env.Content)
		TrackMsgRecv() // Track incoming message
		if MessageCallback != nil {
			MessageCallback(MessageEvent{
				Type:      "direct",
				MsgID:     env.ID,
				Timestamp: ts,
				Sender:    senderID.String(),
				Content:   env.Content,
				UnixTime:  env.Timestamp / 1e6,
			})
		}
		// OTOMATIS: Kirim status "delivered" (Centang 2)
		go SendStatusUpdate(ctx, h, senderID, env.ID, StatusDelivered)
		return true

	case MsgTypeFile:
		// Persist to SQLite
		corestore.SaveMessage(senderID.String(), h.ID().String(), env.Content, env.ID, msgHash, "file")

		parts := strings.Split(env.Content, ":")
		if len(parts) >= 4 {
			ts := time.Now().Format("02/01 15:04:05")
			logger.Displayf("\033[92m[%s] [FILE from %s]: %s (%s bytes)\033[0m\n", ts, FormatSender(senderID.String()), parts[2], parts[3])
			logger.Displayf("\033[33m>> To download, use: /download %s %s\033[0m\n", parts[0], parts[1])
			if MessageCallback != nil {
				MessageCallback(MessageEvent{
					Type:      "file",
					Timestamp: ts,
					Sender:    senderID.String(),
					Content:   env.Content,
					UnixTime:  env.Timestamp / 1e6,
				})
			}
		}
		return true

	case MsgTypeGroup:
		return ProcessGroupMessage(env.RefID, []byte(env.Content), "")
	default:
		logger.Warn().Str("type", env.Type).Str("msgID", env.ID).Msg("handleIncomingPayload: received message with unknown or unhandled type")
		return true
	}
}

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

func prepareSecureEnvelope(ctx context.Context, h host.Host, priv crypto.PrivKey, targetID peer.ID, jsonPayload []byte) (string, error) {
	startPrep := time.Now()
	defer func() {
		logger.Info().Str("target", targetID.String()).Dur("elapsed", time.Since(startPrep)).Msg("LOG_STEP: prepareSecureEnvelope completed")
	}()

	// BUG-03: Lock per-peer agar tidak ada race condition pada session state
	sessionMu := getSessionLock(targetID.String())
	sessionMu.Lock()
	defer sessionMu.Unlock()

	// 1. Cek apakah sudah punya sesi aktif (Session Cache)
	remoteIdentityB64, rootB64, sendB64, recvB64, remoteRatchetB64, localRatchetPrivB64, localRatchetPubB64, n, m, pn, err := corestore.LoadSession(targetID.String())
	if err == nil && rootB64 != "" {
		// Sesi Aktif Ditemukan!
		rootKey, _ := base64.StdEncoding.DecodeString(rootB64)
		sendChain, _ := base64.StdEncoding.DecodeString(sendB64)
		recvChain, _ := base64.StdEncoding.DecodeString(recvB64)
		remoteRatchetPub, _ := base64.StdEncoding.DecodeString(remoteRatchetB64)
		localRatchetPriv, _ := base64.StdEncoding.DecodeString(localRatchetPrivB64)
		localRatchetPub, _ := base64.StdEncoding.DecodeString(localRatchetPubB64)

		if len(sendChain) == 0 {
			sendChain = rootKey
		}

		session := &corecrypto.SessionState{
			PeerID:              targetID.String(),
			RemoteIdentityKey:   []byte(remoteIdentityB64),
			RootKey:             rootKey,
			SendChainKey:        sendChain,
			RecvChainKey:        recvChain,
			RemoteRatchetPubkey: remoteRatchetPub,
			LocalRatchetPrivkey: localRatchetPriv,
			LocalRatchetPubkey:  localRatchetPub,
			N:                   n,
			M:                   m,
			PN:                  pn,
		}

		ciphertext, err := session.EncryptWithRatchet(string(jsonPayload))
		if err == nil {
			// Save updated state
			corestore.SaveSession(targetID.String(), remoteIdentityB64,
				base64.StdEncoding.EncodeToString(session.RootKey),
				base64.StdEncoding.EncodeToString(session.SendChainKey),
				base64.StdEncoding.EncodeToString(session.RecvChainKey),
				base64.StdEncoding.EncodeToString(session.RemoteRatchetPubkey),
				base64.StdEncoding.EncodeToString(session.LocalRatchetPrivkey),
				base64.StdEncoding.EncodeToString(session.LocalRatchetPubkey),
				session.N, session.M, session.PN)

			finalWireEnvelope := fmt.Sprintf("DR:%s", base64.StdEncoding.EncodeToString([]byte(ciphertext)))
			return finalWireEnvelope, nil
		}
	}

	// 2. Jika tidak ada sesi, lakukan alur X3DH
	var keyID, pubKeyB64 string
	preKeyFound := false
	connectedPeers := h.Network().Peers()
	logger.Info().
		Str("target", targetID.String()).
		Int("peers", len(connectedPeers)).
		Msg("No session found. Initiating X3DH Handshake flow")

	for _, relayPeer := range connectedPeers {
		// Optimization: Check if peer supports the pre-key protocol before attempting to dial
		protos, err := h.Peerstore().GetProtocols(relayPeer)
		if err != nil {
			continue
		}
		supportsPreKey := false
		for _, proto := range protos {
			if string(proto) == PreKeyProtocolID {
				supportsPreKey = true
				break
			}
		}
		if !supportsPreKey {
			continue
		}

		logger.Info().Str("target", targetID.String()).Str("relay", relayPeer.String()).Msg("LOG_STEP: X3DH HANDSHAKE: Fetching Pre-Key starting...")
		startFetch := time.Now()
		id, pub, _, err := FetchPreKey(ctx, h, relayPeer, targetID.String())
		logger.Info().Str("target", targetID.String()).Str("relay", relayPeer.String()).Dur("elapsed", time.Since(startFetch)).Err(err).Msg("LOG_STEP: X3DH HANDSHAKE: FetchPreKey finished")
		if err == nil && pub != "" {
			keyID = id
			pubKeyB64 = pub
			preKeyFound = true
			logger.Info().Str("target", targetID.String()).Str("relay", relayPeer.String()).Msg("X3DH SUCCESS: Pre-Key found")
			break
		}
		logger.Debug().
			Err(err).
			Str("target", targetID.String()).
			Str("relay", relayPeer.String()).
			Msg("X3DH: FetchPreKey failed from this peer (not a relay, or no key available)")
	}
	if !preKeyFound {
		logger.Warn().
			Str("target", targetID.String()).
			Int("peers_tried", len(connectedPeers)).
			Msg("X3DH FAILED: no pre-key found for target on any connected peer")
		return "", fmt.Errorf("no pre-key found")
	}

	logger.Debug().Msg("X3DH HANDSHAKE: Generating Ephemeral Keypair & Deriving Shared Secret")
	ePriv, ePub, err := corecrypto.GenerateEphemeralKeypair()
	if err != nil {
		return "", err
	}

	peerPubKeyBytes, _ := base64.StdEncoding.DecodeString(pubKeyB64)
	aesKey, err := corecrypto.DeriveSharedSecret(ePriv, peerPubKeyBytes)
	if err != nil {
		return "", err
	}

	// Inisialisasi Double Ratchet: Generate ratchet keypair lokal
	localRatchetPriv, localRatchetPub, err := corecrypto.GenerateEphemeralKeypair()
	if err != nil {
		return "", err
	}

	// Lakukan DH Send Step awal menggunakan localRatchetPriv dan pubKeyB64 (Pre-key Bob)
	sharedSecret, err := corecrypto.DeriveSharedSecret(localRatchetPriv, peerPubKeyBytes)
	if err != nil {
		return "", err
	}
	res, err := corecrypto.HKDFExpand(sharedSecret, "p2p-core-dh-ratchet", 64)
	if err != nil {
		return "", err
	}

	initRootKey := res[:32]
	initSendChainKey := res[32:]

	senderRootKeyB64 := base64.StdEncoding.EncodeToString(initRootKey)
	senderSendChainB64 := base64.StdEncoding.EncodeToString(initSendChainKey)
	senderRatchetPrivB64 := base64.StdEncoding.EncodeToString(localRatchetPriv)
	senderRatchetPubB64Out := base64.StdEncoding.EncodeToString(localRatchetPub)

	logger.Info().Str("peerID", FormatPeerID(targetID.String())).Str("rootKey", senderRootKeyB64[:6]).Msg("X3DH HANDSHAKE: Saving Initial Session with Ratchet Keys")
	TrackHandshake() // Track X3DH handshake
	// BUG-1 FIX: Sender side — clear stale skipped keys before establishing new session.
	if clearErr := corestore.ClearSkippedKeys(targetID.String()); clearErr != nil {
		logger.Warn().Err(clearErr).Str("peerID", targetID.String()).Msg("X3DH SEND: Failed to clear stale skipped keys")
	} else {
		logger.Debug().Str("peerID", targetID.String()).Msg("X3DH SEND: Cleared stale skipped keys for new session")
	}
	// Simpan session dengan SendChainKey terisi, RecvChainKey kosong, dan RemoteRatchetPubkey = pubKeyB64
	corestore.SaveSession(targetID.String(), pubKeyB64, senderRootKeyB64, senderSendChainB64, "", pubKeyB64, senderRatchetPrivB64, senderRatchetPubB64Out, 0, 0, 0)

	// Sertakan localRatchetPub di dalam payload agar receiver bisa init RecvChainKey
	ePubB64 := base64.StdEncoding.EncodeToString(ePub)
	encryptedBytes, err := corecrypto.EncryptMessageRaw(aesKey, jsonPayload)
	if err != nil {
		return "", err
	}

	// Format: X3DH:keyID:ePub:senderRatchetPub:encryptedPayload
	finalWireEnvelope := fmt.Sprintf("X3DH:%s:%s:%s:%s", keyID, ePubB64, senderRatchetPubB64Out, base64.StdEncoding.EncodeToString(encryptedBytes))
	return finalWireEnvelope, nil
}

func sendSecureEnvelope(ctx context.Context, h host.Host, priv crypto.PrivKey, targetID peer.ID, env MessageEnvelope) error {
	jsonPayload, _ := json.Marshal(env)
	finalWireEnvelope, err := prepareSecureEnvelope(ctx, h, priv, targetID, jsonPayload)
	if err != nil {
		return err
	}
	return transmitEnvelope(ctx, h, targetID, finalWireEnvelope)
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
	}
}

// deriveNextKeys is deprecated, logic moved to corecrypto.RatchetStep

func SendMessage(ctx context.Context, h host.Host, priv crypto.PrivKey, target peer.ID, msg string) (string, error) {
	msg = strings.TrimSuffix(msg, "\n")
	msgID := fmt.Sprintf("%x", sha256.Sum256([]byte(msg+time.Now().String())))[:8]
	dataToSign := []byte(msg + msgID)
	sigBytes, _ := priv.Sign(dataToSign)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	senderAlias, _ := corestore.FindAliasByPeerID(h.ID().String())

	env := MessageEnvelope{
		ID:        msgID,
		Type:      MsgTypeText,
		Content:   msg,
		Timestamp: time.Now().UnixNano(),
		Sender:    senderAlias,
		Signature: sigB64,
	}

	// Simpan pesan ke sent-message buffer per-peer.
	// Jika receiver mengalami masalah sesi dan mengirim REQUEST_X3DH,
	// pesan ini akan di-kirim ulang setelah X3DH baru selesai.
	trackSentMessage(target.String(), env)

	return msgID, sendSecureEnvelope(ctx, h, priv, target, env)
}

var (
	customDialTimeouts sync.Map // map[string]time.Duration
	customDialRTTs     sync.Map // map[string]time.Duration
)

// getRelayRTT returns the minimum stream dial RTT to any currently connected dedicated relay.
// If no dedicated relay is connected or measured, it returns 0.
func getRelayRTT(h host.Host) time.Duration {
	if h == nil {
		return 0
	}
	var bestRTT time.Duration = 0
	for _, p := range h.Network().Peers() {
		// Verify if peer is a dedicated relay
		protos, err := h.Peerstore().GetProtocols(p)
		if err != nil {
			continue
		}
		isDedicated := false
		for _, proto := range protos {
			if string(proto) == "/p2p-core/infra/dedicated/1.1.0" {
				isDedicated = true
				break
			}
		}
		if isDedicated {
			if val, ok := customDialRTTs.Load(p.String()); ok {
				if rtt, ok := val.(time.Duration); ok {
					if bestRTT == 0 || rtt < bestRTT {
						bestRTT = rtt
					}
				}
			}
		}
	}
	return bestRTT
}

// MeasureAndRecordDialTimeout measures stream creation latency to a newly connected peer
// and saves a custom adaptive dial timeout for it.
func MeasureAndRecordDialTimeout(ctx context.Context, h host.Host, target peer.ID) {
	go func() {
		// Wait a moment for connection handshakes (QUIC/TCP, security, muxer) to settle down.
		time.Sleep(1 * time.Second)

		logger.Info().Str("target", target.String()).Msg("LOG_STEP: MeasureAndRecordDialTimeout: Initiating test stream to measure latency...")
		start := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		s, err := h.NewStream(dialCtx, target, "/ipfs/ping/1.0.0")
		cancel()

		if err == nil {
			elapsed := time.Since(start)
			s.Close()

			customDialRTTs.Store(target.String(), elapsed)

			// Calculate adaptive timeout: 3 * elapsed + 1 second buffer (longer buffer to handle spikes or relay routes)
			timeout := 3*elapsed + 1*time.Second
			if timeout < 500*time.Millisecond {
				timeout = 500 * time.Millisecond
			}
			if timeout > 3*time.Second {
				timeout = 3 * time.Second
			}

			customDialTimeouts.Store(target.String(), timeout)
			logger.Info().
				Str("target", target.String()).
				Dur("stream_dial_rtt", elapsed).
				Dur("dial_timeout", timeout).
				Msg("LOG_STEP: MeasureAndRecordDialTimeout: Successfully measured stream creation time and saved custom dial timeout")
		} else {
			logger.Warn().
				Str("target", target.String()).
				Err(err).
				Msg("LOG_STEP: MeasureAndRecordDialTimeout: Failed to open test stream to measure latency")
		}
	}()
}

func getPeerDialTimeout(ctx context.Context, h host.Host, target peer.ID) time.Duration {
	// Establish maximum timeout limit. Hard cap is 3 seconds.
	maxLimit := 3 * time.Second

	// If we are connected to a dedicated relay, scale maxLimit dynamically based on the relay's RTT.
	// Since relay routing takes at least 1 relay RTT (plus stream negotiation/handshakes),
	// we scale the limit to 3 * relayRTT + 500ms.
	if relayRTT := getRelayRTT(h); relayRTT > 0 {
		adaptiveLimit := 3*relayRTT + 500*time.Millisecond
		if adaptiveLimit < maxLimit {
			maxLimit = adaptiveLimit
			// Ensure a floor of 1.0 second so we don't time out too aggressively under normal jitter
			if maxLimit < 1*time.Second {
				maxLimit = 1 * time.Second
			}
		}
	}

	// First, check if we have a measured custom dial timeout
	if val, ok := customDialTimeouts.Load(target.String()); ok {
		if timeout, ok := val.(time.Duration); ok {
			if timeout > maxLimit {
				timeout = maxLimit
			}
			logger.Debug().
				Str("target", target.String()).
				Dur("dial_timeout", timeout).
				Dur("max_limit", maxLimit).
				Msg("LOG_STEP: getPeerDialTimeout: Using custom recorded dial timeout (capped by limit)")
			return timeout
		}
	}

	// Retrieve EWMA latency from Peerstore
	ewma := h.Peerstore().LatencyEWMA(target)
	if ewma > 0 {
		// Calculate adaptive timeout: 4x RTT + 500ms safety buffer
		timeout := 4 * ewma + 500 * time.Millisecond
		// Bound it between 300ms and maxLimit
		if timeout < 300*time.Millisecond {
			timeout = 300 * time.Millisecond
		}
		if timeout > maxLimit {
			timeout = maxLimit
		}
		logger.Debug().
			Str("target", target.String()).
			Dur("ewma_rtt", ewma).
			Dur("calculated_timeout", timeout).
			Dur("max_limit", maxLimit).
			Msg("LOG_STEP: getPeerDialTimeout: Calculated timeout using stored EWMA latency")
		return timeout
	}

	// Fallback to active ping measurement if no EWMA latency is stored
	logger.Debug().Str("target", target.String()).Msg("LOG_STEP: getPeerDialTimeout: No EWMA latency stored, performing active ping...")
	pingCtx, pingCancel := context.WithTimeout(ctx, 1*time.Second)
	defer pingCancel()
	pings := ping.Ping(pingCtx, h, target)
	select {
	case res, ok := <-pings:
		if ok && res.Error == nil && res.RTT > 0 {
			timeout := 4 * res.RTT + 500 * time.Millisecond
			if timeout < 300*time.Millisecond {
				timeout = 300 * time.Millisecond
			}
			if timeout > maxLimit {
				timeout = maxLimit
			}
			logger.Debug().
				Str("target", target.String()).
				Dur("ping_rtt", res.RTT).
				Dur("calculated_timeout", timeout).
				Dur("max_limit", maxLimit).
				Msg("LOG_STEP: getPeerDialTimeout: Calculated timeout using active ping")
			return timeout
		}
	case <-pingCtx.Done():
	}

	// Default fallback timeout
	fallback := 3 * time.Second
	if fallback > maxLimit {
		fallback = maxLimit
	}
	logger.Debug().Str("target", target.String()).Dur("fallback", fallback).Msg("LOG_STEP: getPeerDialTimeout: Active ping failed or timed out, falling back to default")
	return fallback
}

func transmitEnvelope(ctx context.Context, h host.Host, target peer.ID, finalWireEnvelope string) error {
	startTransmit := time.Now()
	defer func() {
		logger.Info().Str("target", target.String()).Dur("elapsed", time.Since(startTransmit)).Msg("LOG_STEP: transmitEnvelope completed")
	}()

	if target == h.ID() {
		logger.Info().Msg("transmitEnvelope: Self-message detected, processing locally without network dial")
		go ProcessSecureEnvelope(ctx, h, h.ID(), finalWireEnvelope, "")
		return nil
	}

	// Cek apakah ada koneksi aktif ke peer tersebut (direct maupun via relay)
	isConnected := len(h.Network().ConnsToPeer(target)) > 0

	var s network.Stream
	var err error

	if isConnected {
		logger.Info().Str("target", target.String()).Msg("LOG_STEP: transmitEnvelope: Active connection found, attempting direct stream dial...")
		dialTimeout := getPeerDialTimeout(ctx, h, target)
		logger.Info().Str("target", target.String()).Dur("timeout", dialTimeout).Msg("LOG_STEP: transmitEnvelope: Using calculated dial timeout")

		startDial := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		s, err = h.NewStream(dialCtx, target, MessagingProtocolID)
		cancel()
		logger.Info().Str("target", target.String()).Dur("elapsed", time.Since(startDial)).Err(err).Msg("LOG_STEP: transmitEnvelope: NewStream dial finished")

		if err == nil {
			logger.Debug().Str("target", target.String()).Msg("transmitEnvelope: Direct stream succeeded, writing envelope")
			s.SetWriteDeadline(time.Now().Add(1 * time.Second))
			startWrite := time.Now()
			errWrite := binary.Write(s, binary.LittleEndian, uint32(len(finalWireEnvelope)))
			if errWrite == nil {
				_, errWrite = s.Write([]byte(finalWireEnvelope))
			}
			logger.Info().Str("target", target.String()).Dur("elapsed", time.Since(startWrite)).Err(errWrite).Msg("LOG_STEP: transmitEnvelope: stream Write finished")

			if errWrite == nil {
				// Read ACK
				respReader := bufio.NewReader(s)
				s.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				startAck := time.Now()
				resp, errRead := respReader.ReadString('\n')
				logger.Info().Str("target", target.String()).Dur("elapsed", time.Since(startAck)).Err(errRead).Msg("LOG_STEP: transmitEnvelope: stream Read ACK finished")
				if errRead != nil || strings.TrimSpace(resp) != "OK" {
					errWrite = fmt.Errorf("did not receive ACK from target: %v", errRead)
				}
			}
			s.Close()
			if errWrite == nil {
				// Track outgoing bytes (4-byte length prefix + envelope payload)
				AddBytesSent(4 + len(finalWireEnvelope))

				// Determine connection type for routing logs
				routeType := "DIRECT (QUIC/UDP)"
				conns := h.Network().ConnsToPeer(target)
				if len(conns) > 0 {
					addrStr := conns[0].RemoteMultiaddr().String()
					if strings.Contains(addrStr, "p2p-circuit") {
						routeType = "RELAYED (Circuit)"
					} else if strings.Contains(addrStr, "webrtc-direct") {
						routeType = "DIRECT (WebRTC)"
					}
				}
				logger.Info().
					Str("peerID", target.String()).
					Str("route", routeType).
					Msg(">>> MESSAGE DELIVERED ONLINE")

				return nil
			}
			logger.Warn().Err(errWrite).Str("target", target.String()).Msg("transmitEnvelope: Direct write failed, falling back to mailbox")
			err = errWrite
		} else {
			logger.Warn().Err(err).Str("target", target.String()).Msg("transmitEnvelope: Dial stream failed, falling back to mailbox")
		}
	} else {
		logger.Info().Str("target", target.String()).Msg("transmitEnvelope: No active connection found, skipping dial and sending via offline mailbox")
	}

	// Wrap envelope with standard signature for spam-proof mailbox storage
	sigWrapped, errSig := WrapEnvelopeWithSignature(h.Peerstore().PrivKey(h.ID()), finalWireEnvelope)
	if errSig == nil {
		finalWireEnvelope = sigWrapped
	} else {
		logger.Warn().Err(errSig).Msg("Failed to wrap envelope with standard signature, sending unwrapped")
	}

	encodedEnvelope := base64.StdEncoding.EncodeToString([]byte(finalWireEnvelope))
	// Pass the actual marshalled public key (not the peer ID string) so the
	// receiver can correctly reconstruct the sender peer ID when fetching from mailbox.
	pubKeyBytes, errMarshal := crypto.MarshalPublicKey(h.Peerstore().PubKey(h.ID()))
	if errMarshal != nil {
		pubKeyBytes, _ = h.ID().MarshalBinary() // fallback: use raw peer ID bytes
	}
	senderPubkeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	logger.Info().
		Str("peerID", target.String()).
		Msg(">>> TARGET OFFLINE/UNREACHABLE: Storing message in offline mailbox")

	// Run mailbox storage in the background to avoid blocking the FFI / UI thread
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := StoreOfflineMessage(bgCtx, h, target, senderPubkeyB64, encodedEnvelope)
		if err != nil {
			logger.Warn().Err(err).Str("target", target.String()).Msg("Background StoreOfflineMessage failed")
		} else {
			logger.Info().
				Str("peerID", target.String()).
				Msg(">>> OFFLINE MAILBOX UPLOAD SUCCESSFUL")
		}
	}()
	return nil
}

func StartChatPrompt(ctx context.Context, h host.Host, priv crypto.PrivKey) {
	// Goroutine 1: Manual Stdin
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			msg, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			msg = strings.TrimSpace(msg)
			if msg != "" {
				ProcessCommand(ctx, h, priv, msg)
			}
		}
	}()

	// Goroutine 2: Automated File Input
	go func() {
		inputPath := os.Getenv("P2P_INPUT_PATH")
		if inputPath == "" {
			inputPath = "/tmp/p2p_input"
		}
		for {
			time.Sleep(1 * time.Second)
			info, err := os.Stat(inputPath)
			if err == nil && info.Mode().IsRegular() {
				content, err := os.ReadFile(inputPath)
				if err == nil && len(content) > 0 {
					// Clear the file immediately before processing to avoid race conditions with subsequent writes
					os.WriteFile(inputPath, []byte(""), 0644)

					lines := strings.Split(string(content), "\n")
					for _, line := range lines {
						cmd := strings.TrimSpace(line)
						if cmd != "" {
							logger.Debug().Str("command", cmd).Msg("Executing automated command from file")
							ProcessCommand(ctx, h, priv, cmd)
						}
					}
				}
			}
		}
	}()
}

func resolveTargetPeerID(ctx context.Context, h host.Host, targetStr string) (peer.ID, error) {
	// First, if it doesn't look like an alias (doesn't start with @), try to decode it directly
	if !strings.HasPrefix(targetStr, "@") {
		if targetID, err := peer.Decode(targetStr); err == nil {
			return targetID, nil
		}
	}

	// Otherwise, treat it as an alias (prepend @ if missing)
	aliasToResolve := targetStr
	if !strings.HasPrefix(aliasToResolve, "@") {
		aliasToResolve = "@" + aliasToResolve
	}

	// Exclude group aliases
	if _, errMeta := corestore.LoadGroupMetadata(aliasToResolve); errMeta == nil {
		return "", fmt.Errorf("'%s' is a group alias, cannot send private messages to it", aliasToResolve)
	}
	if meta, errGroup := ResolveGroupMetadata(ctx, h, aliasToResolve); errGroup == nil && meta.GroupID != "" {
		return "", fmt.Errorf("'%s' is a group alias, cannot send private messages to it", aliasToResolve)
	}

	resolved, err := ResolveAlias(ctx, h, aliasToResolve)
	if err != nil {
		return "", fmt.Errorf("failed to resolve alias %s: %w", aliasToResolve, err)
	}

	return peer.Decode(resolved)
}

func ProcessCommand(ctx context.Context, h host.Host, priv crypto.PrivKey, msgStr string) {
	msgStr = strings.TrimSpace(msgStr)
	if msgStr == "" {
		return
	}

	if strings.HasPrefix(msgStr, "/latency ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			targetID, err := resolveTargetPeerID(ctx, h, parts[1])
			if err == nil {
				pings := ping.Ping(ctx, h, targetID)
				for i := 0; i < 3; i++ {
					res := <-pings
					if res.Error == nil {
						logger.Displayf("[Latency] Ping %d: %v\n", i+1, res.RTT)
					}
				}
			} else {
				logger.Displayf("[Error] Failed to resolve target '%s': %v\n", parts[1], err)
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-create ") {
		parts := strings.SplitN(msgStr, " ", 4)
		if len(parts) >= 3 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}
			gtype := strings.ToUpper(parts[2])
			if gtype != "SECURE" && gtype != "UNSECURE" {
				logger.Displayf("[Error] Invalid group type: %s. Must be SECURE or UNSECURE.\n", parts[2])
				return
			}

			var members []string
			if len(parts) == 4 {
				memberListRaw := strings.Split(parts[3], ",")
				for _, m := range memberListRaw {
					m = strings.TrimSpace(m)
					if m == "" {
						continue
					}
					if strings.HasPrefix(m, "@") {
						resolved, err := ResolveAlias(ctx, h, m)
						if err == nil {
							m = resolved
						} else {
							logger.Displayf("[Error] Failed to resolve member alias %s: %v\n", m, err)
							return
						}
					}
					members = append(members, m)
				}
			}

			// Generate Group ID
			groupID := fmt.Sprintf("group_%x", sha256.Sum256([]byte(h.ID().String()+fmt.Sprintf("%d", time.Now().UnixNano()))))[:32]

			// Sign Metadata
			privKey := h.Peerstore().PrivKey(h.ID())
			createdAt := time.Now().Unix()
			dataToSign := []byte(groupID + alias + h.ID().String() + fmt.Sprintf("%d", createdAt))
			sigBytes, err := privKey.Sign(dataToSign)
			if err != nil {
				logger.Displayf("[Error] Failed to sign metadata: %v\n", err)
				return
			}
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			// Register Group Alias to DHT
			errReg := RegisterAlias(ctx, h, alias, h.ID().String())
			if errReg != nil {
				logger.Displayf("[Error] Failed to register group alias %s: %v\n", alias, errReg)
				return
			}

			// Join Group locally
			errJoin := JoinGroupProper(ctx, h, privKey, groupID, alias, h.ID().String(), gtype, sigB64, createdAt, members)
			if errJoin == nil {
				// Send Invitations to members (GINVITE)
				localKey, _ := corestore.GetGroupLocalKey(groupID)
				invitePayload := struct {
					Meta    corestore.GroupMetadata `json:"meta"`
					Members []string                `json:"members"`
					GKey    string                  `json:"gkey"`
				}{
					Meta: corestore.GroupMetadata{
						GroupID:    groupID,
						GroupAlias: alias,
						CreatorID:  h.ID().String(),
						GroupType:  gtype,
						CreatedAt:  createdAt,
						Signature:  sigB64,
					},
					Members: members,
					GKey:    base64.StdEncoding.EncodeToString(localKey),
				}
				inviteBytes, _ := json.Marshal(invitePayload)
				inviteMsg := "GINVITE:" + string(inviteBytes)

				for _, m := range members {
					if m != h.ID().String() {
						targetID, errDec := peer.Decode(m)
						if errDec == nil {
							go func(t peer.ID) {
								_, _ = SendMessage(ctx, h, privKey, t, inviteMsg)
							}(targetID)
						}
					}
				}
			} else {
				logger.Displayf("[Error] Failed to join group: %v\n", errJoin)
			}
		} else {
			logger.Displayf("[Error] Use: /group-create <alias> <secure/unsecure> [member1,member2,...]\n")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-join ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			// Resolve group metadata from the network
			meta, err := ResolveGroupMetadata(ctx, h, alias)
			if err != nil {
				logger.Displayf("[Error] Failed to resolve group metadata for %s: %v\n", alias, err)
				return
			}

			if meta.GroupType == "SECURE" {
				logger.Displayf("[Error] This group is SECURE (Closed). You must be invited by the Creator (%s).\n", FormatSender(meta.CreatorID))
				return
			}

			privKey := h.Peerstore().PrivKey(h.ID())

			// Join locally
			errJoin := JoinGroupProper(ctx, h, privKey, meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.Signature, meta.CreatedAt, []string{})
			if errJoin == nil {
				// Broadcast GCMD:JOIN to the group so online members share GKEYs with us
				payload := fmt.Sprintf("GCMD:JOIN:%s", h.ID().String())
				dataToSign := []byte(payload + h.ID().String())
				sigBytes, _ := privKey.Sign(dataToSign)
				sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

				gMsg := GroupMessage{
					SenderID:  h.ID().String(),
					Payload:   payload,
					Signature: sigB64,
				}
				msgBytes, _ := json.Marshal(gMsg)

				session, exists := activeGroups[meta.GroupID]
				if exists {
					_ = session.Topic.Publish(ctx, msgBytes)
				}
			} else {
				logger.Displayf("[Error] Failed to join group: %v\n", errJoin)
			}
		} else {
			logger.Displayf("[Error] Use: /group-join <group_alias>\n")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-add ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			alias := parts[1]
			member := parts[2]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			if meta.CreatorID != h.ID().String() {
				logger.Displayf("[Error] Only the Creator can add members.\n")
				return
			}
			if meta.GroupType != "SECURE" {
				logger.Displayf("[Error] This group is public/open. Members join themselves using /group-join.\n")
				return
			}

			if strings.HasPrefix(member, "@") {
				resolved, err := ResolveAlias(ctx, h, member)
				if err == nil {
					member = resolved
				} else {
					logger.Displayf("[Error] Failed to resolve member alias %s: %v\n", member, err)
					return
				}
			}

			// Save member locally
			_ = corestore.AddGroupMemberV2(meta.GroupID, member, "MEMBER")

			// Send GINVITE to new member
			privKey := h.Peerstore().PrivKey(h.ID())
			localKey, _ := corestore.GetGroupLocalKey(meta.GroupID)
			existingMembers, _ := corestore.GetGroupMembersV2(meta.GroupID)
			var memberIDs []string
			for _, m := range existingMembers {
				memberIDs = append(memberIDs, m.PeerID)
			}
			// Ensure the new member is also included
			memberIDs = append(memberIDs, member)

			invitePayload := struct {
				Meta    corestore.GroupMetadata `json:"meta"`
				Members []string                `json:"members"`
				GKey    string                  `json:"gkey"`
			}{
				Meta:    meta,
				Members: memberIDs,
				GKey:    base64.StdEncoding.EncodeToString(localKey),
			}
			inviteBytes, _ := json.Marshal(invitePayload)
			inviteMsg := "GINVITE:" + string(inviteBytes)

			targetID, errDec := peer.Decode(member)
			if errDec == nil {
				go func(t peer.ID) {
					_, _ = SendMessage(ctx, h, privKey, t, inviteMsg)
				}(targetID)
			}

			// Broadcast GCMD:ADD to existing members
			payload := fmt.Sprintf("GCMD:ADD:%s", member)
			dataToSign := []byte(payload + h.ID().String())
			sigBytes, _ := privKey.Sign(dataToSign)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			gMsg := GroupMessage{
				SenderID:  h.ID().String(),
				Payload:   payload,
				Signature: sigB64,
			}
			msgBytes, _ := json.Marshal(gMsg)

			session, exists := activeGroups[meta.GroupID]
			if exists {
				_ = session.Topic.Publish(ctx, msgBytes)
			}
			logger.Displayf("[Group] Added member %s successfully.\n", parts[2])
		} else {
			logger.Displayf("[Error] Use: /group-add <group_alias> <member>\n")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-remove ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			alias := parts[1]
			member := parts[2]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			if meta.CreatorID != h.ID().String() {
				logger.Displayf("[Error] Only the Creator can remove members.\n")
				return
			}

			if strings.HasPrefix(member, "@") {
				resolved, err := ResolveAlias(ctx, h, member)
				if err == nil {
					member = resolved
				} else {
					logger.Displayf("[Error] Failed to resolve member alias %s: %v\n", member, err)
					return
				}
			}

			// Broadcast GCMD:REMOVE
			payload := fmt.Sprintf("GCMD:REMOVE:%s", member)
			privKey := h.Peerstore().PrivKey(h.ID())
			dataToSign := []byte(payload + h.ID().String())
			sigBytes, _ := privKey.Sign(dataToSign)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			gMsg := GroupMessage{
				SenderID:  h.ID().String(),
				Payload:   payload,
				Signature: sigB64,
			}
			msgBytes, _ := json.Marshal(gMsg)

			session, exists := activeGroups[meta.GroupID]
			if exists {
				_ = session.Topic.Publish(ctx, msgBytes)
			}

			// Process locally
			ProcessGroupControlMessage(ctx, h, meta.GroupID, gMsg)
		} else {
			logger.Displayf("[Error] Use: /group-remove <group_alias> <member>\n")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-exit ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			if meta.CreatorID == h.ID().String() {
				logger.Displayf("[Warning] You are the Creator. Use /group-disband to dissolve the group.\n")
				return
			}

			// Broadcast GCMD:EXIT
			payload := fmt.Sprintf("GCMD:EXIT:%s", h.ID().String())
			privKey := h.Peerstore().PrivKey(h.ID())
			dataToSign := []byte(payload + h.ID().String())
			sigBytes, _ := privKey.Sign(dataToSign)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			gMsg := GroupMessage{
				SenderID:  h.ID().String(),
				Payload:   payload,
				Signature: sigB64,
			}
			msgBytes, _ := json.Marshal(gMsg)

			session, exists := activeGroups[meta.GroupID]
			if exists {
				_ = session.Topic.Publish(ctx, msgBytes)

				// Exit locally
				session.Sub.Cancel()
				session.Topic.Close()
				groupsMutex.Lock()
				delete(activeGroups, meta.GroupID)
				groupsMutex.Unlock()
			}
			_ = corestore.DeleteGroupMetadata(meta.GroupID)
			logger.Displayf("[Group] You left group %s successfully.\n", meta.GroupAlias)
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-disband ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			if meta.CreatorID != h.ID().String() {
				logger.Displayf("[Error] Only the Creator can disband the group.\n")
				return
			}

			// Broadcast GCMD:DISBAND
			payload := "GCMD:DISBAND:"
			privKey := h.Peerstore().PrivKey(h.ID())
			dataToSign := []byte(payload + h.ID().String())
			sigBytes, _ := privKey.Sign(dataToSign)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			gMsg := GroupMessage{
				SenderID:  h.ID().String(),
				Payload:   payload,
				Signature: sigB64,
			}
			msgBytes, _ := json.Marshal(gMsg)

			session, exists := activeGroups[meta.GroupID]
			if exists {
				_ = session.Topic.Publish(ctx, msgBytes)
			}

			// Disband locally
			ProcessGroupControlMessage(ctx, h, meta.GroupID, gMsg)
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-info ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			members, _ := corestore.GetGroupMembersV2(meta.GroupID)
			logger.Displayln("=========================================")
			logger.Displayf("  Group Info: %s\n", meta.GroupAlias)
			logger.Displayf("  ID:         %s\n", meta.GroupID)
			logger.Displayf("  Type:       %s\n", meta.GroupType)
			logger.Displayf("  Creator:    %s\n", FormatSender(meta.CreatorID))
			logger.Displayf("  Created At: %s\n", time.Unix(meta.CreatedAt, 0).Format("02/01/2006 15:04:05"))
			logger.Displayln("  Members List:")
			for _, m := range members {
				status := "Offline"
				memberID, errDec := peer.Decode(m.PeerID)
				if errDec == nil && h.Network().Connectedness(memberID) == network.Connected {
					status = "Online"
				}
				logger.Displayf("    - %s (%s) [%s]\n", FormatSender(m.PeerID), m.Role, status)
			}
			logger.Displayln("=========================================")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			targetStr := parts[1]
			if !strings.HasPrefix(targetStr, "@") {
				targetStr = "@" + targetStr
			}

			meta, err := corestore.LoadGroupMetadata(targetStr)
			if err == nil {
				targetStr = meta.GroupID
			}
			errSend := SendGroupMessage(ctx, h, targetStr, parts[2])
			if errSend != nil {
				logger.Displayf("[Error] Failed to send message to group: %v\n", errSend)
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/reset-session ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			targetID, err := resolveTargetPeerID(ctx, h, parts[1])
			if err == nil {
				errReset := SendSessionReset(ctx, h, targetID)
				if errReset == nil {
					logger.Displayf("[Success] E2EE Session with %s has been reset.\n", parts[1])
				} else {
					logger.Displayf("[Error] Failed to send reset signal to %s: %v\n", parts[1], errReset)
				}
			} else {
				logger.Displayf("[Error] Failed to resolve target '%s': %v\n", parts[1], err)
			}
		} else {
			logger.Displayf("[Error] Use: /reset-session <peerID_or_alias>\n")
		}
		return
	}

	if msgStr == "/fetch" {
		for _, p := range h.Network().Peers() {
			protos, _ := h.Peerstore().GetProtocols(p)
			isRelay := false
			for _, proto := range protos {
				if string(proto) == InfrastructureProtocolID {
					isRelay = true
					break
				}
			}
			if isRelay {
				logger.Info().Str("peerID", p.String()).Msg("Triggering manual mailbox fetch")
				FetchMailboxMessages(ctx, h, p, priv)
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/register ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}
			err := RegisterAlias(ctx, h, alias, h.ID().String())
			if err != nil {
				logger.Error().Err(err).Str("alias", alias).Msg("COMMAND: Failed to register alias")
				logger.Displayf("[Error] Failed to register alias %s: %v\n", alias, err)
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/send ") || strings.HasPrefix(msgStr, "/msg ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			targetID, err := resolveTargetPeerID(ctx, h, parts[1])
			if err == nil {
				logger.Debug().Str("peerID", targetID.String()).Msg("COMMAND: Calling SendMessage")
				_, errSend := SendMessage(ctx, h, priv, targetID, parts[2])
				if errSend == nil {
					TrackMsgSent()
					logger.Info().Str("peerID", targetID.String()).Msg("Message sent successfully")
				} else {
					logger.Error().Err(errSend).Str("peerID", targetID.String()).Msg("Failed to send message")
					logger.Displayf("[Error] Failed to send message to %s: %v\n", FormatPeerID(targetID.String()), errSend)
				}
			} else {
				logger.Error().Err(err).Str("target", parts[1]).Msg("COMMAND: Invalid Peer ID or unresolvable alias")
				logger.Displayf("[Error] Invalid Peer ID or unresolvable alias '%s': %v\n", parts[1], err)
			}
		} else {
			logger.Warn().Str("command", msgStr).Msg("COMMAND: Invalid /msg format. Use: /msg @alias message")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/upload ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			filePath := parts[1]
			targetID, err := resolveTargetPeerID(ctx, h, parts[2])
			if err == nil {
				fileData, err := os.ReadFile(filePath)
				if err == nil {
					fileName := filepath.Base(filePath)
					fileMsg := fmt.Sprintf("FILE:%s:%d:%s", fileName, len(fileData), base64.StdEncoding.EncodeToString(fileData))
					_, errSend := SendMessage(ctx, h, priv, targetID, fileMsg)
					if errSend == nil {
						TrackMsgSent()
						logger.Displayf("[Success] Encrypted file %s sent to %s\n", fileName, FormatPeerID(targetID.String()))
					} else {
						logger.Error().Err(errSend).Str("peerID", targetID.String()).Msg("Failed to send file")
						logger.Displayf("[Error] Failed to send file %s to %s: %v\n", fileName, FormatPeerID(targetID.String()), errSend)
					}
				} else {
					logger.Displayf("[Error] Failed to read file %s: %v\n", filePath, err)
				}
			} else {
				logger.Displayf("[Error] Failed to resolve target '%s': %v\n", parts[2], err)
			}
		}
		return
	}

	// DESIGN-05 FIX: Input tidak dikenal sebagai command → tampilkan error, jangan broadcast ke semua peer.
	// Perilaku broadcast lama sangat berbahaya (typo command = kirim ke semua orang).
	logger.Displayf("[Error] Unknown command: '%s'\n", msgStr)
	logger.Displayf("Available commands: /msg, /group, /join, /fetch, /register, /upload, /latency, /reset-session\n")
}
