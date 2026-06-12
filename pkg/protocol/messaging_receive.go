package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	"github.com/nicabreon/meshsage/pkg/logger"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

// ProcessSecureEnvelope menangani dekripsi X3DH dan pemrosesan JSON payload
func ProcessSecureEnvelope(ctx context.Context, h host.Host, senderID peer.ID, envelope string, msgHash string) {
	// Update last active status of the peer
	connType := "relay"
	relayVia := ""
	if h != nil {
		conns := h.Network().ConnsToPeer(senderID)
		if len(conns) > 0 {
			addrStr := conns[0].RemoteMultiaddr().String()
			if strings.Contains(addrStr, "webrtc-direct") {
				connType = "direct_webrtc"
			} else if strings.Contains(addrStr, "p2p-circuit") {
				connType = "relay"
				parts := strings.Split(addrStr, "/")
				for i, part := range parts {
					if part == "p2p-circuit" && i >= 2 {
						for j := i - 1; j >= 0; j-- {
							if parts[j] == "p2p" && j+1 < i {
								relayVia = parts[j+1]
								break
							}
						}
						break
					}
				}
			} else {
				connType = "direct_quic"
			}
		}
	}
	UpdatePeerActivity(senderID.String(), connType, relayVia)

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
			remoteRatchetPub, _ := base64.StdEncoding.DecodeString(headerParts[0])
			skippedKey, skippedErr := corestore.GetSkippedKey(senderID.String(), remoteRatchetPub, uint32(counter))
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
			remoteIdentityB64, rootB64, sendB64, recvB64, remoteRatchetB64, localRatchetPrivB64, localRatchetPubB64, n, m, pn, outboundMsgsSinceRatchet, err := corestore.LoadSession(senderID.String())
			if err != nil || rootB64 == "" {
				logger.Error().Str("peerID", senderID.String()).Msg("No session found for E2EE decryption. Sending REQUEST_X3DH to sender.")
				// Do NOT send RESET here (we have nothing to reset).
				// Instead, ask the sender to start fresh X3DH.
				go sendRequestX3DH(ctx, h, senderID)
				pushDecryptionErrorToUI(h, senderID, "No E2EE session found for decryption (requires X3DH handshake)")
				return
			}

			rootKey, _ := base64.StdEncoding.DecodeString(rootB64)
			sendChain, _ := base64.StdEncoding.DecodeString(sendB64)
			recvChain, _ := base64.StdEncoding.DecodeString(recvB64)
			remoteRatchetPub = nil
			remoteRatchetPub, _ = base64.StdEncoding.DecodeString(remoteRatchetB64)
			localRatchetPriv, _ := base64.StdEncoding.DecodeString(localRatchetPrivB64)
			localRatchetPub, _ := base64.StdEncoding.DecodeString(localRatchetPubB64)

			if len(recvChain) == 0 {
				recvChain = rootKey
			}

			session := &corecrypto.SessionState{
				PeerID:                       senderID.String(),
				RootKey:                      rootKey,
				SendChainKey:                 sendChain,
				RecvChainKey:                 recvChain,
				RemoteRatchetPubkey:          remoteRatchetPub,
				LocalRatchetPrivkey:          localRatchetPriv,
				LocalRatchetPubkey:           localRatchetPub,
				N:                            n,
				M:                            m,
				PN:                           pn,
				OutboundMessagesSinceRatchet: outboundMsgsSinceRatchet,
			}

			plaintext, skipped, err := session.DecryptWithRatchet(payloadStr)
			if err != nil {
				logger.Error().Str("peerID", senderID.String()).Err(err).Msg("DR Decryption failed. Clearing session and requesting fresh X3DH.")
				_ = corestore.DeleteSession(senderID.String())
				_ = corestore.ClearSkippedKeys(senderID.String())
				go sendRequestX3DH(ctx, h, senderID)
				pushDecryptionErrorToUI(h, senderID, "Double Ratchet decryption failed: "+err.Error())
				return
			}

			// Berhasil dekripsi! Simpan state baru
			// We no longer clear skipped keys on DH ratchet step because skipped keys are now
			// correctly isolated by ratchet epoch (ratchet_pub) in the database.
			// Old epoch keys are kept so out-of-order messages from the old epoch can still be decrypted.
			corestore.SaveSession(senderID.String(), remoteIdentityB64,
				base64.StdEncoding.EncodeToString(session.RootKey),
				base64.StdEncoding.EncodeToString(session.SendChainKey),
				base64.StdEncoding.EncodeToString(session.RecvChainKey),
				base64.StdEncoding.EncodeToString(session.RemoteRatchetPubkey),
				base64.StdEncoding.EncodeToString(session.LocalRatchetPrivkey),
				base64.StdEncoding.EncodeToString(session.LocalRatchetPubkey),
				session.N, session.M, session.PN, session.OutboundMessagesSinceRatchet)

			// Simpan skipped keys
			for _, sk := range skipped {
				corestore.SaveSkippedKey(senderID.String(), sk.RatchetPub, sk.Counter, sk.MsgKey)
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
			pushDecryptionErrorToUI(h, senderID, "Receiver's pre-key not found in local DB (expired or rotated)")
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
		corestore.SaveSession(senderID.String(), bobPreKeyPubB64, rootKeyB64, sendChainB64, recvChainB64, senderRatchetPubB64, localRatchetPrivB64, localRatchetPubB64, 0, 0, 0, 0)
	} else {
		snippet := envelope
		if len(snippet) > 50 {
			snippet = snippet[:50] + "..."
		}
		logger.Warn().Str("senderID", senderID.String()).Str("envelope", snippet).Msg("ProcessSecureEnvelope: unknown or unhandled envelope type")
		pushDecryptionErrorToUI(h, senderID, "Unknown envelope prefix (envelope: "+snippet+")")
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
		pushDecryptionErrorToUI(h, senderID, "X3DH decryption failed: "+err.Error())
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
		pushDecryptionErrorToUI(h, senderID, "Failed to parse decrypted message JSON: "+err.Error())
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

func pushDecryptionErrorToUI(h host.Host, senderID peer.ID, errStr string) {
	if MessageCallback != nil {
		ts := time.Now().Format("02/01 15:04:05")
		errID := fmt.Sprintf("err-%x", sha256.Sum256([]byte(errStr+time.Now().String())))[:8]
		content := "[Error: Failed to decrypt message: " + errStr + "]"

		// Simpan error ini ke SQLite database lokal agar tersimpan di chat history
		if h != nil {
			_ = corestore.SaveMessage(senderID.String(), h.ID().String(), content, "", "", "direct", "unread")
		}

		MessageCallback(MessageEvent{
			Type:      "direct",
			MsgID:     errID,
			Timestamp: ts,
			Sender:    senderID.String(),
			Content:   content,
			UnixTime:  time.Now().UnixNano() / 1e6,
		})
	} else {
		logger.Info().Msg("Callback is nil for error")
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
	case MsgTypeProfileKeyShare:
		logger.Info().Str("peerID", senderID.String()).Msg("Received E2EE profile key share from peer")
		avatarKey := env.Content
		if avatarKey != "" {
			name, cid, _, path, err := corestore.GetPeerProfile(senderID.String())
			if err != nil {
				name = ""
				cid = ""
				path = ""
			}
			_ = corestore.SavePeerProfile(senderID.String(), name, cid, avatarKey, path)
			if cid != "" {
				TriggerAvatarDownload(senderID.String(), cid, avatarKey)
			}
		}
		// Notify Dart UI of profile update
		if ProfileUpdateCallback != nil {
			ProfileUpdateCallback(senderID.String())
		}
		return true

	case MsgTypeProfileUpdate:
		logger.Info().Str("peerID", senderID.String()).Msg("Received E2EE profile update from peer")
		var payload struct {
			DisplayName string `json:"display_name"`
			AvatarCID   string `json:"avatar_cid"`
			AvatarKey   string `json:"avatar_key"`
		}
		if err := json.Unmarshal([]byte(env.Content), &payload); err == nil {
			_, _, _, path, _ := corestore.GetPeerProfile(senderID.String())
			_ = corestore.SavePeerProfile(senderID.String(), payload.DisplayName, payload.AvatarCID, payload.AvatarKey, path)
			if payload.AvatarCID != "" && payload.AvatarKey != "" {
				TriggerAvatarDownload(senderID.String(), payload.AvatarCID, payload.AvatarKey)
			}
		}
		// Notify Dart UI of profile update
		if ProfileUpdateCallback != nil {
			ProfileUpdateCallback(senderID.String())
		}
		return true

	case MsgTypeHandshakeAck:
		// Silent: X3DH bidirectional handshake completed. No UI display.
		// Receiving this ACK means both sides now have a fully operational
		// Double Ratchet session in both directions.
		logger.Info().Str("peerID", senderID.String()).Msg("X3DH handshake ACK received: bidirectional session established")
		// Automatically send profile key share back to the sender
		go func() {
			time.Sleep(100 * time.Millisecond) // Let it settle
			if err := SendProfileKeyShare(ctx, h, senderID); err != nil {
				logger.Warn().Err(err).Str("targetID", senderID.String()).Msg("Failed to auto-send profile key share on ACK receipt")
			}
		}()
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
		corestore.SaveMessage(senderID.String(), h.ID().String(), env.Content, env.ID, msgHash, "direct", "unread")

		logger.Info().Str("senderID", senderID.String()).Str("msgID", env.ID).Msg("Received standard text message successfully")
		TrackMsgRecv() // Track incoming message

		ts := time.Now().Format("02/01 15:04:05")
		logger.Displayf("\033[92m[%s] [Message from %s]: %s\033[0m\n", ts, FormatSender(senderID.String()), env.Content)

		if MessageCallback != nil {
			MessageCallback(MessageEvent{
				Type:      "direct",
				MsgID:     env.ID,
				Timestamp: ts,
				Sender:    senderID.String(),
				Content:   env.Content,
				UnixTime:  env.Timestamp / 1e6,
			})
			// OTOMATIS: Kirim status "delivered" (Centang 2)
			go SendStatusUpdate(ctx, h, senderID, env.ID, StatusDelivered)
		} else {
			logger.Info().Msg("Callback is nil for message")
		}
		return true

	case MsgTypeFile:
		// Persist to SQLite
		corestore.SaveMessage(senderID.String(), h.ID().String(), env.Content, env.ID, msgHash, "file", "unread")

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
			} else {
				logger.Info().Msg("Callback is nil for file")
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
