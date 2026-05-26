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
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	"github.com/nicabreon/meshsage/pkg/logger"
)

const MessagingProtocolID = "/p2p-core/msg/1.0.0"

// sessionLocks menyimpan mutex per-peer untuk mencegah race condition
// saat concurrent goroutine mengakses Double Ratchet session state.
var (
	localHost    host.Host
	sessionLocks sync.Map // map[peerID string]*sync.Mutex
)

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
		return
	}

	envelopeBytes := make([]byte, length)
	if _, err := io.ReadFull(buf, envelopeBytes); err != nil {
		return
	}

	ProcessSecureEnvelope(context.Background(), localHost, senderID, string(envelopeBytes))

	// Kirim balik "OK\n" sebagai tanda terima (ACK)
	_, _ = s.Write([]byte("OK\n"))
}

// ProcessSecureEnvelope menangani dekripsi X3DH dan pemrosesan JSON payload
func ProcessSecureEnvelope(ctx context.Context, h host.Host, senderID peer.ID, envelope string) {
	var aesKey []byte
	var encryptedPayloadB64 string

	if strings.HasPrefix(envelope, "DR:") {
		// 1. Jalur Double Ratchet (Per-message Keys)
		parts := strings.SplitN(envelope, ":", 2)
		if len(parts) < 2 { return }
		
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
			skippedKey, err := corestore.GetSkippedKey(senderID.String(), uint32(counter))
			if err == nil {
				logger.Info().Str("peerID", senderID.String()).Uint32("counter", uint32(counter)).Msg("DR: Using skipped message key")
				// BUG-02 FIX: Gunakan DecryptMessage (bukan DecryptMessageRaw) karena
				// EncryptWithRatchet menggunakan EncryptMessage yang menyertakan gzip.
				plaintext, err := corecrypto.DecryptMessage(skippedKey, headerParts[3])
				if err != nil {
					logger.Error().Str("peerID", senderID.String()).Err(err).Msg("DR: Skipped key decryption failed")
					return
				}
				processDecryptedPayload(ctx, h, senderID, []byte(plaintext))
				return
			} else {
				// B. Jalur Standard Ratchet
				remoteIdentityB64, rootB64, sendB64, recvB64, remoteRatchetB64, localRatchetPrivB64, localRatchetPubB64, n, m, pn, err := corestore.LoadSession(senderID.String())
				if err != nil || rootB64 == "" {
					logger.Error().Str("peerID", senderID.String()).Msg("No session found for E2EE decryption")
					return
				}

				rootKey, _ := base64.StdEncoding.DecodeString(rootB64)
				sendChain, _ := base64.StdEncoding.DecodeString(sendB64)
				recvChain, _ := base64.StdEncoding.DecodeString(recvB64)
				remoteRatchetPub, _ := base64.StdEncoding.DecodeString(remoteRatchetB64)
				localRatchetPriv, _ := base64.StdEncoding.DecodeString(localRatchetPrivB64)
				localRatchetPub, _ := base64.StdEncoding.DecodeString(localRatchetPubB64)

				if len(recvChain) == 0 { recvChain = rootKey }

				session := &corecrypto.SessionState{
					PeerID: senderID.String(),
					RootKey: rootKey,
					SendChainKey: sendChain,
					RecvChainKey: recvChain,
					RemoteRatchetPubkey: remoteRatchetPub,
					LocalRatchetPrivkey: localRatchetPriv,
					LocalRatchetPubkey: localRatchetPub,
					N: n,
					M: m,
					PN: pn,
				}

				plaintext, skipped, err := session.DecryptWithRatchet(payloadStr)
				if err != nil {
					logger.Error().Str("peerID", senderID.String()).Err(err).Msg("DR Decryption failed")
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
				
				processDecryptedPayload(ctx, h, senderID, []byte(plaintext))
				return
			}
		}

	} else if strings.HasPrefix(envelope, "X3DH:") {
		// 2. Jalur Handshake X3DH (Lengkap)
		logger.Info().Str("peerID", senderID.String()).Msg("Receiving new X3DH Handshake")
		// Format baru: X3DH:keyID:ePub:senderRatchetPub:encryptedPayload
		parts := strings.SplitN(envelope, ":", 5)
		if len(parts) < 4 { return }
		
		keyID := parts[1]
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
			logger.Error().Str("keyID", keyID).Msg("Receiver's Pre-Key not found (Already used or expired)")
			return
		}
		privKeyBytes, _ := base64.StdEncoding.DecodeString(privKeyB64)
		ePubBytes, _ := base64.StdEncoding.DecodeString(ePubB64)

		logger.Debug().Msg("Deriving shared secret from receiver's Pre-Key...")
		aesKey, err = corecrypto.DeriveSharedSecret(privKeyBytes, ePubBytes)
		if err != nil { return }

		// Inisialisasi ratchet keys di sisi receiver
		bobPreKeyPub, err := corecrypto.DerivePublicKey(privKeyBytes)
		if err != nil { return }
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
		localRatchetPubB64  := base64.StdEncoding.EncodeToString(localRatchetPub)

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
		return
	}

	// 3. Dekripsi Payload
	encryptedPayload, _ := base64.StdEncoding.DecodeString(encryptedPayloadB64)
	plaintextBytes, err := corecrypto.DecryptMessageRaw(aesKey, encryptedPayload)
	if err != nil {
		logger.Error().Str("peerID", senderID.String()).Msg("E2EE Decryption failed")
		return
	}

	processDecryptedPayload(ctx, h, senderID, plaintextBytes)
}

func processDecryptedPayload(ctx context.Context, h host.Host, senderID peer.ID, plaintextBytes []byte) {
	// 4. Unmarshal JSON
	var env MessageEnvelope
	if err := json.Unmarshal(plaintextBytes, &env); err != nil {
		return
	}

	// 5. Verifikasi Signature
	if env.Signature != "" {
		pubKey, err := senderID.ExtractPublicKey()
		if err == nil {
			dataToVerify := []byte(env.Content + env.ID)
			sigBytes, _ := base64.StdEncoding.DecodeString(env.Signature)
			valid, _ := pubKey.Verify(dataToVerify, sigBytes)
			if !valid {
				logger.Warn().Str("peerID", senderID.String()).Msg("INVALID SIGNATURE detected!")
				return
			}
			logger.Debug().Str("peerID", senderID.String()).Msg("Message signature verified")
		}
	}

	// 6. Handle Content
	handleIncomingPayload(ctx, h, senderID, env)
}

func handleIncomingPayload(ctx context.Context, h host.Host, senderID peer.ID, env MessageEnvelope) {
	// Persist to SQLite
	corestore.SaveMessage(senderID.String(), h.ID().String(), env.Content)

	switch env.Type {
	case MsgTypeStatus:
		logger.Displayf("[Status Report] Peer %s marked your message %s as: %s\n", 
			FormatPeerID(senderID.String()), env.RefID, env.Status)
		return

	case MsgTypeText:
		// Check for Group Key sharing (GKEY:groupID:base64Key)
		if strings.HasPrefix(env.Content, "GKEY:") {
			parts := strings.SplitN(env.Content, ":", 3)
			if len(parts) == 3 {
				groupID := parts[1]
				keyBytes, _ := base64.StdEncoding.DecodeString(parts[2])
				corestore.SaveGroupSenderKey(groupID, senderID.String(), keyBytes)
				logger.Info().
					Str("group", groupID).
					Str("peerID", senderID.String()).
					Msg("Received and saved Group Session Key (via Double Ratchet)")
				// Flush any buffered messages that were waiting for this key
				go FlushPendingGroupMessages(groupID, senderID.String())
				return
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
				return
			}
			
			// Verify Creator Signature
			creatorID, errDec := peer.Decode(invite.Meta.CreatorID)
			if errDec != nil {
				logger.Error().Err(errDec).Str("creator", invite.Meta.CreatorID).Msg("Failed to decode creator peer ID")
				return
			}
			pubKey := h.Peerstore().PubKey(creatorID)
			var errExtract error
			if pubKey == nil {
				pubKey, errExtract = creatorID.ExtractPublicKey()
				if errExtract != nil {
					logger.Error().Err(errExtract).Str("creator", invite.Meta.CreatorID).Msg("Failed to extract creator public key")
					return
				}
			}
			
			dataToVerify := []byte(invite.Meta.GroupID + invite.Meta.GroupAlias + invite.Meta.CreatorID + fmt.Sprintf("%d", invite.Meta.CreatedAt))
			sigBytes, _ := base64.StdEncoding.DecodeString(invite.Meta.Signature)
			valid, errVerify := pubKey.Verify(dataToVerify, sigBytes)
			if errVerify != nil {
				logger.Error().Err(errVerify).Msg("Error verifying GINVITE signature")
				return
			}
			if !valid {
				logger.Error().Str("group", invite.Meta.GroupAlias).Msg("Received GINVITE with INVALID signature!")
				return
			}
			
			errJoin := JoinGroupProper(ctx, h, h.Peerstore().PrivKey(h.ID()),
				invite.Meta.GroupID, invite.Meta.GroupAlias, invite.Meta.CreatorID, invite.Meta.GroupType, invite.Meta.Signature, invite.Members)
			if errJoin != nil {
				logger.Error().Err(errJoin).Str("group", invite.Meta.GroupAlias).Msg("Failed to join group in GINVITE handler")
			}
			
			if invite.GKey != "" {
				keyBytes, _ := base64.StdEncoding.DecodeString(invite.GKey)
				_ = corestore.SaveGroupSenderKey(invite.Meta.GroupID, invite.Meta.CreatorID, keyBytes)
				// Flush any buffered messages waiting for the creator's key
				go FlushPendingGroupMessages(invite.Meta.GroupID, invite.Meta.CreatorID)
			}
			return
		}

		// Check for Group Message prefix (Offline Fan-out)
		if strings.HasPrefix(env.Content, "GRPM:") {
			parts := strings.SplitN(env.Content, ":", 3)
			if len(parts) == 3 {
				ProcessGroupMessage(parts[1], []byte(parts[2]))
				return
			}
		}

		ts := time.Now().Format("02/01 15:04:05")
		logger.Displayf("\033[92m[%s] [Message from %s]: %s\033[0m\n", ts, FormatSender(senderID.String()), env.Content)
		if MessageCallback != nil {
			MessageCallback(MessageEvent{
				Type:      "direct",
				Timestamp: ts,
				Sender:    senderID.String(),
				Content:   env.Content,
			})
		}
		// OTOMATIS: Kirim status "delivered" (Centang 2)
		go SendStatusUpdate(ctx, h, senderID, env.ID, StatusDelivered)
		
	case MsgTypeFile:
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
				})
			}
		}
	
	case MsgTypeGroup:
		ProcessGroupMessage(env.RefID, []byte(env.Content))
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

func sendSecureEnvelope(ctx context.Context, h host.Host, priv crypto.PrivKey, targetID peer.ID, env MessageEnvelope) error {
	jsonPayload, _ := json.Marshal(env)

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

		if len(sendChain) == 0 { sendChain = rootKey }

		session := &corecrypto.SessionState{
			PeerID: targetID.String(),
			RemoteIdentityKey: []byte(remoteIdentityB64),
			RootKey: rootKey,
			SendChainKey: sendChain,
			RecvChainKey: recvChain,
			RemoteRatchetPubkey: remoteRatchetPub,
			LocalRatchetPrivkey: localRatchetPriv,
			LocalRatchetPubkey: localRatchetPub,
			N: n,
			M: m,
			PN: pn,
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
			return transmitEnvelope(ctx, h, targetID, finalWireEnvelope)
		}
	}

	// 2. Jika tidak ada sesi, lakukan alur X3DH
	var keyID, pubKeyB64 string
	preKeyFound := false
	logger.Info().Str("target", targetID.String()).Msg("No session found. Initiating X3DH Handshake flow")

	for _, relayPeer := range h.Network().Peers() {
		logger.Debug().Str("target", targetID.String()).Str("relay", relayPeer.String()).Msg("X3DH HANDSHAKE: Fetching Pre-Key")
		id, pub, _, err := FetchPreKey(ctx, h, relayPeer, targetID.String())
		if err == nil && pub != "" {
			keyID = id
			pubKeyB64 = pub
			preKeyFound = true
			logger.Info().Str("target", targetID.String()).Str("relay", relayPeer.String()).Msg("X3DH SUCCESS: Pre-Key found")
			break
		}
	}
	if !preKeyFound { return fmt.Errorf("no pre-key found") }


	logger.Debug().Msg("X3DH HANDSHAKE: Generating Ephemeral Keypair & Deriving Shared Secret")
	ePriv, ePub, err := corecrypto.GenerateEphemeralKeypair()
	if err != nil { return err }

	peerPubKeyBytes, _ := base64.StdEncoding.DecodeString(pubKeyB64)
	aesKey, err := corecrypto.DeriveSharedSecret(ePriv, peerPubKeyBytes)
	if err != nil { return err }

	// Inisialisasi Double Ratchet: Generate ratchet keypair lokal
	localRatchetPriv, localRatchetPub, err := corecrypto.GenerateEphemeralKeypair()
	if err != nil { return err }

	// Lakukan DH Send Step awal menggunakan localRatchetPriv dan pubKeyB64 (Pre-key Bob)
	sharedSecret, err := corecrypto.DeriveSharedSecret(localRatchetPriv, peerPubKeyBytes)
	if err != nil { return err }
	res, err := corecrypto.HKDFExpand(sharedSecret, "p2p-core-dh-ratchet", 64)
	if err != nil { return err }

	initRootKey := res[:32]
	initSendChainKey := res[32:]

	senderRootKeyB64 := base64.StdEncoding.EncodeToString(initRootKey)
	senderSendChainB64 := base64.StdEncoding.EncodeToString(initSendChainKey)
	senderRatchetPrivB64 := base64.StdEncoding.EncodeToString(localRatchetPriv)
	senderRatchetPubB64Out := base64.StdEncoding.EncodeToString(localRatchetPub)

	logger.Info().Str("peerID", FormatPeerID(targetID.String())).Str("rootKey", senderRootKeyB64[:6]).Msg("X3DH HANDSHAKE: Saving Initial Session with Ratchet Keys")
	// BUG-1 FIX: Sender side — clear stale skipped keys before establishing new session.
	if clearErr := corestore.ClearSkippedKeys(targetID.String()); clearErr != nil {
		logger.Warn().Err(clearErr).Str("peerID", targetID.String()).Msg("X3DH SEND: Failed to clear stale skipped keys")
	} else {
		logger.Debug().Str("peerID", targetID.String()).Msg("X3DH SEND: Cleared stale skipped keys for new session")
	}
	// Simpan session dengan SendChainKey terisi, RecvChainKey kosong, dan RemoteRatchetPubkey = pubKeyB64
	corestore.SaveSession(targetID.String(), pubKeyB64, senderRootKeyB64, senderSendChainB64, "", pubKeyB64, senderRatchetPrivB64, senderRatchetPubB64Out, 0, 0, 0)

	// Sertakan localRatchetPub di dalam payload agar receiver bisa init RecvChainKey
	type x3dhPayload struct {
		Data        []byte `json:"d"`
		RatchetPub  string `json:"rp"`
	}
	encryptedBytes, err := corecrypto.EncryptMessageRaw(aesKey, jsonPayload)
	if err != nil { return err }

	ePubB64 := base64.StdEncoding.EncodeToString(ePub)
	// Format: X3DH:keyID:ePub:senderRatchetPub:encryptedPayload
	finalWireEnvelope := fmt.Sprintf("X3DH:%s:%s:%s:%s", keyID, ePubB64, senderRatchetPubB64Out, base64.StdEncoding.EncodeToString(encryptedBytes))
	return transmitEnvelope(ctx, h, targetID, finalWireEnvelope)
}


// deriveNextKeys is deprecated, logic moved to corecrypto.RatchetStep

func SendMessage(ctx context.Context, h host.Host, priv crypto.PrivKey, target peer.ID, msg string) error {
	msg = strings.TrimSuffix(msg, "\n")
	msgID := fmt.Sprintf("%x", sha256.Sum256([]byte(msg+time.Now().String())))[:8]
	dataToSign := []byte(msg + msgID)
	sigBytes, _ := priv.Sign(dataToSign)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	env := MessageEnvelope{
		ID:        msgID,
		Type:      MsgTypeText,
		Content:   msg,
		Timestamp: time.Now().UnixNano(),
		Signature: sigB64,
	}

	return sendSecureEnvelope(ctx, h, priv, target, env)
}

func transmitEnvelope(ctx context.Context, h host.Host, target peer.ID, finalWireEnvelope string) error {
	if target == h.ID() {
		logger.Info().Msg("transmitEnvelope: Self-message detected, processing locally without network dial")
		go ProcessSecureEnvelope(ctx, h, h.ID(), finalWireEnvelope)
		return nil
	}

	// Query the DHT to find the target peer's actual addresses (including relay addresses)
	// if we don't have them cached in peerstore. This is standard libp2p peer routing.
	if len(h.Peerstore().Addrs(target)) == 0 && corenet.GlobalDHT != nil {
		logger.Debug().Str("target", target.String()).Msg("No addresses for target, querying DHT FindPeer...")
		findCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		pinfo, err := corenet.GlobalDHT.FindPeer(findCtx, target)
		cancel()
		if err == nil {
			h.Peerstore().AddAddrs(target, pinfo.Addrs, 5*time.Minute)
			logger.Debug().Str("target", target.String()).Int("addrs", len(pinfo.Addrs)).Msg("Found target addresses via DHT")
		} else {
			logger.Warn().Err(err).Str("target", target.String()).Msg("DHT FindPeer failed")
		}
	}

	logger.Debug().Str("target", target.String()).Msg("transmitEnvelope: Attempting dial to target (direct/relay)")
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, err := h.NewStream(dialCtx, target, MessagingProtocolID)
	if err == nil {
		logger.Debug().Str("target", target.String()).Msg("transmitEnvelope: Direct dial succeeded, writing envelope")
		errWrite := binary.Write(s, binary.LittleEndian, uint32(len(finalWireEnvelope)))
		if errWrite == nil {
			_, errWrite = s.Write([]byte(finalWireEnvelope))
		}
		if errWrite == nil {
			// Read ACK
			respReader := bufio.NewReader(s)
			s.SetReadDeadline(time.Now().Add(1 * time.Second))
			resp, errRead := respReader.ReadString('\n')
			if errRead != nil || strings.TrimSpace(resp) != "OK" {
				errWrite = fmt.Errorf("did not receive ACK from target: %v", errRead)
			}
		}
		s.Close()
		if errWrite == nil {
			return nil
		}
		logger.Warn().Err(errWrite).Str("target", target.String()).Msg("transmitEnvelope: Direct write failed, falling back to mailbox")
		err = errWrite
	} else {
		logger.Warn().Err(err).Str("target", target.String()).Msg("transmitEnvelope: Dial failed, falling back to mailbox storage")
	}
	encodedEnvelope := base64.StdEncoding.EncodeToString([]byte(finalWireEnvelope))
	return StoreOfflineMessage(ctx, h, target, h.ID().String(), encodedEnvelope)
}

func StartChatPrompt(ctx context.Context, h host.Host, priv crypto.PrivKey) {
	// Goroutine 1: Manual Stdin
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			msg, err := reader.ReadString('\n')
			if err != nil { return }
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

func ProcessCommand(ctx context.Context, h host.Host, priv crypto.PrivKey, msgStr string) {
	msgStr = strings.TrimSpace(msgStr)
	if msgStr == "" { return }

	if strings.HasPrefix(msgStr, "/latency ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			targetStr := parts[1]
			if strings.HasPrefix(targetStr, "@") {
				resolved, err := ResolveAlias(ctx, h, targetStr)
				if err == nil { targetStr = resolved }
			}
			targetID, err := peer.Decode(targetStr)
			if err == nil {
				pings := ping.Ping(ctx, h, targetID)
				for i := 0; i < 3; i++ {
					res := <-pings
					if res.Error == nil { logger.Displayf("[Latency] Ping %d: %v\n", i+1, res.RTT) }
				}
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-create ") {
		parts := strings.SplitN(msgStr, " ", 4)
		if len(parts) >= 3 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") { alias = "@" + alias }
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
					if m == "" { continue }
					if strings.HasPrefix(m, "@") {
						resolved, err := ResolveAlias(ctx, h, m)
						if err == nil { m = resolved } else {
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
			errJoin := JoinGroupProper(ctx, h, privKey, groupID, alias, h.ID().String(), gtype, sigB64, members)
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
								_ = SendMessage(ctx, h, privKey, t, inviteMsg)
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
			if !strings.HasPrefix(alias, "@") { alias = "@" + alias }
			
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
			errJoin := JoinGroupProper(ctx, h, privKey, meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.Signature, []string{})
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
			if !strings.HasPrefix(alias, "@") { alias = "@" + alias }

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
				if err == nil { member = resolved } else {
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
					_ = SendMessage(ctx, h, privKey, t, inviteMsg)
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
			if !strings.HasPrefix(alias, "@") { alias = "@" + alias }

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
				if err == nil { member = resolved } else {
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
			if !strings.HasPrefix(alias, "@") { alias = "@" + alias }

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
			if !strings.HasPrefix(alias, "@") { alias = "@" + alias }

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
			if !strings.HasPrefix(alias, "@") { alias = "@" + alias }

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
			if !strings.HasPrefix(targetStr, "@") { targetStr = "@" + targetStr }

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

	if msgStr == "/fetch" {
		for _, p := range h.Network().Peers() {
			protos, _ := h.Peerstore().GetProtocols(p)
			isRelay := false
			for _, proto := range protos {
				if string(proto) == "/p2p-core/mailbox/1.0.0" {
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
			if !strings.HasPrefix(alias, "@") { alias = "@" + alias }
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
			targetStr := parts[1]
			if strings.HasPrefix(targetStr, "@") {
				logger.Debug().Str("alias", targetStr).Msg("COMMAND: Resolving alias")
				resolved, err := ResolveAlias(ctx, h, targetStr)
				if err == nil { 
					targetStr = resolved 
					logger.Debug().Str("alias", parts[1]).Str("peerID", targetStr).Msg("COMMAND: Alias resolved successfully")
				} else {
					logger.Error().Err(err).Str("alias", parts[1]).Msg("COMMAND: Failed to resolve alias")
					logger.Displayf("[Error] Failed to resolve alias %s: %v\n", targetStr, err)
					return
				}
			}
			targetID, err := peer.Decode(targetStr)
			if err == nil {
				logger.Debug().Str("peerID", targetID.String()).Msg("COMMAND: Calling SendMessage")
				errSend := SendMessage(ctx, h, priv, targetID, parts[2])
				if errSend == nil {
					logger.Info().Str("peerID", targetID.String()).Msg("Message sent successfully")
				} else {
					logger.Error().Err(errSend).Str("peerID", targetID.String()).Msg("Failed to send message")
					logger.Displayf("[Error] Failed to send message to %s: %v\n", FormatPeerID(targetID.String()), errSend)
				}
			} else {
				logger.Error().Err(err).Str("target", targetStr).Msg("COMMAND: Invalid Peer ID or unresolvable alias")
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
			targetStr := parts[2]
			if strings.HasPrefix(targetStr, "@") {
				resolved, err := ResolveAlias(ctx, h, targetStr)
				if err == nil { 
					targetStr = resolved 
				} else {
					logger.Error().Err(err).Str("alias", targetStr).Msg("COMMAND: Failed to resolve alias for upload")
					logger.Displayf("[Error] Failed to resolve alias %s: %v\n", targetStr, err)
					return
				}
			}
			targetID, err := peer.Decode(targetStr)
			if err == nil {
				fileData, err := os.ReadFile(filePath)
				if err == nil {
					fileName := filepath.Base(filePath)
					fileMsg := fmt.Sprintf("FILE:%s:%d:%s", fileName, len(fileData), base64.StdEncoding.EncodeToString(fileData))
					errSend := SendMessage(ctx, h, priv, targetID, fileMsg)
					if errSend == nil {
						logger.Displayf("[Success] Encrypted file %s sent to %s\n", fileName, FormatPeerID(targetID.String()))
					} else {
						logger.Error().Err(errSend).Str("peerID", targetID.String()).Msg("Failed to send file")
						logger.Displayf("[Error] Failed to send file %s to %s: %v\n", fileName, FormatPeerID(targetID.String()), errSend)
					}
				}
			}
		}
		return
	}

	// DESIGN-05 FIX: Input tidak dikenal sebagai command → tampilkan error, jangan broadcast ke semua peer.
	// Perilaku broadcast lama sangat berbahaya (typo command = kirim ke semua orang).
	logger.Displayf("[Error] Unknown command: '%s'\n", msgStr)
	logger.Displayf("Available commands: /msg, /group, /join, /fetch, /register, /upload, /latency\n")
}
