package protocol

import (
	"bufio"
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
		fmt.Printf("[HANDSHAKE] Receiving new X3DH Handshake from %s\n", FormatPeerID(senderID.String()))
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
			fmt.Printf("[HANDSHAKE Error] Receiver's Pre-Key %s not found (Already used or expired).\n", keyID)
			return
		}
		privKeyBytes, _ := base64.StdEncoding.DecodeString(privKeyB64)
		ePubBytes, _ := base64.StdEncoding.DecodeString(ePubB64)

		fmt.Printf("[HANDSHAKE] Deriving shared secret from receiver's Pre-Key...\n")
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

		fmt.Printf("[HANDSHAKE] Initial session established. RootKey: %s...\n", rootKeyB64[:6])
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
		fmt.Printf("\n[Status Report] Peer %s marked your message %s as: %s\n> ", 
			FormatPeerID(senderID.String()), env.RefID, env.Status)
		return

	case MsgTypeText:
		// Check for Group Key sharing (GKEY:groupID:base64Key)
		if strings.HasPrefix(env.Content, "GKEY:") {
			parts := strings.SplitN(env.Content, ":", 3)
			if len(parts) == 3 {
				keyBytes, _ := base64.StdEncoding.DecodeString(parts[2])
				corestore.SaveGroupSenderKey(parts[1], senderID.String(), keyBytes)
				logger.Info().
					Str("group", parts[1]).
					Str("peerID", senderID.String()).
					Msg("Received and saved Group Session Key (via Double Ratchet)")
				return
			}
		}

		// Check for Group Message prefix (Offline Fan-out)
		if strings.HasPrefix(env.Content, "GRPM:") {
			parts := strings.SplitN(env.Content, ":", 3)
			if len(parts) == 3 {
				ProcessGroupMessage(parts[1], []byte(parts[2]))
				return
			}
		}

		fmt.Printf("\n[Message from %s]: %s\n> ", FormatPeerID(senderID.String()), env.Content)
		// OTOMATIS: Kirim status "delivered" (Centang 2)
		go SendStatusUpdate(ctx, h, senderID, env.ID, StatusDelivered)
		
	case MsgTypeFile:
		parts := strings.Split(env.Content, ":")
		if len(parts) >= 4 {
			fmt.Printf("\n[FILE Notification from %s]: %s (%s bytes)\n", FormatPeerID(senderID.String()), parts[2], parts[3])
			fmt.Printf(">> To download, use: /download %s %s\n> ", parts[0], parts[1])
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
	logger.Debug().Str("target", target.String()).Msg("transmitEnvelope: Attempting direct dial to target")
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
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
		logger.Debug().Err(err).Str("target", target.String()).Msg("transmitEnvelope: Direct dial failed, falling back to mailbox storage")
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
				processCommand(ctx, h, priv, msg)
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
					lines := strings.Split(string(content), "\n")
					for _, line := range lines {
						cmd := strings.TrimSpace(line)
						if cmd != "" {
							logger.Debug().Str("command", cmd).Msg("Executing automated command from file")
							processCommand(ctx, h, priv, cmd)
						}
					}
					os.WriteFile(inputPath, []byte(""), 0644)
				}
			}
		}
	}()
}

func processCommand(ctx context.Context, h host.Host, priv crypto.PrivKey, msgStr string) {
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
					if res.Error == nil { fmt.Printf("[Latency] Ping %d: %v\n", i+1, res.RTT) }
				}
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/join ") {
		parts := strings.Split(msgStr, " ")
		if len(parts) >= 2 {
			groupID := parts[1]
			var members []string
			if len(parts) >= 3 {
				members = strings.Split(parts[2], ",")
			}
			JoinGroup(ctx, h, priv, groupID, members)
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			SendGroupMessage(ctx, h, parts[1], parts[2])
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
			RegisterAlias(ctx, h, alias, h.ID().String())
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
				}
			}
			targetID, err := peer.Decode(targetStr)
			if err == nil {
				logger.Debug().Str("peerID", targetID.String()).Msg("COMMAND: Calling SendMessage")
				_ = SendMessage(ctx, h, priv, targetID, parts[2])
				logger.Info().Str("peerID", targetID.String()).Msg("Message sent successfully (request submitted)")
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
				if err == nil { targetStr = resolved }
			}
			targetID, err := peer.Decode(targetStr)
			if err == nil {
				fileData, err := os.ReadFile(filePath)
				if err == nil {
					fileName := filepath.Base(filePath)
					fileMsg := fmt.Sprintf("FILE:%s:%d:%s", fileName, len(fileData), base64.StdEncoding.EncodeToString(fileData))
					_ = SendMessage(ctx, h, priv, targetID, fileMsg)
					fmt.Printf("[Success] Encrypted file %s sent to %s\n", fileName, FormatPeerID(targetID.String()))
				}
			}
		}
		return
	}

	// DESIGN-05 FIX: Input tidak dikenal sebagai command → tampilkan error, jangan broadcast ke semua peer.
	// Perilaku broadcast lama sangat berbahaya (typo command = kirim ke semua orang).
	fmt.Printf("[Error] Unknown command: '%s'\n", msgStr)
	fmt.Printf("Available commands: /msg, /group, /join, /fetch, /register, /upload, /latency\n> ")
}
