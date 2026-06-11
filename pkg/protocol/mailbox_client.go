package protocol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

// SignedMailboxEnvelope represents the signed envelope stored in the Mailbox
type SignedMailboxEnvelope struct {
	Payload   string `json:"payload"`   // The original E2EE message envelope
	Signature string `json:"signature"` // Base64 signature of the payload
}

// WrapEnvelopeWithSignature signs the payload with the host's private key and marshals it into a SignedMailboxEnvelope JSON.
func WrapEnvelopeWithSignature(privKey crypto.PrivKey, payload string) (string, error) {
	sig, err := privKey.Sign([]byte(payload))
	if err != nil {
		return "", err
	}
	env := SignedMailboxEnvelope{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	data, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// VerifySignedEnvelope verifies the envelope signature using the sender's public key and returns the decrypted payload.
func VerifySignedEnvelope(envelopeStr string, senderPubKey crypto.PubKey) (string, error) {
	var env SignedMailboxEnvelope
	if err := json.Unmarshal([]byte(envelopeStr), &env); err != nil {
		return "", fmt.Errorf("invalid envelope JSON: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return "", fmt.Errorf("invalid signature base64: %w", err)
	}
	valid, err := senderPubKey.Verify([]byte(env.Payload), sigBytes)
	if err != nil || !valid {
		return "", fmt.Errorf("invalid signature")
	}
	return env.Payload, nil
}

func StoreOfflineMessage(ctx context.Context, h host.Host, targetID peer.ID, senderPubkeyB64, payloadB64 string) error {
	coord := GetMailboxCoordinate(targetID)
	msgHash := fmt.Sprintf("%x", sha256.Sum256([]byte(payloadB64+senderPubkeyB64+fmt.Sprintf("%d", time.Now().UnixNano()))))

	var infraPeers []peer.ID
	var hybridPeers []peer.ID
	allPeers := h.Network().Peers()

	for _, p := range allPeers {
		if p == h.ID() {
			continue
		}
		isInfra := false
		protos, _ := h.Peerstore().GetProtocols(p)
		for _, proto := range protos {
			if string(proto) == InfrastructureProtocolID {
				isInfra = true
				break
			}
		}
		if isInfra {
			infraPeers = append(infraPeers, p)
		} else {
			hybridPeers = append(hybridPeers, p)
		}
	}

	// Look up closest peers in memory cache
	var closest []peer.ID
	cacheVal, found := MailboxPeersCache.Load(targetID)
	needRefresh := true

	if found {
		cached := cacheVal.(CachedMailboxPeers)
		closest = cached.Peers
		if time.Now().Sub(cached.LastUpdate) < 30*time.Second {
			needRefresh = false
		}
	}

	if needRefresh && corenet.GlobalDHT != nil {
		go func(tID peer.ID, cd string) {
			dhtCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			peers, err := corenet.GlobalDHT.GetClosestPeers(dhtCtx, cd)
			if err == nil {
				MailboxPeersCache.Store(tID, CachedMailboxPeers{
					Peers:      peers,
					LastUpdate: time.Now(),
				})
				logger.Debug().Str("target", tID.String()).Int("closest", len(peers)).Msg("Mailbox DHT cache updated in background")
			}
		}(targetID, coord)
	}

	// Fallback to connected hybrid peers if we have no cached closest peers (preflight/warmup path)
	if len(closest) == 0 {
		closest = hybridPeers
	}

	if len(infraPeers) == 0 {
		for _, p := range closest {
			if p != h.ID() && p != targetID {
				hybridPeers = append(hybridPeers, p)
			}
		}
	}

	// If the local node acts as a relay, and the target is not itself, we can store it locally
	storeLocally := corenet.ShouldActAsRelay() && targetID != h.ID()

	maxRemoteTargets := 3
	if storeLocally {
		maxRemoteTargets = 2
	}

	targetPeers := make(map[peer.ID]bool)
	for _, p := range infraPeers {
		if len(targetPeers) >= maxRemoteTargets {
			break
		}
		if p != targetID {
			targetPeers[p] = true
		}
	}
	for _, p := range closest {
		if len(targetPeers) >= maxRemoteTargets {
			break
		}
		if p != h.ID() && p != targetID {
			targetPeers[p] = true
		}
	}

	var mu sync.Mutex
	successCount := 0

	if storeLocally {
		err := corestore.SaveMailboxMessage(msgHash, coord, senderPubkeyB64, payloadB64)
		if err == nil {
			successCount++
			logger.Debug().Str("hash", msgHash).Str("coord", coord).Msg("Message stored in local mailbox (self-relay)")
			NotifyRecipient(coord)
			BroadcastClusterEvent(ctx, ClusterEvent{
				Type: "MAILBOX_ADD", Hash: msgHash, OwnerID: coord, Sender: senderPubkeyB64, Payload: payloadB64,
			})
		} else {
			logger.Error().Err(err).Msg("Failed to store mailbox message locally")
		}
	}

	logger.Debug().Str("hash", msgHash).Int("targets", len(targetPeers)).Bool("storeLocally", storeLocally).Msg("Starting offline storage distribution")

	var wg sync.WaitGroup
	for p := range targetPeers {
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()

			dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			s, err := h.NewStream(dialCtx, peerID, protocol.ID(MailboxProtocolID))
			cancel()
			if err != nil {
				return
			}
			defer s.Close()

			_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
			cmd := fmt.Sprintf("STORE %s %s %s %s\n", msgHash, coord, senderPubkeyB64, payloadB64)
			_, err = s.Write([]byte(cmd))
			if err != nil {
				return
			}
			AddBytesSent(len(cmd))

			_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
			respBuf := bufio.NewReader(s)
			resp, _ := respBuf.ReadString('\n')
			AddBytesRecv(len(resp))

			if strings.TrimSpace(resp) == "OK" {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	// Enforce minimum success: 2 nodes, or total targeted nodes if less than 2
	totalTargeted := len(targetPeers)
	if storeLocally {
		totalTargeted++
	}
	requiredMin := 2
	if totalTargeted < requiredMin {
		requiredMin = totalTargeted
	}

	if successCount < requiredMin {
		return fmt.Errorf("failed to store message on required number of nodes (stored on %d/%d nodes)", successCount, requiredMin)
	}
	logger.Info().Int("nodes", successCount).Msg("Offline message stored successfully")
	return nil
}

func FetchMailboxMessages(ctx context.Context, h host.Host, relayID peer.ID, privKey crypto.PrivKey) {
	activeFetchesMutex.Lock()
	if _, exists := activeFetches[relayID]; exists {
		activeFetchesMutex.Unlock()
		logger.Debug().Str("peerID", relayID.String()).Msg("Mailbox fetch already in progress, skipping concurrent fetch")
		return
	}
	activeFetches[relayID] = struct{}{}
	activeFetchesMutex.Unlock()

	defer func() {
		activeFetchesMutex.Lock()
		delete(activeFetches, relayID)
		activeFetchesMutex.Unlock()
	}()

	coord := GetMailboxCoordinate(h.ID())
	logger.Debug().Str("coord", coord).Str("peerID", relayID.String()).Msg("Starting mailbox fetch")

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	s, err := h.NewStream(dialCtx, relayID, protocol.ID(MailboxProtocolID))
	cancel()
	if err != nil {
		logger.Debug().Err(err).Str("peerID", relayID.String()).Msg("Mailbox fetch: failed to open stream")
		return
	}
	defer s.Close()

	_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
	cmd := fmt.Sprintf("FETCH %s ACK\n", coord)
	_, err = s.Write([]byte(cmd))
	if err != nil {
		logger.Debug().Err(err).Str("peerID", relayID.String()).Msg("Mailbox fetch: failed to write FETCH request")
		return
	}
	AddBytesSent(len(cmd))

	buf := bufio.NewReader(s)

	type fetchedEnvelope struct {
		senderID peer.ID
		payload  string
		msgHash  string
	}
	var fetched []fetchedEnvelope
	foundCount := 0

	for {
		_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := buf.ReadString('\n')
		if err == nil {
			AddBytesRecv(len(line))
		}
		if err != nil {
			logger.Debug().Err(err).Str("peerID", relayID.String()).Msg("Mailbox fetch: read error during stream iteration")
			break
		}
		line = strings.TrimSpace(line)

		if line == "DONE" {
			logger.Debug().Int("count", foundCount).Str("peerID", relayID.String()).Msg("Fetch complete")
			if foundCount > 0 {
				logger.Info().Int("count", foundCount).Msg("Fetch complete")
			}
			// Send ACK to relay to confirm we received the messages
			_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
			ackMsg := "ACK\n"
			_, _ = s.Write([]byte(ackMsg))
			AddBytesSent(len(ackMsg))
			break
		}
		if strings.HasPrefix(line, "ERROR") {
			logger.Warn().Str("peerID", relayID.String()).Str("status", line).Msg("Mailbox fetch: relay returned error status")
			break
		}

		parts := strings.Split(line, " ")
		if len(parts) < 4 || parts[0] != "MSG" {
			logger.Warn().Str("line", line).Msg("Mailbox fetch: ignored invalid/malformed response line from relay")
			continue
		}

		msgHash := parts[1]
		// Check in-memory cache first (already marked true)
		if statusVal, loaded := processedMailboxMessages.Load(msgHash); loaded && statusVal == true {
			logger.Info().Str("hash", msgHash).Msg("Mailbox fetch: Message already processed (in-memory), skipping duplicate")
			continue
		}
		// Check persistent database cache
		if corestore.IsMailboxMessageProcessed(msgHash) {
			processedMailboxMessages.Store(msgHash, true) // cache it
			logger.Info().Str("hash", msgHash).Msg("Mailbox fetch: Message already processed (DB), skipping duplicate")

			// Dispatch the already decrypted message from SQLite in case the UI missed it
			sender, recipient, content, msgID, msgType, err := corestore.GetMessageByHash(msgHash)
			if err != nil {
				if err == sql.ErrNoRows {
					logger.Debug().Str("hash", msgHash).Msg("Mailbox fetch: message hash not found in messages DB (this is normal for handshakes/status reports)")
				} else {
					logger.Warn().Err(err).Str("hash", msgHash).Msg("Mailbox fetch: failed to retrieve message by hash from DB")
				}
			} else if msgID != "" {
				ts := time.Now().Format("02/01 15:04:05")
				if MessageCallback != nil {
					var groupID string
					if msgType == "group" {
						groupID = recipient
					}
					MessageCallback(MessageEvent{
						Type:      msgType,
						Timestamp: ts,
						Sender:    sender,
						GroupID:   groupID,
						Content:   content,
						MsgID:     msgID,
					})
				}
			} else {
				logger.Warn().Str("hash", msgHash).Msg("Mailbox fetch: message by hash in DB has empty msgID")
			}
			continue
		}
		// Mark as processing in memory to prevent concurrent fetches
		status, loaded := processedMailboxMessages.LoadOrStore(msgHash, "processing")
		if loaded {
			logger.Info().Str("hash", msgHash).Interface("status", status).Msg("Mailbox fetch: Message already in-flight or processed, skipping duplicate")
			continue
		}

		senderPubkeyB64 := parts[2]
		payloadB64 := parts[3]

		payload, errDecPayload := base64.StdEncoding.DecodeString(payloadB64)
		if errDecPayload != nil {
			logger.Error().Err(errDecPayload).Str("hash", msgHash).Msg("Mailbox fetch: failed to decode payload base64, skipping message")
			processedMailboxMessages.Delete(msgHash)
			continue
		}

		// Derive senderID from the marshalled libp2p public key stored by the sender.
		// We cannot use peer.Decode here because the stored value is raw pubkey bytes
		// (from crypto.MarshalPublicKey), not a multihash peer ID string.
		var senderID peer.ID
		pubKeyBytes, errDec := base64.StdEncoding.DecodeString(senderPubkeyB64)
		if errDec == nil {
			pubKey, errUnmarshal := crypto.UnmarshalPublicKey(pubKeyBytes)
			if errUnmarshal == nil {
				senderID, _ = peer.IDFromPublicKey(pubKey)
				// Cache the address in peerstore so the reply can reach them
				h.Peerstore().AddPubKey(senderID, pubKey)
			} else {
				logger.Error().Err(errUnmarshal).Str("hash", msgHash).Msg("Mailbox fetch: failed to unmarshal public key")
			}
		} else {
			logger.Error().Err(errDec).Str("hash", msgHash).Msg("Mailbox fetch: failed to decode public key base64")
		}
		if senderID == "" {
			// Fallback: try treating the field as a plain peer ID string (legacy messages)
			var errFallback error
			senderID, errFallback = peer.Decode(senderPubkeyB64)
			if errFallback != nil {
				logger.Error().Err(errFallback).Str("hash", msgHash).Msg("Mailbox fetch: fallback peer.Decode failed")
			}
		}
		if senderID == "" {
			logger.Error().Str("hash", msgHash).Msg("Mailbox fetch: could not derive senderID, skipping message")
			processedMailboxMessages.Delete(msgHash)
			continue
		}

		foundCount++
		fetched = append(fetched, fetchedEnvelope{
			senderID: senderID,
			payload:  string(payload),
			msgHash:  msgHash,
		})
	}

	// Sort stable so X3DH handshakes are processed before DR messages
	sort.SliceStable(fetched, func(i, j int) bool {
		isX3DHi := strings.HasPrefix(fetched[i].payload, "X3DH:")
		isX3DHj := strings.HasPrefix(fetched[j].payload, "X3DH:")
		if isX3DHi && !isX3DHj {
			return true
		}
		return false
	})

	for _, msg := range fetched {
		ProcessSecureEnvelope(ctx, h, msg.senderID, msg.payload, msg.msgHash)
	}
}
