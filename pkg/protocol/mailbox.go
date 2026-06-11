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

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

var (
	rateLimitMap     = make(map[string]time.Time)
	rateLimitMutex   sync.Mutex
	activeSyncs      = make(map[peer.ID]struct{})
	activeSyncsMutex sync.Mutex
	activeFetches      = make(map[peer.ID]struct{})
	activeFetchesMutex sync.Mutex
)

const (
	MailboxProtocolID        = "/p2p-core/mailbox/1.0.0"
	InfrastructureProtocolID = "/p2p-core/infra/1.1.0"
	DedicatedProtocolID      = "/p2p-core/infra/dedicated/1.1.0"
	NotifyProtocolID         = "/p2p-core/notify/1.0.0"
	MaxMessageSize           = 1024 * 1024
	MaxHybridQuota           = 50 * 1024 * 1024
)

var (
	notifyRegistry = make(map[string]network.Stream)
	notifyMutex    sync.RWMutex
	processedMailboxMessages sync.Map
)

func SetupMailbox(h host.Host, isClientOnly bool) {
	logger.Debug().Str("protocol", MailboxProtocolID).Msg("Setting up mailbox stream handler")
	h.SetStreamHandler(protocol.ID(MailboxProtocolID), func(s network.Stream) {
		handleMailboxStream(h, s)
	})

	actAsRelay := !isClientOnly && !corenet.IsNetworkWeak
	logger.Info().Bool("actAsRelay", actAsRelay).Msg("Mailbox service decision")

	if actAsRelay {
		logger.Debug().Str("protocol", InfrastructureProtocolID).Msg("Registering infrastructure marker")
		h.SetStreamHandler(protocol.ID(InfrastructureProtocolID), func(s network.Stream) {
			s.Close()
		})

		// Jika memang Dedicated Relay, daftarkan marker tambahan
		if corenet.IsDedicated {
			logger.Debug().Str("protocol", DedicatedProtocolID).Msg("Registering DEDICATED infrastructure marker")
			h.SetStreamHandler(protocol.ID(DedicatedProtocolID), func(s network.Stream) {
				s.Close()
			})
		}

		logger.Debug().Str("protocol", NotifyProtocolID).Msg("Setting up notification handler")
		h.SetStreamHandler(protocol.ID(NotifyProtocolID), func(s network.Stream) {
			handleNotifyStream(s)
		})
	}

	// BUG-08 FIX: Periodic cleanup rateLimitMap agar tidak memory leak pada relay long-running
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rateLimitMutex.Lock()
			for k, t := range rateLimitMap {
				if time.Since(t) > 5*time.Minute {
					delete(rateLimitMap, k)
				}
			}
			rateLimitMutex.Unlock()
			logger.Debug().Msg("Rate limit map cleaned up")
		}
	}()
}

func handleNotifyStream(s network.Stream) {
	scanner := bufio.NewScanner(s)
	if scanner.Scan() {
		coord := strings.TrimSpace(scanner.Text())
		if coord == "" {
			s.Close()
			return
		}

		notifyMutex.Lock()
		if old, ok := notifyRegistry[coord]; ok {
			old.Close()
		}
		notifyRegistry[coord] = s
		notifyMutex.Unlock()

		logger.Debug().Str("coord", coord).Msg("Notification stream established")
		
		go func() {
			for scanner.Scan() {}
			notifyMutex.Lock()
			if notifyRegistry[coord] == s {
				delete(notifyRegistry, coord)
			}
			notifyMutex.Unlock()
			s.Close()
			logger.Debug().Str("coord", coord).Msg("Notification stream closed")
		}()
	}
}

func SubscribeNotifications(ctx context.Context, h host.Host, relayID peer.ID, statusChan chan<- bool) {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	s, err := h.NewStream(dialCtx, relayID, protocol.ID(NotifyProtocolID))
	cancel()
	if err != nil {
		if statusChan != nil { statusChan <- false }
		return
	}

	coord := GetMailboxCoordinate(h.ID())
	_, err = fmt.Fprintf(s, "%s\n", coord)
	if err != nil {
		s.Close()
		if statusChan != nil { statusChan <- false }
		return
	}

	logger.Info().Str("peerID", relayID.String()).Msg("Subscribed to push notifications")
	if statusChan != nil { statusChan <- true }

	go func() {
		scanner := bufio.NewScanner(s)
		for scanner.Scan() {
			text := scanner.Text()
			if text == "PING" {
				logger.Debug().Str("peerID", relayID.String()).Msg("Received PUSH notification! Triggering fetch...")
				go FetchMailboxMessages(ctx, h, relayID, h.Peerstore().PrivKey(h.ID()))
			}
		}
		s.Close()
		logger.Warn().Str("peerID", relayID.String()).Msg("Subscription lost to relay. Reverting to fast polling")
		if statusChan != nil { statusChan <- false }
	}()
}

func NotifyRecipient(coord string) {
	notifyMutex.RLock()
	s, ok := notifyRegistry[coord]
	notifyMutex.RUnlock()

	if ok {
		go func() {
			logger.Debug().Str("coord", FormatPeerID(coord)).Msg("Pushing PING notification to active stream")
			_, err := fmt.Fprintf(s, "PING\n")
			if err != nil {
				s.Close()
				notifyMutex.Lock()
				if notifyRegistry[coord] == s {
					delete(notifyRegistry, coord)
				}
				notifyMutex.Unlock()
			}
		}()
	}
}

func handleMailboxStream(h host.Host, s network.Stream) {
	peerID := s.Conn().RemotePeer().String()
	senderID := s.Conn().RemotePeer()
	logger.Debug().Str("peerID", peerID).Msg("Incoming mailbox stream")

	if IsPeerBlocked(peerID) {
		logger.Warn().Str("peerID", peerID).Msg("Dropping stream from blacklisted peer")
		s.Reset()
		return
	}

	if !corenet.ShouldActAsRelay() {
		logger.Debug().Str("peerID", FormatPeerID(peerID)).Msg("Rejecting request: Node is not acting as relay")
		s.Reset()
		return
	}

	defer s.Close()
	buf := bufio.NewReader(s)
	line, err := buf.ReadString('\n')
	if err != nil { return }
	AddBytesRecv(len(line))

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 5)
	if len(parts) < 2 { return }

	isInfra := false
	protos, _ := h.Peerstore().GetProtocols(senderID)
	for _, p := range protos {
		if string(p) == InfrastructureProtocolID {
			isInfra = true
			break
		}
	}

	rateLimitMutex.Lock()
	lastTime, exists := rateLimitMap[string(senderID)]
	if !isInfra && exists && time.Since(lastTime) < 1*time.Millisecond {
		rateLimitMutex.Unlock()
		logger.Warn().Str("peer", FormatPeerID(string(senderID))).Msg("Rate limit triggered for mailbox request")
		s.Write([]byte("ERROR_RATE_LIMIT_EXCEEDED\n"))
		return
	}
	rateLimitMap[string(senderID)] = time.Now()
	rateLimitMutex.Unlock()

	cmd := parts[0]
	switch cmd {
	case "STORE":
		if len(parts) == 5 {
			msgHash := parts[1]
			coord := parts[2]
			senderPubkey := parts[3]
			payload := parts[4]

			if len(payload) > MaxMessageSize {
				logger.Warn().Int("size", len(payload)).Msg("REJECTED: Message too large")
				s.Write([]byte("ERROR_TOO_LARGE\n"))
				return
			}

			pubKeyBytes, errDecPub := base64.StdEncoding.DecodeString(senderPubkey)
			if errDecPub != nil {
				logger.Warn().Err(errDecPub).Msg("REJECTED: Invalid sender public key base64")
				s.Write([]byte("ERROR_INVALID_SENDER_PUBKEY\n"))
				return
			}
			senderPubKey, errUnmarshal := crypto.UnmarshalPublicKey(pubKeyBytes)
			if errUnmarshal != nil {
				logger.Warn().Err(errUnmarshal).Msg("REJECTED: Failed to unmarshal sender public key")
				s.Write([]byte("ERROR_INVALID_SENDER_PUBKEY\n"))
				return
			}
			senderPeerID, errID := peer.IDFromPublicKey(senderPubKey)
			if errID != nil {
				logger.Warn().Err(errID).Msg("REJECTED: Failed to derive sender Peer ID")
				s.Write([]byte("ERROR_INVALID_SENDER_PUBKEY\n"))
				return
			}

			// Verify signature to prevent spam on mailboxes
			envBytes, errDec := base64.StdEncoding.DecodeString(payload)
			if errDec != nil {
				logger.Warn().Err(errDec).Msg("REJECTED: Invalid base64 payload")
				s.Write([]byte("ERROR_INVALID_PAYLOAD\n"))
				return
			}

			_, errSig := VerifySignedEnvelope(string(envBytes), senderPubKey)
			if errSig != nil {
				logger.Warn().Err(errSig).Msg("REJECTED: Mailbox signature verification failed (invalid signature)")
				s.Write([]byte("ERROR_SIGNATURE_VERIFICATION_FAILED\n"))
				return
			}

			// Anti-Spam Check: Verify sender is registered by checking if they have active pre-keys
			if corestore.GetPreKeyCount(senderPeerID.String()) == 0 {
				logger.Warn().Str("sender", senderPeerID.String()).Msg("REJECTED: Sender has no registered pre-keys on this relay")
				s.Write([]byte("ERROR_SENDER_UNREGISTERED\n"))
				return
			}

			err := corestore.SaveMailboxMessage(msgHash, coord, senderPubkey, payload)
			if err != nil {
				logger.Error().Err(err).Msg("Database error while saving mailbox message")
				s.Write([]byte("ERROR\n"))
			} else {
				logger.Debug().Str("coord", coord).Msg("Message stored in mailbox")
				s.Write([]byte("OK\n"))
				NotifyRecipient(coord)
				BroadcastClusterEvent(context.Background(), ClusterEvent{
					Type: "MAILBOX_ADD", Hash: msgHash, OwnerID: coord, Sender: senderPubkey, Payload: payload,
				})
			}
		}
	case "REPLICATE":
		if len(parts) < 2 { return }
		manifestCIDStr := parts[1]
		go func(cidStr string) {
			logger.Info().Str("cid", cidStr).Msg("Relay received REPLICATE request for media file")
			mCID, err := cid.Decode(cidStr)
			if err != nil {
				logger.Warn().Err(err).Str("cid", cidStr).Msg("Invalid replication CID")
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			mBlock, err := corenet.GlobalBlockService.GetBlock(ctx, mCID)
			if err != nil {
				logger.Warn().Err(err).Str("cid", cidStr).Msg("Failed to fetch manifest block for replication")
				return
			}
			var manifest corestore.FileManifest
			if err := json.Unmarshal(mBlock.RawData(), &manifest); err != nil {
				logger.Warn().Err(err).Msg("Failed to unmarshal manifest for replication")
				return
			}
			var cids []cid.Cid
			for _, cStr := range manifest.Chunks {
				c, _ := cid.Decode(cStr)
				cids = append(cids, c)
			}
			logger.Info().Str("file", manifest.Name).Int("chunks", len(cids)).Msg("Relay fetching chunks for replication...")
			blockChan := corenet.GlobalBlockService.GetBlocks(ctx, cids)
			fetchedCount := 0
			for b := range blockChan {
				_ = b
				fetchedCount++
			}
			logger.Info().Str("file", manifest.Name).Int("fetched", fetchedCount).Msg("Relay successfully replicated and cached media file blocks!")
		}(manifestCIDStr)
		s.Write([]byte("OK\n"))
	case "FETCH":
		coord := parts[1]
		useACK := len(parts) >= 3 && parts[2] == "ACK"
		logger.Debug().Str("coord", coord).Bool("useACK", useACK).Msg("Incoming FETCH request")
		messages, err := corestore.GetMailboxMessages(coord)
		if err != nil {
			s.Write([]byte("ERROR\n"))
			return
		}

		for _, msg := range messages {
			response := fmt.Sprintf("MSG %s %s %s\n", msg.MsgHash, msg.SenderPubkey, msg.Payload)
			s.Write([]byte(response))
			AddBytesSent(len(response))
		}
		doneMsg := "DONE\n"
		s.Write([]byte(doneMsg))
		AddBytesSent(len(doneMsg))

		if !useACK {
			// Legacy client compatibility: immediately purge message database
			for _, msg := range messages {
				BroadcastClusterEvent(context.Background(), ClusterEvent{Type: "MAILBOX_PURGE", Hash: msg.MsgHash})
			}
			corestore.ClearMailboxMessages(coord)
			logger.Debug().Int("count", len(messages)).Str("coord", coord).Msg("Mailbox cleared immediately (legacy client)")
		} else {
			// Wait for ACK from the client to confirm successful receipt before clearing
			_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(s)
			ack, errRead := reader.ReadString('\n')
			if errRead == nil {
				AddBytesRecv(len(ack))
			}
			if errRead == nil && strings.TrimSpace(ack) == "ACK" {
				for _, msg := range messages {
					BroadcastClusterEvent(context.Background(), ClusterEvent{Type: "MAILBOX_PURGE", Hash: msg.MsgHash})
				}
				corestore.ClearMailboxMessages(coord)
				logger.Debug().Int("count", len(messages)).Str("coord", coord).Msg("Mailbox cleared after fetch confirmed with ACK")
			} else {
				logger.Warn().Err(errRead).Str("coord", coord).Str("ack", ack).Msg("Mailbox fetch: client failed to send ACK or timeout occurred. Messages retained on relay.")
			}
		}
	}
}

func GetMailboxCoordinate(targetID peer.ID) string {
	hash := sha256.Sum256([]byte(targetID.String() + "mailbox"))
	return fmt.Sprintf("%x", hash)
}

type CachedMailboxPeers struct {
	Peers      []peer.ID
	LastUpdate time.Time
}

var MailboxPeersCache sync.Map // map[peer.ID]CachedMailboxPeers

func PrefetchMailboxCoords(targetID peer.ID) {
	if corenet.GlobalDHT == nil { return }
	go func() {
		coord := GetMailboxCoordinate(targetID)
		dhtCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		peers, err := corenet.GlobalDHT.GetClosestPeers(dhtCtx, coord)
		if err == nil {
			MailboxPeersCache.Store(targetID, CachedMailboxPeers{
				Peers:      peers,
				LastUpdate: time.Now(),
			})
			logger.Debug().Str("target", targetID.String()).Int("closest", len(peers)).Msg("Mailbox DHT cache pre-fetched in background")
		} else {
			logger.Debug().Err(err).Str("target", targetID.String()).Msg("Mailbox DHT cache pre-fetch failed")
		}
	}()
}

func StoreOfflineMessage(ctx context.Context, h host.Host, targetID peer.ID, senderPubkeyB64, payloadB64 string) error {
	coord := GetMailboxCoordinate(targetID)
	msgHash := fmt.Sprintf("%x", sha256.Sum256([]byte(payloadB64+senderPubkeyB64+fmt.Sprintf("%d", time.Now().UnixNano()))))

	var infraPeers []peer.ID
	var hybridPeers []peer.ID
	allPeers := h.Network().Peers()
	
	for _, p := range allPeers {
		if p == h.ID() { continue }
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
			if p != h.ID() && p != targetID { hybridPeers = append(hybridPeers, p) }
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
		if len(targetPeers) >= maxRemoteTargets { break }
		if p != targetID { targetPeers[p] = true }
	}
	for _, p := range closest {
		if len(targetPeers) >= maxRemoteTargets { break }
		if p != h.ID() && p != targetID { targetPeers[p] = true }
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
			if err != nil { return }
			defer s.Close()

			_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
			cmd := fmt.Sprintf("STORE %s %s %s %s\n", msgHash, coord, senderPubkeyB64, payloadB64)
			_, err = s.Write([]byte(cmd))
			if err != nil { return }
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

// StartMailboxSync coordinates initial pre-key refill, immediate message fetching,
// and runs a notification subscription loop and a periodic 30-second pre-key refill
// check loop concurrently.
//
// Guard lifecycle: activeSyncs entry is held inside the subscription goroutine itself,
// NOT in the calling function. This prevents duplicate sync loops when the relay
// reconnects while a loop is already running.
func StartMailboxSync(ctx context.Context, h host.Host, relayID peer.ID, privKey crypto.PrivKey) {
	// Quick non-blocking guard check before spawning goroutines.
	activeSyncsMutex.Lock()
	if _, exists := activeSyncs[relayID]; exists {
		activeSyncsMutex.Unlock()
		logger.Debug().Str("peerID", relayID.String()).Msg("Mailbox sync already running for relay, skipping duplicate setup")
		return
	}
	// Mark as running immediately — the goroutine below will unmark on exit.
	activeSyncs[relayID] = struct{}{}
	activeSyncsMutex.Unlock()

	// 1. Refill pre-keys
	go AutoRefillPreKeys(ctx, h, relayID, privKey)

	// 2. Fetch mailbox messages immediately (staggered to avoid rate limiting on startup)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
			FetchMailboxMessages(ctx, h, relayID, privKey)
		}
	}()

	// 3. Keep-alive subscription loop.
	// IMPORTANT: This goroutine owns the activeSyncs guard for relayID.
	// The guard is released only when this goroutine exits (ctx cancelled),
	// preventing duplicate loops if the relay reconnects while this loop runs.
	go func() {
		defer func() {
			activeSyncsMutex.Lock()
			delete(activeSyncs, relayID)
			activeSyncsMutex.Unlock()
			logger.Debug().Str("peerID", relayID.String()).Msg("Mailbox sync loop exited, guard released")
		}()

		backoff := 15 * time.Second
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			statusChan := make(chan bool, 2)
			go SubscribeNotifications(ctx, h, relayID, statusChan)

			// Wait for subscription status or context cancel
			var subscribed bool
			select {
			case <-ctx.Done():
				return
			case subscribed = <-statusChan:
			}

			if subscribed {
				backoff = 15 * time.Second // Reset backoff on success
				// Successfully subscribed — wait until lost or ctx cancelled.
				select {
				case <-ctx.Done():
					return
				case <-statusChan:
					// Lost subscription, will retry after backoff below.
				}
			}

			// Back-off before retrying to avoid hammering the relay.
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Increase backoff for next failure
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
	}()

	// 4. Concurrent 30-second pre-key refill check loop.
	go func() {
		refillTicker := time.NewTicker(30 * time.Second)
		defer refillTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-refillTicker.C:
				go AutoRefillPreKeys(ctx, h, relayID, privKey)
			}
		}
	}()
}

func ReplicateFileToRelays(ctx context.Context, h host.Host, manifestCID string) {
	// Find all connected dedicated relays
	var relays []peer.ID
	for _, p := range h.Network().Peers() {
		protos, err := h.Peerstore().GetProtocols(p)
		if err != nil {
			continue
		}
		isDedicated := false
		for _, proto := range protos {
			if string(proto) == DedicatedProtocolID {
				isDedicated = true
				break
			}
		}
		if isDedicated {
			relays = append(relays, p)
		}
	}

	if len(relays) == 0 {
		logger.Warn().Msg("[Replication] No connected Dedicated Relays found to replicate file")
		return
	}

	logger.Info().Str("cid", manifestCID).Int("count", len(relays)).Msg("[Replication] Requesting file replication to dedicated relays...")

	for _, relayID := range relays {
		go func(rID peer.ID) {
			sCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			s, err := h.NewStream(sCtx, rID, protocol.ID(MailboxProtocolID))
			if err != nil {
				logger.Warn().Str("relay", rID.String()).Err(err).Msg("[Replication] Failed to open mailbox stream to relay")
				return
			}
			defer s.Close()

			cmd := fmt.Sprintf("REPLICATE %s\n", manifestCID)
			_, err = s.Write([]byte(cmd))
			if err != nil {
				logger.Warn().Str("relay", rID.String()).Err(err).Msg("[Replication] Failed to write REPLICATE command to relay")
				return
			}

			buf := bufio.NewReader(s)
			resp, err := buf.ReadString('\n')
			if err != nil {
				logger.Warn().Str("relay", rID.String()).Err(err).Msg("[Replication] Failed to read response from relay")
				return
			}

			if strings.TrimSpace(resp) == "OK" {
				logger.Info().Str("relay", rID.String()).Msg("[Replication] Dedicated Relay accepted replication request")
			} else {
				logger.Warn().Str("relay", rID.String()).Str("resp", resp).Msg("[Replication] Dedicated Relay returned non-OK status")
			}
		}(relayID)
	}
}

// StartGlobalMailboxSyncManager runs a single global loop to fetch mailbox messages
// sequentially from all connected infrastructure/relay nodes every 1 minute as a fallback.
// Real-time delivery is handled by push notifications (SubscribeNotifications).
// The 1-minute interval drastically reduces idle data usage compared to the prior 30-second polling.
func StartGlobalMailboxSyncManager(ctx context.Context, h host.Host, privKey crypto.PrivKey) {
	logger.Info().Msg("Starting Global Mailbox Sync Manager (1m fallback polling)...")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 1. Find all connected peers
			peers := h.Network().Peers()
			if len(peers) == 0 {
				continue
			}

			// 2. Filter to find peers that support the mailbox protocol
			var relays []peer.ID
			for _, p := range peers {
				protos, err := h.Peerstore().GetProtocols(p)
				if err != nil {
					continue
				}
				isRelay := false
				for _, proto := range protos {
					if string(proto) == InfrastructureProtocolID {
						isRelay = true
						break
					}
				}
				if isRelay {
					relays = append(relays, p)
				}
			}

			// 3. Fetch from each relay sequentially (synchronously)
			for _, rID := range relays {
				FetchMailboxMessages(ctx, h, rID, privKey)
			}
		}
	}
}



