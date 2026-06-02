package protocol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

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
	if !isInfra && exists && time.Since(lastTime) < 50*time.Millisecond {
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
	case "FETCH":
		coord := parts[1]
		logger.Debug().Str("coord", coord).Msg("Incoming FETCH request")
		messages, err := corestore.GetMailboxMessages(coord)
		if err != nil {
			s.Write([]byte("ERROR\n"))
			return
		}

		for _, msg := range messages {
			response := fmt.Sprintf("MSG %s %s %s\n", msg.MsgHash, msg.SenderPubkey, msg.Payload)
			s.Write([]byte(response))
			BroadcastClusterEvent(context.Background(), ClusterEvent{Type: "MAILBOX_PURGE", Hash: msg.MsgHash})
		}
		s.Write([]byte("DONE\n"))
		corestore.ClearMailboxMessages(coord)
		logger.Debug().Int("count", len(messages)).Str("coord", coord).Msg("Mailbox cleared after fetch")
	}
}

func GetMailboxCoordinate(targetID peer.ID) string {
	hash := sha256.Sum256([]byte(targetID.String() + "mailbox"))
	return fmt.Sprintf("%x", hash)
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

	// Query closest peers once from DHT
	var closest []peer.ID
	dhtCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	closest, _ = corenet.GlobalDHT.GetClosestPeers(dhtCtx, coord)
	cancel()

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

			_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
			respBuf := bufio.NewReader(s)
			resp, _ := respBuf.ReadString('\n')

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
	_, err = s.Write([]byte(fmt.Sprintf("FETCH %s\n", coord)))
	if err != nil {
		logger.Debug().Err(err).Str("peerID", relayID.String()).Msg("Mailbox fetch: failed to write FETCH request")
		return
	}
	buf := bufio.NewReader(s)

	type fetchedEnvelope struct {
		senderID peer.ID
		payload  string
	}
	var fetched []fetchedEnvelope
	foundCount := 0

	for {
		_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := buf.ReadString('\n')
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
			break
		}
		if line == "ERROR" {
			logger.Debug().Str("peerID", relayID.String()).Msg("Mailbox fetch: relay returned ERROR status")
			break
		}

		parts := strings.Split(line, " ")
		if len(parts) < 4 || parts[0] != "MSG" { continue }

		msgHash := parts[1]
		if _, loaded := processedMailboxMessages.LoadOrStore(msgHash, true); loaded {
			logger.Debug().Str("hash", msgHash).Msg("Mailbox: Message already processed, skipping duplicate")
			continue
		}

		foundCount++
		senderPubkeyB64 := parts[2]
		payloadB64 := parts[3]

		payload, _ := base64.StdEncoding.DecodeString(payloadB64)

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
			}
		}
		if senderID == "" {
			// Fallback: try treating the field as a plain peer ID string (legacy messages)
			senderID, _ = peer.Decode(senderPubkeyB64)
		}
		if senderID == "" {
			logger.Warn().Str("hash", msgHash).Msg("Mailbox: could not derive senderID, skipping message")
			continue
		}
		fetched = append(fetched, fetchedEnvelope{
			senderID: senderID,
			payload:  string(payload),
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
		ProcessSecureEnvelope(ctx, h, msg.senderID, msg.payload)
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
// and runs a notification subscription loop, a periodic 2-second fast polling loop,
// and a periodic 30-second pre-key refill check loop concurrently.
func StartMailboxSync(ctx context.Context, h host.Host, relayID peer.ID, privKey crypto.PrivKey) {
	activeSyncsMutex.Lock()
	if _, exists := activeSyncs[relayID]; exists {
		activeSyncsMutex.Unlock()
		logger.Debug().Str("peerID", relayID.String()).Msg("Mailbox sync already running for relay, skipping duplicate setup")
		return
	}
	activeSyncs[relayID] = struct{}{}
	activeSyncsMutex.Unlock()

	defer func() {
		activeSyncsMutex.Lock()
		delete(activeSyncs, relayID)
		activeSyncsMutex.Unlock()
	}()

	// 1. Refill pre-keys
	go AutoRefillPreKeys(ctx, h, relayID, privKey)

	// 2. Fetch mailbox messages immediately
	go FetchMailboxMessages(ctx, h, relayID, privKey)

	// 3. Keep-alive subscription loop (runs in its own goroutine)
	go func() {
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
				// We are successfully subscribed to push notifications.
				// Wait until the subscription is lost or context cancel
				select {
				case <-ctx.Done():
					return
				case <-statusChan:
					// Lost subscription
				}
			}

			// Wait 5 seconds before retrying subscription to avoid tight connection loop
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()

	// 4. Concurrent 2-second fast polling loop
	go func() {
		logger.Info().Str("peerID", relayID.String()).Msg("Starting concurrent 2-second fast polling loop")
		pollTicker := time.NewTicker(2 * time.Second)
		defer pollTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-pollTicker.C:
				go FetchMailboxMessages(ctx, h, relayID, privKey)
			}
		}
	}()

	// 5. Concurrent 30-second pre-key refill check loop
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


