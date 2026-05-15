package protocol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	rateLimitMap   = make(map[string]time.Time)
	rateLimitMutex sync.Mutex
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
	s, err := h.NewStream(ctx, relayID, protocol.ID(NotifyProtocolID))
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

	if len(infraPeers) == 0 {
		dhtCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		closest, _ := corenet.GlobalDHT.GetClosestPeers(dhtCtx, coord)
		cancel()
		for _, p := range closest {
			if p != h.ID() && p != targetID { hybridPeers = append(hybridPeers, p) }
		}
	}

	targetPeers := make(map[peer.ID]bool)
	for _, p := range infraPeers {
		if p != targetID { targetPeers[p] = true }
	}
	closest, _ := corenet.GlobalDHT.GetClosestPeers(ctx, coord)
	for _, p := range closest {
		if len(targetPeers) >= 3 { break }
		if p != h.ID() && p != targetID { targetPeers[p] = true }
	}

	successCount := 0
	logger.Debug().Str("hash", msgHash).Int("targets", len(targetPeers)).Msg("Starting offline storage distribution")

	for p := range targetPeers {
		s, err := h.NewStream(ctx, p, protocol.ID(MailboxProtocolID))
		if err != nil { continue }

		cmd := fmt.Sprintf("STORE %s %s %s %s\n", msgHash, coord, senderPubkeyB64, payloadB64)
		_, err = s.Write([]byte(cmd))
		if err != nil { s.Close(); continue }

		respBuf := bufio.NewReader(s)
		resp, _ := respBuf.ReadString('\n')
		s.Close()

		if strings.TrimSpace(resp) == "OK" {
			successCount++
		}
	}

	if successCount == 0 { return fmt.Errorf("failed to store message on any node") }
	logger.Info().Int("nodes", successCount).Msg("Offline message stored successfully")
	return nil
}

func FetchMailboxMessages(ctx context.Context, h host.Host, relayID peer.ID, privKey crypto.PrivKey) {
	coord := GetMailboxCoordinate(h.ID())
	logger.Debug().Str("coord", coord).Str("peerID", relayID.String()).Msg("Starting mailbox fetch")
	
	s, err := h.NewStream(ctx, relayID, protocol.ID(MailboxProtocolID))
	if err != nil { return }
	defer s.Close()

	s.Write([]byte(fmt.Sprintf("FETCH %s\n", coord)))
	buf := bufio.NewReader(s)

	foundCount := 0
	for {
		line, err := buf.ReadString('\n')
		if err != nil { break }
		line = strings.TrimSpace(line)
		
		if line == "DONE" { 
			if foundCount > 0 { logger.Info().Int("count", foundCount).Msg("Fetch complete") }
			break 
		}
		if line == "ERROR" { break }

		parts := strings.Split(line, " ")
		if len(parts) < 4 || parts[0] != "MSG" { continue }

		foundCount++
		senderPubkey := parts[2]
		payloadB64 := parts[3]
		
		payload, _ := base64.StdEncoding.DecodeString(payloadB64)
		senderID, _ := peer.Decode(senderPubkey)
		ProcessSecureEnvelope(ctx, h, senderID, string(payload))
	}
}
