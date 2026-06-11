package protocol

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

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
	if err != nil {
		return
	}
	AddBytesRecv(len(line))

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 5)
	if len(parts) < 2 {
		return
	}

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
		if len(parts) < 2 {
			return
		}
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
