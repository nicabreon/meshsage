package protocol

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

var ClusterSecretKey = []byte("default-p2p-cluster-secret-key-change-me")

func init() {
	if envKey := os.Getenv("CLUSTER_SECRET"); envKey != "" {
		ClusterSecretKey = []byte(envKey)
	}
}

const (
	ReplicationProtocol = "/chirp/replicate/1.0.0"
	ClusterSyncTopic    = "p2p-core-cluster-sync"
)

type ClusterEvent struct {
	Type      string `json:"type"` // "MAILBOX_ADD", "MAILBOX_PURGE", "PREKEY_ADD"
	Hash      string `json:"hash,omitempty"`
	OwnerID   string `json:"owner_id,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Sender    string `json:"sender,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GenerateClusterHMAC menghasilkan tanda tangan HMAC-SHA256 base64 untuk ClusterEvent.
// Signature dihitung dari semua field selain field Signature itu sendiri.
func GenerateClusterHMAC(event ClusterEvent, key []byte) string {
	sigInput := ClusterEvent{
		Type:    event.Type,
		Hash:    event.Hash,
		OwnerID: event.OwnerID,
		Payload: event.Payload,
		Sender:  event.Sender,
	}
	data, _ := json.Marshal(sigInput)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyClusterHMAC memverifikasi apakah signature pada ClusterEvent cocok dengan HMAC dari data event.
func VerifyClusterHMAC(event ClusterEvent, key []byte) bool {
	if event.Signature == "" {
		return false
	}
	expectedSig := GenerateClusterHMAC(event, key)
	return hmac.Equal([]byte(event.Signature), []byte(expectedSig))
}

// SetupReplicationHandler configures the Relay to listen for replication requests
func SetupReplicationHandler(h host.Host) {
	h.SetStreamHandler(ReplicationProtocol, func(s network.Stream) {
		if !corenet.ShouldActAsRelay() {
			s.Reset()
			return
		}
		defer s.Close()

		buf, err := io.ReadAll(s)
		if err != nil {
			return
		}

		manifestCIDStr := string(buf)
		logger.Info().Str("manifestCID", manifestCIDStr).Msg("Received request to cache file")

		go replicateFile(manifestCIDStr)
	})
	logger.Info().Msg("Relay is ready to Auto-Cache files.")
}

// replicateFile is run by the Relay to proactively fetch and store chunks
func replicateFile(manifestCIDStr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	mCID, err := cid.Decode(manifestCIDStr)
	if err != nil {
		logger.Error().Err(err).Str("manifestCID", manifestCIDStr).Msg("Invalid CID")
		return
	}

	// 1. Fetch Manifest
	mBlock, err := corenet.GlobalBlockService.GetBlock(ctx, mCID)
	if err != nil {
		logger.Error().Err(err).Str("manifestCID", manifestCIDStr).Msg("Failed to fetch manifest")
		return
	}

	var manifest corestore.FileManifest
	if err := json.Unmarshal(mBlock.RawData(), &manifest); err != nil {
		logger.Error().Err(err).Str("manifestCID", manifestCIDStr).Msg("Failed to parse manifest")
		return
	}

	// 2. Fetch all chunks (This automatically pulls them to the Relay's Blockstore)
	logger.Info().Msgf("Fetching %d chunks to local cache...", len(manifest.Chunks))
	var cids []cid.Cid
	for _, cStr := range manifest.Chunks {
		c, _ := cid.Decode(cStr)
		cids = append(cids, c)
	}

	blockChan := corenet.GlobalBlockService.GetBlocks(ctx, cids)
	
	fetched := 0
	for b := range blockChan {
		// Just by receiving it, GlobalBlockService (Bitswap) has cached it!
		_ = corestore.TrackBlock(b.Cid().String())
		
		// We also want to explicitly Provide it to the DHT
		_ = corenet.GlobalDHT.Provide(ctx, b.Cid(), true)
		fetched++
	}

	logger.Info().Msgf("Cached %d/%d chunks for %s!", fetched, len(manifest.Chunks), manifest.Name)
}

// SetupClusterSync joins the gossip topic for metadata replication
func SetupClusterSync(ctx context.Context, h host.Host) {
	topic, err := corenet.GlobalPubSub.Join(ClusterSyncTopic)
	if err != nil { return }
	sub, err := topic.Subscribe()
	if err != nil { return }

	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil { return }
			if msg.ReceivedFrom == h.ID() { continue }

			var event ClusterEvent
			if err := json.Unmarshal(msg.Data, &event); err != nil { continue }

			// DESIGN-07 FIX: Verifikasi signature HMAC-SHA256 untuk cluster event
			if !VerifyClusterHMAC(event, ClusterSecretKey) {
				logger.Error().Str("type", event.Type).Str("peerID", msg.ReceivedFrom.String()).Msg("Invalid HMAC signature for cluster event")
				continue
			}

			switch event.Type {
			case "MAILBOX_ADD":
				logger.Info().Str("ownerID", event.OwnerID).Msg("Syncing mailbox message from cluster")
				corestore.SaveMailboxMessage(event.Hash, event.OwnerID, event.Sender, event.Payload)
			case "MAILBOX_PURGE":
				logger.Info().Str("hash", event.Hash).Msg("Purging message from cluster")
				corestore.DeleteMailboxMessageByHash(event.Hash)
			case "PREKEY_ADD":
				// BUG-07 FIX: Replicate pre-keys across relay nodes
				if event.OwnerID != "" && event.Hash != "" && event.Payload != "" {
					// event.Hash = KeyID, event.Payload = PublicKey, event.Sender = Signature
					err := corestore.SavePreKey(event.OwnerID, event.Hash, event.Payload, "", event.Sender)
					if err == nil {
						logger.Info().Str("ownerID", event.OwnerID[:8]).Str("keyID", event.Hash[:8]).Msg("Synced pre-key from cluster")
					}
				}
			}
		}
	}()
}

// BroadcastClusterEvent sends a metadata event to the entire cluster
func BroadcastClusterEvent(ctx context.Context, event ClusterEvent) {
	topic, err := corenet.GlobalPubSub.Join(ClusterSyncTopic)
	if err != nil { return }
	
	// DESIGN-07 FIX: Tambahkan signature HMAC sebelum melakukan broadcast
	event.Signature = GenerateClusterHMAC(event, ClusterSecretKey)
	
	data, _ := json.Marshal(event)
	topic.Publish(ctx, data)
}

// SendReplicationRequest sends a replicate command to a connected relay
func SendReplicationRequest(ctx context.Context, h host.Host, manifestCID string) {
	// Simple approach: Send to all connected peers that support the protocol
	// In a real app, you'd target specific Relay nodes
	peers := h.Network().Peers()
	count := 0
	for _, p := range peers {
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		s, err := h.NewStream(dialCtx, p, ReplicationProtocol)
		cancel()
		if err == nil {
			_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = s.Write([]byte(manifestCID))
			s.Close()
			count++
		}
	}
	if count > 0 {
		logger.Info().Int("count", count).Msg("Sent replication request to relays")
	}
}
