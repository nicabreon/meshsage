package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

const (
	ReplicationProtocol = "/chirp/replicate/1.0.0"
	ClusterSyncTopic    = "p2p-core-cluster-sync"
)

type ClusterEvent struct {
	Type    string `json:"type"` // "MAILBOX_ADD", "MAILBOX_PURGE", "PREKEY_ADD"
	Hash    string `json:"hash,omitempty"`
	OwnerID string `json:"owner_id,omitempty"`
	Payload string `json:"payload,omitempty"`
	Sender  string `json:"sender,omitempty"`
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
		fmt.Printf("[Replication] Received request to cache file: %s\n", manifestCIDStr)

		go replicateFile(manifestCIDStr)
	})
	fmt.Println("[Replication] Relay is ready to Auto-Cache files.")
}

// replicateFile is run by the Relay to proactively fetch and store chunks
func replicateFile(manifestCIDStr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	mCID, err := cid.Decode(manifestCIDStr)
	if err != nil {
		fmt.Printf("[Replication Error] Invalid CID: %v\n", err)
		return
	}

	// 1. Fetch Manifest
	mBlock, err := corenet.GlobalBlockService.GetBlock(ctx, mCID)
	if err != nil {
		fmt.Printf("[Replication Error] Failed to fetch manifest: %v\n", err)
		return
	}

	var manifest corestore.FileManifest
	if err := json.Unmarshal(mBlock.RawData(), &manifest); err != nil {
		fmt.Printf("[Replication Error] Failed to parse manifest: %v\n", err)
		return
	}

	// 2. Fetch all chunks (This automatically pulls them to the Relay's Blockstore)
	fmt.Printf("[Replication] Fetching %d chunks to local cache...\n", len(manifest.Chunks))
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

	fmt.Printf("[Replication Success] Cached %d/%d chunks for %s!\n", fetched, len(manifest.Chunks), manifest.Name)
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

			switch event.Type {
			case "MAILBOX_ADD":
				fmt.Printf("[Cluster] Syncing mailbox message for %s\n", event.OwnerID)
				corestore.SaveMailboxMessage(event.Hash, event.OwnerID, event.Sender, event.Payload)
			case "MAILBOX_PURGE":
				fmt.Printf("[Cluster] Purging message %s from cluster\n", event.Hash)
				corestore.DeleteMailboxMessageByHash(event.Hash)
			case "PREKEY_ADD":
				// BUG-07 FIX: Replicate pre-keys across relay nodes
				if event.OwnerID != "" && event.Hash != "" && event.Payload != "" {
					// event.Hash = KeyID, event.Payload = PublicKey, event.Sender = Signature
					err := corestore.SavePreKey(event.OwnerID, event.Hash, event.Payload, "", event.Sender)
					if err == nil {
						fmt.Printf("[Cluster] Synced pre-key for %s (KeyID: %s)\n", event.OwnerID[:8], event.Hash[:8])
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
		s, err := h.NewStream(ctx, p, ReplicationProtocol)
		if err == nil {
			_, _ = s.Write([]byte(manifestCID))
			s.Close()
			count++
		}
	}
	if count > 0 {
		fmt.Printf("[Replication] Sent replication request to %d relays.\n", count)
	}
}
