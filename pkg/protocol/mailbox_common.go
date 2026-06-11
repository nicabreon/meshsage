package protocol

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
)

type CachedMailboxPeers struct {
	Peers      []peer.ID
	LastUpdate time.Time
}

var MailboxPeersCache sync.Map // map[peer.ID]CachedMailboxPeers

func GetMailboxCoordinate(targetID peer.ID) string {
	hash := sha256.Sum256([]byte(targetID.String() + "mailbox"))
	return fmt.Sprintf("%x", hash)
}

func PrefetchMailboxCoords(targetID peer.ID) {
	if corenet.GlobalDHT == nil {
		return
	}
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
