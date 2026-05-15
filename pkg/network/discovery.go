package network

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/nicabreon/meshsage/pkg/logger"
)

// DiscoveryServiceTag is the identifier for our application on the local network
const DiscoveryServiceTag = "p2p-core-messaging"

// mdnsNotifee gets notified when we find a new peer via mDNS
type mdnsNotifee struct {
	h host.Host
}

// HandlePeerFound connects to peers discovered via mDNS
func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() { return }
	logger.Debug().Str("peerID", pi.ID.String()).Msg("mDNS: Found local peer")
	
	// Automatically connect to the discovered peer
	err := n.h.Connect(context.Background(), pi)
	if err != nil {
		logger.Debug().Err(err).Str("peerID", pi.ID.String()).Msg("mDNS: Connection failed")
	} else {
		logger.Info().Str("peerID", pi.ID.String()).Msg("mDNS: Successfully connected to local peer")
	}
}

// SetupDiscovery sets up mDNS discovery to automatically find local peers
func SetupDiscovery(h host.Host) error {
	// Register the notifee
	n := &mdnsNotifee{h: h}
	
	// Create the mDNS service
	s := mdns.NewMdnsService(h, DiscoveryServiceTag, n)
	
	// Start the service
	return s.Start()
}
