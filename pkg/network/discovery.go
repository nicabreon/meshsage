package network

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/nicabreon/meshsage/pkg/logger"
)

// DiscoveryServiceTag is the identifier for our application on the local and global network
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

// SetupDiscovery sets up mDNS discovery to automatically find local peers, and DHT routing discovery for global peers
func SetupDiscovery(h host.Host) error {
	// 1. Setup mDNS Service
	n := &mdnsNotifee{h: h}
	s := mdns.NewMdnsService(h, DiscoveryServiceTag, n)
	if err := s.Start(); err != nil {
		logger.Error().Err(err).Msg("Failed to start mDNS service")
	}

	// 2. Setup DHT Rendezvous Discovery in the background
	go func() {
		// Wait for DHT bootstrapping to start
		time.Sleep(5 * time.Second)
		ctx := context.Background()

		for {
			// Don't advertise/discover if the network node is stopping
			if h.Network().Peers() == nil {
				return
			}

			if GlobalDHT != nil {
				routingDisc := routing.NewRoutingDiscovery(GlobalDHT)
				
				// A. Advertise our presence on the DHT
				logger.Debug().Msg("DHT Discovery: Advertising our presence to the swarm...")
				routingDisc.Advertise(ctx, DiscoveryServiceTag, discovery.TTL(10*time.Minute))
				
				// B. Find other peers advertising on the DHT
				peerChan, err := routingDisc.FindPeers(ctx, DiscoveryServiceTag, discovery.Limit(15))
				if err == nil {
					for pinfo := range peerChan {
						if pinfo.ID == h.ID() {
							continue
						}
						
						// Connect if not already connected
						if h.Network().Connectedness(pinfo.ID) != network.Connected {
							logger.Info().Str("peerID", pinfo.ID.String()).Msg("DHT Discovery: Attempting connection to discovered peer")
							
							// Run dial in a separate goroutine so it doesn't block the channel reader
							go func(pi peer.AddrInfo) {
								dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
								defer cancel()
								
								errDial := h.Connect(dialCtx, pi)
								if errDial == nil {
									logger.Info().Str("peerID", pi.ID.String()).Msg("DHT Discovery: Successfully connected")
								} else {
									logger.Debug().Err(errDial).Str("peerID", pi.ID.String()).Msg("DHT Discovery: Connection failed")
								}
							}(pinfo)
						}
					}
				}
			}
			
			// Poll peer discovery every 45 seconds
			time.Sleep(45 * time.Second)
		}
	}()

	return nil
}
