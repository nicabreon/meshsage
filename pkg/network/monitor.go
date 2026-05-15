package network

import (
	"context"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/nicabreon/meshsage/pkg/logger"
)

var (
	// IsClientOnly is a manual override set by the user
	IsClientOnly bool = false

	// IsNetworkWeak is automatically determined by the monitor
	IsNetworkWeak bool = false

	// MaxLatencyThreshold defines what we consider a "good" connection for relaying
	MaxLatencyThreshold = 500 * time.Millisecond

	// IsDedicated is set for infrastructure nodes
	IsDedicated bool = false
)

func StartNetworkMonitor(ctx context.Context, h host.Host) {
	ticker := time.NewTicker(30 * time.Second)
	ps := ping.NewPingService(h)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkNetworkQuality(ctx, h, ps)
			}
		}
	}()
}

func checkNetworkQuality(ctx context.Context, h host.Host, ps *ping.PingService) {
	peers := h.Network().Peers()
	if len(peers) == 0 {
		return
	}

	var totalLatency time.Duration
	count := 0

	for _, p := range peers {
		pCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		res := <-ps.Ping(pCtx, p)
		cancel()

		if res.Error == nil {
			totalLatency += res.RTT
			count++
		}
	}

	if count > 0 {
		avgLatency := totalLatency / time.Duration(count)
		if avgLatency > 500*time.Millisecond && !IsClientOnly {
			IsClientOnly = true
			logger.Warn().Dur("avg_rtt", avgLatency).Msg("Network quality degraded. Switching to Client-Only mode")
		} else if avgLatency < 200*time.Millisecond && IsClientOnly && !IsDedicated {
			IsClientOnly = false
			logger.Info().Dur("avg_rtt", avgLatency).Msg("Network quality improved. Enabling Hybrid Mesh features")
		}
	}
}

func RunDetailedPeerMonitor(ctx context.Context, h host.Host, relaySource chan<- peer.AddrInfo) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers := h.Network().Peers()
			
			selfRole := "Hybrid"
			if IsDedicated {
				selfRole = "Dedicated Relay"
			} else if IsClientOnly {
				selfRole = "Client Only"
			}

			logger.Info().
				Int("total_peers", len(peers)).
				Str("self_role", selfRole).
				Msg("--- NETWORK STATUS REPORT ---")

			for _, p := range peers {
				role := "Client Only"
				protos, _ := h.Peerstore().GetProtocols(p)
				
				hasInfra := false
				hasDedicated := false
				
				for _, proto := range protos {
					pStr := string(proto)
					if pStr == "/p2p-core/infra/1.1.0" {
						hasInfra = true
					}
					if pStr == "/p2p-core/infra/dedicated/1.1.0" {
						hasDedicated = true
					}
				}

				if hasDedicated {
					role = "Dedicated Relay"
					// OTOMATISASI: Daftarkan sebagai kandidat Relay baru!
					if relaySource != nil {
						pinfo := h.Peerstore().PeerInfo(p)
						if len(pinfo.Addrs) > 0 {
							select {
							case relaySource <- pinfo:
								logger.Info().Str("peerID", p.String()).Msg("New Dedicated Relay registered as AutoRelay candidate")
							default:
								// Channel penuh atau tidak ada yang baca
							}
						}
					}
				} else if hasInfra {
					role = "Hybrid Relay"
				} else {
					role = "Client Only"
				}

				addrList := h.Peerstore().Addrs(p)
				var declaredAddrs []string
				for _, a := range addrList {
					declaredAddrs = append(declaredAddrs, a.String())
				}

				// Ambil alamat koneksi aktif (IP asli yang dilihat VPS)
				var activeAddrs []string
				conns := h.Network().ConnsToPeer(p)
				for _, conn := range conns {
					activeAddrs = append(activeAddrs, conn.RemoteMultiaddr().String())
				}

				// Analisis tipe koneksi
				connType := "Unknown"
				if len(activeAddrs) > 0 {
					mainConn := activeAddrs[0]
					if strings.Contains(mainConn, "/p2p-circuit") {
						connType = "RELAYED (Circuit)"
					} else if strings.Contains(mainConn, "/quic-v1") {
						connType = "DIRECT (QUIC/UDP)"
					} else if strings.Contains(mainConn, "/tcp") {
						connType = "DIRECT (TCP)"
					}
				}

				logger.Info().
					Str("peerID", p.String()).
					Str("role", role).
					Str("connType", connType).
					Interface("declared_addrs", declaredAddrs).
					Interface("active_conns", activeAddrs).
					Msg("Connected Peer Detail")
			}
		}
	}
}

func ShouldActAsRelay() bool {
	return !IsClientOnly && !IsNetworkWeak
}
