package network

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/nicabreon/meshsage/pkg/logger"
)

// HasActiveSessionFn is a callback injected from the storage package to check if a peer ID has an active Double Ratchet chat session.
// This resolves the import cycle between storage and network packages.
var HasActiveSessionFn func(peerID string) bool

var explicitAllowedPeers sync.Map // map[peer.ID]struct{}

// AllowPeerExplicitly registers a peer ID to be temporarily allowed by the connection gater.
func AllowPeerExplicitly(p peer.ID) {
	explicitAllowedPeers.Store(p, struct{}{})
}

// RemoveExplicitPeer removes a peer ID from the explicitly allowed list.
func RemoveExplicitPeer(p peer.ID) {
	explicitAllowedPeers.Delete(p)
}

type RestrictedConnectionGater struct {
	h                    host.Host
	staticSeeds          map[peer.ID]struct{}
	connectedRelaysCount int32
}

var _ connmgr.ConnectionGater = (*RestrictedConnectionGater)(nil)

func NewRestrictedConnectionGater(staticRelays []peer.AddrInfo) *RestrictedConnectionGater {
	seeds := make(map[peer.ID]struct{})
	for _, r := range staticRelays {
		seeds[r.ID] = struct{}{}
	}
	return &RestrictedConnectionGater{
		staticSeeds: seeds,
	}
}

func (g *RestrictedConnectionGater) Start(h host.Host) {
	g.h = h
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			if h.Network() == nil {
				return
			}
			count := 0
			for _, p := range h.Network().Peers() {
				protos, err := h.Peerstore().GetProtocols(p)
				if err == nil {
					for _, proto := range protos {
						if string(proto) == "/p2p-core/infra/dedicated/1.1.0" {
							count++
							break
						}
					}
				}
			}
			atomic.StoreInt32(&g.connectedRelaysCount, int32(count))

			select {
			case <-ticker.C:
			}
		}
	}()
}

func (g *RestrictedConnectionGater) isAllowed(p peer.ID) bool {
	// Jika bukan mode client-only, matikan batasan gater ini
	if !IsClientOnly {
		return true
	}

	// 0. Izinkan jika peer di-dial secara eksplisit (misal untuk ConnectPeer atau Resolve)
	if _, ok := explicitAllowedPeers.Load(p); ok {
		return true
	}

	// Jika host belum selesai diinisialisasi, izinkan koneksi (mencegah blokir saat libp2p.New)
	if g.h == nil {
		return true
	}

	// 1. Izinkan jika peer adalah static seed
	if _, ok := g.staticSeeds[p]; ok {
		return true
	}

	// 2. Izinkan jika peer memiliki sesi chat aktif di SQLite
	if g.hasActiveSession(p) {
		return true
	}

	// 3. Izinkan jika peer adalah Dedicated Relay terdaftar
	if g.h != nil {
		protos, err := g.h.Peerstore().GetProtocols(p)
		if err == nil {
			for _, proto := range protos {
				if string(proto) == "/p2p-core/infra/dedicated/1.1.0" {
					return true
				}
			}
		}
	}

	// 3.5. Izinkan jika peer memiliki alamat IP publik (potensial Dedicated/Hybrid Relay)
	if g.h != nil {
		addrs := g.h.Peerstore().Addrs(p)
		if len(addrs) > 0 && HasPublicAddr(addrs) {
			return true
		}
	}

	// 3.6. Izinkan jika peer memiliki alamat loopback/localhost (untuk development/testing lokal)
	if g.h != nil {
		addrs := g.h.Peerstore().Addrs(p)
		if len(addrs) > 0 && HasLoopbackAddr(addrs) {
			return true
		}
	}

	// 3.7. Izinkan jika peer memiliki alamat relay (/p2p-circuit) di peerstore
	if g.h != nil {
		addrs := g.h.Peerstore().Addrs(p)
		for _, addr := range addrs {
			if strings.Contains(addr.String(), "/p2p-circuit") {
				return true
			}
		}
	}

	// 4. Fallback: Jika tidak terhubung ke dedicated relay mana pun, izinkan koneksi terbuka untuk mencari relay
	if g.h != nil && g.countConnectedDedicatedRelays() == 0 {
		return true
	}

	return false
}

// HasLoopbackAddr mengecek apakah slice multiaddr mengandung alamat loopback/localhost
func HasLoopbackAddr(addrs []multiaddr.Multiaddr) bool {
	for _, addr := range addrs {
		addrStr := addr.String()
		if strings.Contains(addrStr, "127.0.0.1") || strings.Contains(addrStr, "localhost") || strings.Contains(addrStr, "::1") {
			return true
		}
		ip := extractIP(addr)
		if ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

func (g *RestrictedConnectionGater) hasActiveSession(p peer.ID) bool {
	if HasActiveSessionFn != nil {
		return HasActiveSessionFn(p.String())
	}
	return false
}

func (g *RestrictedConnectionGater) countConnectedDedicatedRelays() int {
	return int(atomic.LoadInt32(&g.connectedRelaysCount))
}

func (g *RestrictedConnectionGater) InterceptPeerDial(p peer.ID) bool {
	allowed := g.isAllowed(p)
	if !allowed {
		logger.Warn().Str("peerID", p.String()).Msg("[Gater] Blocked outgoing peer dial (non-relayed/non-contact peer)")
	}
	return allowed
}

func (g *RestrictedConnectionGater) InterceptAddrDial(p peer.ID, addr multiaddr.Multiaddr) bool {
	addrStr := addr.String()
	if strings.Contains(addrStr, "/p2p-circuit") {
		return true
	}
	if strings.Contains(addrStr, "127.0.0.1") || strings.Contains(addrStr, "localhost") || strings.Contains(addrStr, "::1") {
		return true
	}
	ip := extractIP(addr)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return g.isAllowed(p)
}

func (g *RestrictedConnectionGater) InterceptAccept(c network.ConnMultiaddrs) bool {
	return true
}

func (g *RestrictedConnectionGater) InterceptSecured(dir network.Direction, p peer.ID, c network.ConnMultiaddrs) bool {
	if dir == network.DirInbound {
		return true // Always allow inbound connections so new peers can contact us / establish session
	}
	return g.isAllowed(p)
}

func (g *RestrictedConnectionGater) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}
