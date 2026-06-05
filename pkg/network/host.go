package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"encoding/json"
	"runtime"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/multiformats/go-multiaddr"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	"github.com/nicabreon/meshsage/pkg/logger"
)

// Config holds the configuration for the P2P node
type Config struct {
	ListenAddr     string
	PrivateKey     crypto.PrivKey
	BootstrapPeers []peer.AddrInfo
	StaticRelays   []peer.AddrInfo
	RelaySource    chan peer.AddrInfo
	DataDir        string // Folder untuk menyimpan peers.datastore
	ForcePublic    bool   // Paksa status keterjangkauan publik (khusus Relay)
}

// NewNode creates a new libp2p host.
func NewNode(ctx context.Context, cfg Config) (host.Host, error) {
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// 0. Connection Manager (The "Bouncer")
	// Limits active connections to save CPU/Battery/Bandwidth
	cm, err := connmgr.NewConnManager(
		100,  // Low Watermark: Minimal connections to keep
		1000, // High Watermark: Max connections (will start pruning above this)
		connmgr.WithGracePeriod(time.Minute*2),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// 0.1 Resource Manager (The "Security Guard")
	// Scale default limits by 10x to support 10k+ connections and more conns per IP
	limitConfig := rcmgr.DefaultLimits.Scale(10, 10)
	limiter := rcmgr.NewFixedLimiter(limitConfig)
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager: %w", err)
	}

	portStr := "0"
	parts := strings.Split(cfg.ListenAddr, "/")
	if len(parts) >= 5 {
		portStr = parts[4]
	}

	// isAndroid detects if running on Android (for SELinux-safe configuration)
	isAndroid := runtime.GOOS == "android"

	opts := []libp2p.Option{
		// 1. Identity
		libp2p.Identity(cfg.PrivateKey),
		// 2. Connection Management & Resource Limits
		libp2p.ConnectionManager(cm),
		libp2p.ResourceManager(rm),
		// 3. Listen Addresses — dual transport: QUIC + WebRTC Direct
		//    QUIC: configured port (UDP)
		//    WebRTC Direct: port 0 (kernel assigns random UDP port)
		//    Note: QUIC and WebRTC cannot share the same UDP socket,
		//    so WebRTC uses a separate port.
		libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/0.0.0.0/udp/%s/quic-v1", portStr),
			"/ip4/0.0.0.0/udp/0/webrtc-direct",
		),
		// 4. Transports
		//    QUIC: mature, low-latency UDP transport
		//    WebRTC Direct: ICE-based, no external STUN configured — uses host
		//    candidates only. Falls back to libp2p circuit relay (not STUN/TURN).
		//    pion/webrtc is pure Go (no CGo) — safe for Android NDK cross-compile.
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.EnableRelay(),
		// 5. Address Factory: advertise known addresses
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			return addrs
		}),
	}

	// 6. NAT Traversal configuration (Android-aware)
	//
	// NATPortMap()    — UPnP/NAT-PMP via netlink socket — BLOCKED on Android API 36+
	//                   by SELinux (untrusted_app cannot bind netlink_route_socket).
	//                   Disabling prevents permanent startup hang on Android emulator/device.
	//
	// EnableNATService() — AutoNAT probe via netlink — also BLOCKED on Android API 36+.
	//                      Disabled on Android for same reason.
	//
	// EnableHolePunching() — DCUtR (Direct Connection Upgrade through Relay).
	//                        Uses existing libp2p relay connections, NO netlink needed.
	//                        SAFE and IMPORTANT for Android P2P direct connections.
	//                        Always enabled on all platforms including Android.
	if !isAndroid {
		opts = append(opts,
			libp2p.NATPortMap(),        // UPnP/NAT-PMP (requires netlink — desktop only)
			libp2p.EnableNATService(),  // AutoNAT probe (requires netlink — desktop only)
		)
	}
	// DCUtR Hole Punching: relay-based, safe on Android — always enabled
	opts = append(opts, libp2p.EnableHolePunching())

	// Paksa status publik/privat berdasarkan jenis node dan ketersediaan IP publik asli
	if cfg.ForcePublic {
		opts = append(opts, libp2p.ForceReachabilityPublic(), libp2p.EnableRelayService())
	} else if !hasPublicIP() {
		// Paksa client menjadi ReachabilityPrivate agar AutoRelay langsung melakukan reservasi ke Relay Server
		opts = append(opts, libp2p.ForceReachabilityPrivate())
	}

	// Tambahkan AutoRelay dengan sumber dinamis
	if cfg.RelaySource != nil {
		peerSource := func(ctx context.Context, num int) <-chan peer.AddrInfo {
			return cfg.RelaySource
		}
		opts = append(opts, libp2p.EnableAutoRelayWithPeerSource(peerSource))

		// Kirim relay statis awal ke channel agar langsung terdeteksi
		go func() {
			for _, r := range cfg.StaticRelays {
				select {
				case cfg.RelaySource <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Create the libp2p host
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Explicitly add private key to Peerstore to guarantee h.Peerstore().PrivKey(h.ID()) is never nil
	if cfg.PrivateKey != nil {
		_ = h.Peerstore().AddPrivKey(h.ID(), cfg.PrivateKey)
	}

	// Audit: Print our own addresses periodically and on changes
	printAddrs := func() {
		for _, addr := range h.Addrs() {
			logger.Info().Str("addr", addr.String()).Msg("Node is listening/observed on")
		}
	}
	printAddrs()

	go func() {
		sub, _ := h.EventBus().Subscribe(new(event.EvtLocalAddressesUpdated))
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sub.Out():
				logger.Info().Msg("Network addresses updated (Public IP discovered?)")
				printAddrs()
			}
		}
	}()

	// 6. Persistence Management
	if cfg.DataDir != "" {
		// Load peers in the background — never block host creation.
		// On reinstall-without-uninstall, peers.json may have I/O contention.
		go LoadPeers(h, cfg.DataDir)
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					SavePeers(h, cfg.DataDir)
				}
			}
		}()
	}

	return h, nil
}

// SavePeers exports known addresses to a JSON file
func SavePeers(h host.Host, dataDir string) {
	peers := make(map[string][]string)
	for _, p := range h.Peerstore().Peers() {
		// Ambil semua alamat yang pernah diketahui untuk peer ini
		addrs := h.Peerstore().Addrs(p)
		if len(addrs) > 0 {
			var addrStrings []string
			for _, a := range addrs {
				addrStrings = append(addrStrings, a.String())
			}
			peers[p.String()] = addrStrings
		}
	}

	data, _ := json.MarshalIndent(peers, "", "  ")
	err := os.WriteFile(dataDir+"/peers.json", data, 0644)
	if err == nil && len(peers) > 0 {
		logger.Debug().Int("count", len(peers)).Msg("Saved peer addresses to persistent storage")
	}
}

// LoadPeers imports addresses from a JSON file
func LoadPeers(h host.Host, dataDir string) {
	filePath := dataDir + "/peers.json"
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	var peers map[string][]string
	if err := json.Unmarshal(data, &peers); err != nil {
		return
	}

	count := 0
	for idStr, addrs := range peers {
		p, err := peer.Decode(idStr)
		if err != nil {
			continue
		}
		for _, aStr := range addrs {
			maddr, err := multiaddr.NewMultiaddr(aStr)
			if err != nil {
				continue
			}
			h.Peerstore().AddAddr(p, maddr, peerstore.AddressTTL)
			count++
		}
	}
	if count > 0 {
		logger.Info().Int("count", count).Msg("Loaded peer addresses from persistent storage")
	}
}

// hasPublicIP mengecek apakah ada interface lokal yang memiliki alamat IP publik global.
func hasPublicIP() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			// Check private ranges (RFC 1918)
			if ip4[0] == 10 {
				continue
			}
			if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
				continue
			}
			if ip4[0] == 192 && ip4[1] == 168 {
				continue
			}
			// Carrier-grade NAT (RFC 6598)
			if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
				continue
			}
			return true // Found public IPv4
		} else {
			// IPv6
			// Skip unique local unicast (fc00::/7)
			if len(ip) >= 16 && (ip[0]&0xfe) == 0xfc {
				continue
			}
			return true // Found public IPv6
		}
	}
	return false
}

