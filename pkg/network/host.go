package network

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	"github.com/multiformats/go-multiaddr"
	"github.com/nicabreon/meshsage/pkg/logger"
	pion_stun "github.com/pion/stun/v3"
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
	IsDedicated    bool
	IsClientOnly   bool
	EnableRelay    bool // Mengaktifkan libp2p relay client & AutoRelay
}

// discoveredPublicIP holds the external IP discovered via STUN (thread-safe).
var (
	discoveredPublicIPMu sync.RWMutex
	discoveredPublicIP   net.IP
	GlobalHost           host.Host
	GlobalBWC            *metrics.BandwidthCounter
)

// discoverPublicIPAsync queries a STUN server asynchronously to find our external/NAT-mapped IP.
// Once discovered, it stores in discoveredPublicIP and triggers an address refresh via the emitter.
func discoverPublicIPAsync(h host.Host) {
	// List of public STUN servers to try in order
	stunServers := []string{
		"103.127.138.103:3478", // Custom STUN server (priority)
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun.cloudflare.com:3478",
	}

	// Create an emitter to signal address updates to libp2p internals
	emitter, err := h.EventBus().Emitter(new(event.EvtLocalAddressesUpdated))
	if err != nil {
		logger.Warn().Err(err).Msg("STUN: failed to create address update emitter, updates won't propagate")
		emitter = nil
	}

	go func() {
		if emitter != nil {
			defer emitter.Close()
		}
		for _, server := range stunServers {
			ip, err := querySTUN(server)
			if err != nil {
				logger.Debug().Str("server", server).Err(err).Msg("STUN: query failed, trying next")
				continue
			}
			logger.Info().Str("external_ip", ip.String()).Str("via", server).Msg("STUN: discovered external IP")
			discoveredPublicIPMu.Lock()
			discoveredPublicIP = ip
			discoveredPublicIPMu.Unlock()

			// Signal libp2p that our addresses have changed (triggers AddrsFactory re-evaluation)
			if emitter != nil {
				_ = emitter.Emit(event.EvtLocalAddressesUpdated{})
			}
			return
		}
		logger.Warn().Msg("STUN: all servers failed, will rely on relay addresses for reachability")
	}()
}

// querySTUN sends a STUN Binding Request and returns the XOR-MAPPED-ADDRESS IP.
func querySTUN(server string) (net.IP, error) {
	conn, err := net.DialTimeout("udp", server, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	msg := pion_stun.MustBuild(pion_stun.TransactionID, pion_stun.BindingRequest)
	_, err = conn.Write(msg.Raw)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var resp pion_stun.Message
	resp.Raw = buf[:n]
	if err := resp.Decode(); err != nil {
		return nil, err
	}

	var xorAddr pion_stun.XORMappedAddress
	if err := xorAddr.GetFrom(&resp); err != nil {
		// Try MAPPED-ADDRESS as fallback
		var mappedAddr pion_stun.MappedAddress
		if err2 := mappedAddr.GetFrom(&resp); err2 != nil {
			return nil, fmt.Errorf("no mapped address in STUN response: %v", err)
		}
		return mappedAddr.IP, nil
	}
	return xorAddr.IP, nil
}

func getSystemTotalMemory() uint64 {
	// Fallback/default to 2GB in bytes
	var defaultMem uint64 = 2 * 1024 * 1024 * 1024

	switch runtime.GOOS {
	case "linux":
		file, err := os.Open("/proc/meminfo")
		if err != nil {
			return defaultMem
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					val, err := strconv.ParseUint(parts[1], 10, 64)
					if err == nil {
						return val * 1024 // /proc/meminfo is in kB
					}
				}
			}
		}
	}
	// On macOS or other systems, scale memory linearly by NumCPU as an approximation for local testing/simulation
	cpus := runtime.NumCPU()
	if cpus > 8 {
		cpus = 8
	}
	return uint64(cpus) * 2 * 1024 * 1024 * 1024
}

func autoDetectRelayLimits() (lowWater, highWater int, rcmgrScale int, maxReservations int) {
	cpus := runtime.NumCPU()
	ramBytes := getSystemTotalMemory()
	ramGB := ramBytes / (1024 * 1024 * 1024)

	logger.Info().
		Int("cpus", cpus).
		Uint64("ram_gb", ramGB).
		Msg(">>> HARDWARE AUTO-DETECTION: Estimating Dedicated Relay capacities")

	// TIER 3: Skala Besar (>= 8 Cores ATAU >= 16 GB RAM)
	if cpus >= 8 || ramGB >= 16 {
		logger.Info().Msg(">>> AUTO-LIMITS: Selected TIER 3 (Large Scale Relay). Scaling up to 20,000 connections / 30,000 sirkuit.")
		return 15000, 20000, 150, 30000
	}

	// TIER 2: Skala Menengah (>= 4 Cores ATAU >= 4 GB RAM)
	if cpus >= 4 || ramGB >= 4 {
		logger.Info().Msg(">>> AUTO-LIMITS: Selected TIER 2 (Medium Scale Relay). Scaling up to 8,000 connections / 10,000 sirkuit.")
		return 5000, 8000, 50, 10000
	}

	// TIER 1: Skala Kecil (Bawaan / VPS murah)
	logger.Info().Msg(">>> AUTO-LIMITS: Selected TIER 1 (Small Scale Relay). Scaling up to 1,000 connections / 1,000 sirkuit.")
	return 500, 1000, 10, 1000
}

// NewNode creates a new libp2p host.
func NewNode(ctx context.Context, cfg Config) (host.Host, error) {
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// isAndroid detects if running on Android (for SELinux-safe configuration)
	isAndroid := runtime.GOOS == "android"

	// Set global mode variables based on config
	IsDedicated = cfg.IsDedicated
	IsClientOnly = cfg.IsClientOnly

	// 0. Connection Manager (The "Bouncer")
	// Limits active connections to save CPU/Battery/Bandwidth
	lowWater := 100
	highWater := 1000
	rcmgrScale := 10
	maxReservations := 1000

	if IsClientOnly || isAndroid {
		lowWater = 15
		highWater = 40
		rcmgrScale = 1
	} else if IsDedicated {
		lowWater, highWater, rcmgrScale, maxReservations = autoDetectRelayLimits()
	}

	cm, err := connmgr.NewConnManager(
		lowWater,
		highWater,
		connmgr.WithGracePeriod(time.Minute*2),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// 0.1 Resource Manager (The "Security Guard")
	var limitConfig rcmgr.ConcreteLimitConfig
	if IsClientOnly || isAndroid {
		// Use default concrete limits (scale by 1x)
		limitConfig = rcmgr.DefaultLimits.Scale(1, 1)
	} else {
		// Scale default limits dynamically to support scaling connections (Relay/Server only)
		limitConfig = rcmgr.DefaultLimits.Scale(int64(rcmgrScale), rcmgrScale)
	}
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

	gater := NewRestrictedConnectionGater(cfg.StaticRelays)

	opts := []libp2p.Option{
		// 1. Identity
		libp2p.Identity(cfg.PrivateKey),
		// 2. Connection Management & Resource Limits
		libp2p.ConnectionManager(cm),
		libp2p.ResourceManager(rm),
		// 2.1 Connection Gater to enforce client-only network whitelist
		libp2p.ConnectionGater(gater),
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
		//    WebRTC Direct: ICE-based, uses host candidates + STUN-discovered public IP.
		//    pion/webrtc is pure Go (no CGo) — safe for Android NDK cross-compile.
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(libp2pwebrtc.New),
		// 5. Address Factory: filter out loopback & link-local, inject STUN-discovered public IP
		libp2p.AddrsFactory(filterAddrsWithSTUN),
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
			libp2p.NATPortMap(),       // UPnP/NAT-PMP (requires netlink — desktop only)
			libp2p.EnableNATService(), // AutoNAT probe (requires netlink — desktop only)
		)
	}
	// DCUtR Hole Punching: relay-based, safe on Android — always enabled
	opts = append(opts, libp2p.EnableHolePunching())

	// Conditionally enable Relay Client functionality (never enabled for Dedicated Relay)
	if cfg.EnableRelay && !cfg.IsDedicated {
		opts = append(opts, libp2p.EnableRelay())
	}

	// Configure Dedicated Relay custom service limits
	var relayOpts []relay.Option
	if IsDedicated {
		resources := relay.DefaultResources()
		resources.MaxReservations = maxReservations
		resources.MaxCircuits = maxReservations / 2
		resources.BufferSize = 65536 // 64KB buffers for high throughput relaying
		resources.MaxReservationsPerPeer = 4
		resources.MaxReservationsPerIP = 8

		relayOpts = append(relayOpts, relay.WithResources(resources))
		logger.Info().
			Int("max_reservations", resources.MaxReservations).
			Int("max_circuits", resources.MaxCircuits).
			Msg(">>> RELAY SERVICE: Configured custom resource manager limits")
	}

	// Paksa status publik/privat berdasarkan jenis node dan ketersediaan IP publik asli
	if cfg.ForcePublic {
		opts = append(opts, libp2p.ForceReachabilityPublic(), libp2p.EnableRelayService(relayOpts...))
	} else if !hasPublicIP() {
		// Paksa client menjadi ReachabilityPrivate agar AutoRelay langsung melakukan reservasi ke Relay Server
		opts = append(opts, libp2p.ForceReachabilityPrivate())
	}

	// Tambahkan AutoRelay dengan sumber dinamis jika relay diaktifkan (tidak untuk Dedicated Relay)
	if cfg.EnableRelay && cfg.RelaySource != nil && !cfg.IsDedicated {
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
	GlobalBWC = metrics.NewBandwidthCounter()
	opts = append(opts, libp2p.BandwidthReporter(GlobalBWC))

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}
	GlobalHost = h

	gater.Start(h)

	// Explicitly add private key to Peerstore to guarantee h.Peerstore().PrivKey(h.ID()) is never nil
	if cfg.PrivateKey != nil {
		_ = h.Peerstore().AddPrivKey(h.ID(), cfg.PrivateKey)
	}

	// Audit: Print our own addresses periodically and on changes
	printAddrs := func() {
		addrs := h.Addrs()
		if len(addrs) == 0 {
			logger.Warn().Msg("Node has NO advertised addresses (all filtered). Peers will connect via relay only.")
		} else {
			for _, addr := range addrs {
				logger.Info().Str("addr", addr.String()).Msg("Node is listening/observed on")
			}
		}
	}
	printAddrs()

	// Start STUN discovery in background — will trigger address refresh when done
	discoverPublicIPAsync(h)

	go func() {
		sub, _ := h.EventBus().Subscribe(new(event.EvtLocalAddressesUpdated))
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sub.Out():
				logger.Info().Msg("Network addresses updated")
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

// filterAddrsWithSTUN menghapus loopback/link-local dari address list dan menyuntikkan
// public IP yang ditemukan via STUN (jika ada) sebagai pengganti.
// Jika tidak ada address valid dan tidak ada STUN IP, kembalikan slice kosong —
// relay multiaddr masih akan digunakan oleh AutoRelay untuk konektivitas.
//
// Setiap alamat LAN (per-transport) mendapatkan pasangan public IP-nya sendiri,
// menggunakan set deduplication agar tidak ada alamat duplikat dalam satu panggilan.
func filterAddrsWithSTUN(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	// Ambil STUN-discovered public IP (thread-safe)
	discoveredPublicIPMu.RLock()
	stunIP := discoveredPublicIP
	discoveredPublicIPMu.RUnlock()

	var filtered []multiaddr.Multiaddr
	// injectedPublicAddrs tracks public addresses already added this call to prevent duplicates.
	// Unlike the old stunInjected bool, this allows *each* LAN transport (quic-v1, webrtc-direct, etc.)
	// to get its own corresponding public IP entry.
	injectedPublicAddrs := make(map[string]struct{})

	for _, addr := range addrs {
		addrStr := addr.String()

		// Selalu pertahankan circuit relay dan p2p-webrtc-star (kecuali jika Dedicated Relay)
		if strings.Contains(addrStr, "/p2p-circuit") ||
			strings.Contains(addrStr, "/p2p-webrtc-star") {
			if !IsDedicated {
				filtered = append(filtered, addr)
			}
			continue
		}

		// Ekstrak komponen ip4/ip6 dari multiaddr
		ip := extractIP(addr)
		if ip == nil {
			// Bukan alamat IP (misal /dns4, /dns6) — pertahankan
			filtered = append(filtered, addr)
			continue
		}

		// Buang loopback (127.0.0.1, ::1)
		if ip.IsLoopback() {
			logger.Debug().Str("addr", addrStr).Msg("AddrsFactory: skipping loopback address")
			continue
		}

		// Buang link-local (169.254.x.x, fe80::)
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			logger.Debug().Str("addr", addrStr).Msg("AddrsFactory: skipping link-local address")
			continue
		}

		// Buang unspecified (0.0.0.0, ::) — gantikan dengan STUN IP jika tersedia
		if ip.IsUnspecified() {
			logger.Debug().Str("addr", addrStr).Msg("AddrsFactory: skipping unspecified address")
			if stunIP != nil {
				newAddr := replaceIP(addr, stunIP)
				if newAddr != nil {
					newAddrStr := newAddr.String()
					if _, dup := injectedPublicAddrs[newAddrStr]; !dup {
						logger.Debug().Str("addr", newAddrStr).Msg("AddrsFactory: injecting STUN-discovered public IP (replacing unspecified)")
						filtered = append(filtered, newAddr)
						injectedPublicAddrs[newAddrStr] = struct{}{}
					}
				}
			}
			continue
		}

		// Pertahankan semua yang lain: LAN (10.x, 172.16-31.x, 192.168.x), publik, dll.
		logger.Debug().Str("addr", addrStr).Msg("AddrsFactory: advertising address")
		filtered = append(filtered, addr)

		// Untuk setiap alamat LAN, tambahkan pasangan public IP via STUN sebagai extra address.
		// Tidak menggunakan flag boolean agar quic-v1 DAN webrtc-direct keduanya mendapat public IP.
		if stunIP != nil && !ip.Equal(stunIP) && isPrivateIP(ip) {
			newAddr := replaceIP(addr, stunIP)
			if newAddr != nil {
				newAddrStr := newAddr.String()
				if _, dup := injectedPublicAddrs[newAddrStr]; !dup {
					logger.Debug().Str("addr", newAddrStr).Msg("AddrsFactory: adding STUN public IP alongside LAN address")
					filtered = append(filtered, newAddr)
					injectedPublicAddrs[newAddrStr] = struct{}{}
				}
			}
		}
	}

	// PENTING: Jangan fallback ke loopback jika tidak ada yang lolos filter.
	// Konektivitas tetap terjaga via relay (p2p-circuit) yang dikelola AutoRelay.
	if len(filtered) == 0 {
		var checkedStr []string
		for _, addr := range addrs {
			checkedStr = append(checkedStr, addr.String())
		}
		logger.Warn().
			Interface("checked_addrs", checkedStr).
			Msg("AddrsFactory: no reachable addresses found. Peers will connect via relay only.")
	}
	return filtered

}

// replaceIP menggantikan komponen IP dalam multiaddr dengan ip baru.
// Membangun ulang multiaddr dengan mengganti segmen ip4/ip6 awal.
func replaceIP(addr multiaddr.Multiaddr, newIP net.IP) multiaddr.Multiaddr {
	var proto int
	var suffix []multiaddr.Multiaddr
	found := false

	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		if !found && (c.Protocol().Code == multiaddr.P_IP4 || c.Protocol().Code == multiaddr.P_IP6) {
			proto = c.Protocol().Code
			found = true
			return true
		}
		if found {
			maddr, err := multiaddr.NewMultiaddrBytes(c.Bytes())
			if err == nil {
				suffix = append(suffix, maddr)
			}
		}
		return true
	})

	if !found {
		return nil
	}

	var prefix multiaddr.Multiaddr
	var err error
	if proto == multiaddr.P_IP4 {
		ip4 := newIP.To4()
		if ip4 == nil {
			return nil // STUN returned IPv6 but addr is IPv4 template
		}
		prefix, err = multiaddr.NewMultiaddr("/ip4/" + ip4.String())
	} else {
		ip6 := newIP.To16()
		if ip6 == nil {
			return nil
		}
		prefix, err = multiaddr.NewMultiaddr("/ip6/" + ip6.String())
	}
	if err != nil {
		return nil
	}

	result := prefix
	for _, s := range suffix {
		result = result.Encapsulate(s)
	}
	return result
}

// isPrivateIP mengecek apakah IP adalah private/LAN address (RFC 1918).
func isPrivateIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return (ip4[0] == 10) ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168) ||
		(ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127)
}

// extractIP mengekstrak net.IP dari multiaddr ip4 atau ip6.
func extractIP(addr multiaddr.Multiaddr) net.IP {
	var ip net.IP
	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case multiaddr.P_IP4:
			ip = net.ParseIP(c.Value())
			return false
		case multiaddr.P_IP6:
			ip = net.ParseIP(c.Value())
			return false
		}
		return true
	})
	return ip
}

// HasPublicAddr mengecek apakah slice multiaddr mengandung alamat IP publik eksternal yang valid
func HasPublicAddr(addrs []multiaddr.Multiaddr) bool {
	for _, addr := range addrs {
		addrStr := addr.String()
		if strings.Contains(addrStr, "/p2p-circuit") {
			continue
		}
		ip := extractIP(addr)
		if ip == nil {
			// Jika alamat berbasis DNS (seperti /dns4/example.com), anggap publik kecuali localhost/.local
			if strings.Contains(addrStr, "/dns") &&
				!strings.Contains(addrStr, "localhost") &&
				!strings.Contains(addrStr, ".local") {
				return true
			}
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if !isPrivateIP(ip) {
			return true
		}
	}
	return false
}
