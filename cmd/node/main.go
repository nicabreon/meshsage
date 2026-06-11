package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/multiformats/go-multiaddr"

	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	coreproto "github.com/nicabreon/meshsage/pkg/protocol"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	coretui "github.com/nicabreon/meshsage/pkg/tui"
)

var (
	DefaultSeeds = []string{
		"/ip4/103.127.138.103/tcp/4004/p2p/12D3KooWFZTmWWGaeNFY7ro95DtiSoV5txAqv6iZCERy6vLWTA95",
		"/ip4/103.127.138.103/udp/4004/quic-v1/p2p/12D3KooWFZTmWWGaeNFY7ro95DtiSoV5txAqv6iZCERy6vLWTA95",
	}
)

func main() {
	port := flag.Int("port", 0, "Listening port (0 for random)")
	targetPeer := flag.String("peer", "", "Target peer multiaddress to connect to")
	isDedicated := flag.Bool("dedicated", false, "Mark this node as a Dedicated Infrastructure Relay")
	forcePublic := flag.Bool("force-public", false, "Force public reachability status (use on VPS)")
	isClientOnly := flag.Bool("client-only", false, "Force node to Client-Only mode")
	idFile := flag.String("identity", "./.data/node.key", "Path to the node identity key file")
	dbFile := flag.String("db", "./.data/node.db", "Path to the database file")
	debug := flag.Bool("debug", false, "Enable detailed debug logging")
	isTUI := flag.Bool("tui", false, "Enable Terminal User Interface (TUI) mode")
	flag.Parse()

	logger.SetDebug(*debug)

	// 1. Identity & Directory Setup
	for _, path := range []string{*idFile, *dbFile} {
		dir := filepath.Dir(path)
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			logger.Error().Err(err).Str("path", dir).Msg("CRITICAL: Failed to create data directory. Permission denied?")
		}
	}

	var priv crypto.PrivKey
	var err error
	if _, err = os.Stat(*idFile); os.IsNotExist(err) {
		logger.Info().Str("path", *idFile).Msg("Generating new node identity")
		priv, _, err = corecrypto.GenerateKeyPair()
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to generate key pair")
		}
		if err := corestore.SavePrivateKey(priv, *idFile); err != nil {
			logger.Fatal().Err(err).Msg("CRITICAL: Failed to save identity. Check path permissions.")
		}
	} else {
		logger.Info().Str("path", *idFile).Msg("Loading existing identity")
		priv, err = corestore.LoadPrivateKey(*idFile)
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to load identity")
		}
	}

	peerID, _ := peer.IDFromPrivateKey(priv)
	logger.Info().Str("peerID", peerID.String()).Msg("Local Identity Initialized")

	// 2. Initialize Host
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Convert seeds strings to peer.AddrInfo for AutoRelay
	seedsList := DefaultSeeds
	if *targetPeer != "" {
		seedsList = []string{*targetPeer}
	}

	var staticRelays []peer.AddrInfo
	for _, s := range seedsList {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			continue
		}
		pinfo, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		staticRelays = append(staticRelays, *pinfo)
	}

	// Jalur pipa untuk relay dinamis
	relaySource := make(chan peer.AddrInfo, 10)

	host, err := corenet.NewNode(ctx, corenet.Config{
		ListenAddr:   fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *port),
		PrivateKey:   priv,
		DataDir:      filepath.Dir(*dbFile),
		StaticRelays: staticRelays,
		RelaySource:  relaySource,
		ForcePublic:  *forcePublic,
		IsDedicated:  *isDedicated,
		IsClientOnly: *isClientOnly,
		EnableRelay:  true,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create network node")
	}

	logger.Info().
		Str("peerID", host.ID().String()).
		Interface("args", os.Args).
		Msg(">>> NODE STARTUP AUDIT")

	// 3. Database & Storage
	if err := corestore.InitDatabase(*dbFile); err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize database")
	}

	// Inject database check callback to networking package to break import cycle
	corenet.HasActiveSessionFn = func(peerID string) bool {
		var count int
		err := corestore.DB.QueryRow("SELECT COUNT(1) FROM sessions WHERE peer_id = ? AND root_key != ''", peerID).Scan(&count)
		if err != nil {
			return false
		}
		return count > 0
	}

	// 3. Global State Initialization
	corenet.IsDedicated = *isDedicated
	corenet.IsClientOnly = *isClientOnly
	corenet.ForceClientOnly = *isClientOnly
	logger.Info().Bool("dedicated", corenet.IsDedicated).Bool("clientOnly", corenet.IsClientOnly).Bool("forceClientOnly", corenet.ForceClientOnly).Msg("Node mode initialized")

	// 4. Protocols
	dhtRouting, err := corenet.SetupDHT(ctx, host)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to setup DHT")
	}
	_ = corenet.SetupBitswap(ctx, host, dhtRouting)
	_ = corenet.SetupPubSub(ctx, host)
	_ = corenet.SetupDiscovery(ctx, host)

	coreproto.SetupMessaging(host)
	coreproto.SetupMailbox(host, *isClientOnly)
	coreproto.SetupPreKeyService(host)
	coreproto.SetupAliasService(host)
	coreproto.SetupProfileService(host)
	coreproto.SetupClusterSync(ctx, host)

	// Start the global sequential mailbox sync manager
	go coreproto.StartGlobalMailboxSyncManager(ctx, host, priv)

	// Restore group memberships from database in background once we connect to at least one peer
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if len(host.Network().Peers()) > 0 {
					logger.Info().Msg("Connected to at least one peer. Starting background group restoration...")
					_ = coreproto.RestoreGroups(ctx, host, priv)
					return
				}
			}
		}
	}()

	if corenet.IsDedicated {
		coreproto.SetupReplicationHandler(host)
		go corestore.StartGarbageCollector(ctx, 1*time.Hour, 14)
	}
	if *isClientOnly {
		corenet.IsClientOnly = true
	}

	// BUG-2/3 FIX: Deduplication map for peer connection events.
	// libp2p fires PeerConnected for every new transport (QUIC, mDNS, circuit relay) separately.
	// Without dedup, the same peer triggers infrastructure sync 2-3x within milliseconds.
	var recentlyConnected sync.Map // map[peer.ID]time.Time

	host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			remoteID := conn.RemotePeer()

			// Dedup: if we fired this event for the same peer within the last 5 seconds, skip.
			now := time.Now()
			if last, ok := recentlyConnected.Load(remoteID); ok {
				if now.Sub(last.(time.Time)) < 5*time.Second {
					logger.Debug().Str("peerID", remoteID.String()).Msg(">>> PEER CONNECTED (dedup suppressed duplicate event)")
					return
				}
			}
			recentlyConnected.Store(remoteID, now)

			logger.Info().Str("peerID", remoteID.String()).Msg(">>> NEW PEER CONNECTED")

			// Measure and record the peer's custom dial timeout
			coreproto.MeasureAndRecordDialTimeout(ctx, host, remoteID)

			logger.Debug().Str("peerID", remoteID.String()).Msg("Checking capabilities for new peer...")

			// Wait a moment for protocol negotiation to finish
			go func() {
				var protos []protocol.ID
				var err error
				for i := 0; i < 5; i++ {
					time.Sleep(2 * time.Second)
					protos, err = host.Peerstore().GetProtocols(remoteID)
					if err == nil && len(protos) > 0 {
						break
					}
				}
				if len(protos) == 0 {
					logger.Debug().Str("peerID", remoteID.String()).Msg("Failed to negotiate protocols (no protocols found after timeout)")
					return
				}

				isInfra := false
				for _, p := range protos {
					if string(p) == "/p2p-core/infra/1.1.0" {
						isInfra = true
						break
					}
				}

				if isInfra {
					logger.Info().Str("peerID", remoteID.String()).Msg("IDENTIFIED INFRASTRUCTURE: Triggering Mailbox Sync Manager")
					go coreproto.StartMailboxSync(ctx, host, remoteID, priv)
				} else {
					// Proactive session warm-up disabled.
					logger.Debug().Str("peerID", remoteID.String()).Msg("Peer is a standard node (not infrastructure)")
				}
			}()
		},
	})

	// Start the Aggressive Reconnection Loop (grouped by Peer ID to avoid dial backoff race conditions)
	go func() {
		seeds := DefaultSeeds
		if *targetPeer != "" {
			seeds = []string{*targetPeer}
		}

		// Group seeds by Peer ID once
		groupedSeeds := make(map[peer.ID][]multiaddr.Multiaddr)
		for _, s := range seeds {
			ma, err := multiaddr.NewMultiaddr(s)
			if err != nil {
				continue
			}
			pinfo, err := peer.AddrInfoFromP2pAddr(ma)
			if err != nil {
				continue
			}
			groupedSeeds[pinfo.ID] = append(groupedSeeds[pinfo.ID], pinfo.Addrs...)
		}

		var seedsInfo []peer.AddrInfo
		for id, addrs := range groupedSeeds {
			seedsInfo = append(seedsInfo, peer.AddrInfo{
				ID:    id,
				Addrs: addrs,
			})
		}

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			for _, pi := range seedsInfo {
				if pi.ID == host.ID() {
					continue
				}

				if host.Network().Connectedness(pi.ID) == network.Connected {
					// Verify connection is actually alive by trying to open a stream.
					// Stale QUIC connections will fail this check.
					go func(pid peer.ID) {
						dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
						defer cancel()
						str, errStream := host.NewStream(dialCtx, pid, "/ipfs/ping/1.0.0")
						if errStream != nil {
							logger.Warn().Str("peerID", pid.String()).Msg("Stale connection detected. Closing peer connection to trigger reconnect.")
							host.Network().ClosePeer(pid)
						} else {
							str.Close()
						}
					}(pi.ID)
				} else {
					// Clear dial backoff to allow immediate reconnection attempt.
					if s, ok := host.Network().(*swarm.Swarm); ok {
						s.Backoff().Clear(pi.ID)
					}
					logger.Debug().Str("peerID", pi.ID.String()).Msg("Attempting to reconnect to seed...")
					go func(addrInfo peer.AddrInfo) {
						if err := host.Connect(ctx, addrInfo); err != nil {
							logger.Debug().Err(err).Str("peerID", addrInfo.ID.String()).Msg("Reconnection failed")
						} else {
							logger.Info().Str("peerID", addrInfo.ID.String()).Msg("Successfully reconnected to seed node")
						}
					}(pi)
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				continue
			}
		}
	}()

	// 6. Adaptive Monitoring
	go corenet.RunDetailedPeerMonitor(ctx, host, relaySource)
	if !*isDedicated {
		go corenet.StartNetworkMonitor(ctx, host)
	}

	if *isTUI {
		coretui.StartTUI(ctx, host, func(cmd string) {
			coreproto.ProcessCommand(ctx, host, priv, cmd)
		})
	} else {
		logger.Info().Msg("Meshsage Node is ready and listening for peers...")

		go coreproto.StartChatPrompt(ctx, host, priv)

		// Wait for termination
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
	}

	logger.Info().Msg("Shutting down Meshsage node...")
}
