package main

/*
#cgo CFLAGS: -I/opt/homebrew/Caskroom/flutter/3.38.9/flutter/bin/cache/dart-sdk/include
#include <stdlib.h>
#include "dart_api_dl.h"

// Helper function to post string messages via Dart_PostCObject_DL
static bool post_string_to_dart(int64_t port_id, const char* str) {
    if (Dart_PostCObject_DL == NULL) {
        return false;
    }
    Dart_CObject obj;
    obj.type = Dart_CObject_kString;
    obj.value.as_string = str;
    return Dart_PostCObject_DL(port_id, &obj);
}
*/
import "C"

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
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
)

// Global state variables
var (
	globalHost   host.Host
	globalPriv   crypto.PrivKey
	globalCtx    context.Context
	globalCancel context.CancelFunc
)

var (
	globalPortID int64 // accessed atomically
)

var DefaultSeeds = []string{
	"/ip4/103.127.138.103/tcp/4004/p2p/12D3KooWFZTmWWGaeNFY7ro95DtiSoV5txAqv6iZCERy6vLWTA95",
	"/ip4/103.127.138.103/udp/4004/quic-v1/p2p/12D3KooWFZTmWWGaeNFY7ro95DtiSoV5txAqv6iZCERy6vLWTA95",
}

// -----------------------------------------------------------------------------
// THREAD-SAFE EVENT QUEUE (Go -> Dart FFI Bridge)
// -----------------------------------------------------------------------------

type Queue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	events []string
	closed bool
}

func NewQueue() *Queue {
	q := &Queue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *Queue) Push(event string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}

	portID := atomic.LoadInt64(&globalPortID)

	if portID != 0 {
		cStr := C.CString(event)
		C.post_string_to_dart(C.int64_t(portID), cStr)
		C.free(unsafe.Pointer(cStr))
	} else {
		q.events = append(q.events, event)
		q.cond.Signal()
	}
}

func (q *Queue) FlushPending(portID int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.events) == 0 {
		return
	}
	// Use raw stdout print to avoid recursive logging deadlocks
	fmt.Printf("[Go EventQueue] Flushing %d pending events to registered Dart Port %d\n", len(q.events), portID)
	for _, event := range q.events {
		cStr := C.CString(event)
		C.post_string_to_dart(C.int64_t(portID), cStr)
		C.free(unsafe.Pointer(cStr))
	}
	q.events = nil
}

// Close wakes up all blocked Pop() callers so they can exit cleanly.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.cond.Broadcast()
}

// Pop returns the next event, or empty string after ~500ms timeout or if queue is closed.
// This prevents the Dart isolate from blocking forever when the app restarts.
func (q *Queue) Pop() string {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Wake up every 500ms via a background ticker so we never block forever
	timer := time.AfterFunc(500*time.Millisecond, func() {
		q.cond.Broadcast()
	})
	defer timer.Stop()

	for len(q.events) == 0 && !q.closed {
		q.cond.Wait()
		// Reset the timer for next wait cycle
		timer.Reset(500 * time.Millisecond)
	}

	if len(q.events) == 0 {
		return "" // queue closed or timeout
	}
	event := q.events[0]
	q.events = q.events[1:]
	return event
}

var eventQueue = NewQueue()

// EventWriter redirects log & system messages directly to our Event Queue
type EventWriter struct {
	original io.Writer
}

func (ew *EventWriter) Write(p []byte) (n int, err error) {
	n, err = ew.original.Write(p)
	cleanStr := string(p)

	// Wrap in log JSON event
	logEv := map[string]string{
		"type":    "log",
		"content": cleanStr,
	}
	data, _ := json.Marshal(logEv)
	eventQueue.Push(string(data))
	return
}

func isKnownChatPeer(peerID string) bool {
	// 1. Check if they have an alias
	if _, err := corestore.FindAliasByPeerID(peerID); err == nil {
		return true
	}
	// 2. Check if they have a profile
	if disp, _, _, _, err := corestore.GetPeerProfile(peerID); err == nil && disp != "" {
		return true
	}
	// 3. Check if there are messages with this peer in messages table
	if corestore.DB != nil {
		var count int
		err := corestore.DB.QueryRow(`SELECT COUNT(1) FROM messages WHERE sender_id = ? OR recipient_id = ? LIMIT 1`, peerID, peerID).Scan(&count)
		if err == nil && count > 0 {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// EXPORTED C FUNCTIONS
// -----------------------------------------------------------------------------

//export StartNode
func StartNode(dbPathStr, idPathStr *C.char, port C.int, isClientOnlyVal C.int, enableRelayVal C.int) *C.char {
	// Clean up previous host and context if they exist (prevents resource/port collision on restart)
	if globalHost != nil {
		logger.Warn().Msg("Starting a new Go node, but a previous node is still running. Stopping it in background...")
		if globalCancel != nil {
			globalCancel()
		}

		oldHost := globalHost
		go func() {
			logger.Info().Msg("Closing old host in background...")
			_ = oldHost.Close()
			logger.Info().Msg("Old host successfully closed in background")
		}()
		globalHost = nil

		// Close the old queue so blocked Pop() callers wake up and exit
		eventQueue.Close()
		// Replace with fresh queue for this session
		eventQueue = NewQueue()
		time.Sleep(100 * time.Millisecond) // Give the OS a brief moment to yield
	}

	// Reset the globalPortID so pending startup events are queued until Dart registers its new Port ID.
	// This prevents Go from pushing events to the dead port ID from the pre-restart Dart VM session.
	atomic.StoreInt64(&globalPortID, 0)

	dbPath := C.GoString(dbPathStr)
	idPath := C.GoString(idPathStr)
	isClientOnly := isClientOnlyVal != 0

	// Initialize global network modes early so NewNode can access them
	corenet.IsDedicated = false
	corenet.IsClientOnly = isClientOnly
	corenet.ForceClientOnly = isClientOnly

	// 1. Direct standard log output & logger output to our JSON event queue
	errWriter := &EventWriter{original: os.Stderr}
	logger.SetOutput(errWriter)
	logger.DisplayWriter = &EventWriter{original: os.Stdout}

	logger.Info().Msg("Starting embedded Go Meshsage Node...")

	// 2. Create directories
	for _, path := range []string{idPath, dbPath} {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return C.CString("Failed to create folder " + dir + ": " + err.Error())
		}
	}

	// 3. Identity Setup
	var priv crypto.PrivKey
	var err error
	if _, err = os.Stat(idPath); os.IsNotExist(err) {
		logger.Info().Msg("Generating new P2P identity key...")
		priv, _, err = corecrypto.GenerateKeyPair()
		if err != nil {
			return C.CString("Failed to generate keys: " + err.Error())
		}
		if err := corestore.SavePrivateKey(priv, idPath); err != nil {
			return C.CString("Failed to save private key: " + err.Error())
		}
	} else {
		logger.Info().Msg("Loading existing P2P identity...")
		priv, err = corestore.LoadPrivateKey(idPath)
		if err != nil {
			return C.CString("Failed to load private key: " + err.Error())
		}
	}
	globalPriv = priv

	// 4. Database Setup
	if err := corestore.InitDatabase(dbPath); err != nil {
		return C.CString("Failed to init SQLite: " + err.Error())
	}
	coreproto.InitStats()

	// Inject database check callback to networking package to break import cycle
	corenet.HasActiveSessionFn = func(peerID string) bool {
		var count int
		// 1. Check if has active E2EE session
		err := corestore.DB.QueryRow("SELECT COUNT(1) FROM sessions WHERE peer_id = ? AND root_key != ''", peerID).Scan(&count)
		if err == nil && count > 0 {
			return true
		}
		// 2. Check if peer exists in profile_store (added contact)
		err = corestore.DB.QueryRow("SELECT COUNT(1) FROM profile_store WHERE peer_id = ?", peerID).Scan(&count)
		if err == nil && count > 0 {
			return true
		}
		// 3. Check if peer exists in alias_store (resolved alias contact)
		err = corestore.DB.QueryRow("SELECT COUNT(1) FROM alias_store WHERE peer_id = ?", peerID).Scan(&count)
		if err == nil && count > 0 {
			return true
		}
		return false
	}

	// 5. Setup Host Context & Relays
	globalCtx, globalCancel = context.WithCancel(context.Background())

	var staticRelays []peer.AddrInfo
	for _, s := range DefaultSeeds {
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

	relaySource := make(chan peer.AddrInfo, 10)

	enableRelay := enableRelayVal != 0

	// Build the Node host.
	// Use a short timeout so we don't hang forever if the port from the previous
	// session is still held by Android OS (happens on reinstall-without-uninstall).
	hostCtx, hostCancel := context.WithTimeout(globalCtx, 10*time.Second)
	defer hostCancel()

	host, err := corenet.NewNode(hostCtx, corenet.Config{
		ListenAddr:   fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
		PrivateKey:   priv,
		DataDir:      filepath.Dir(dbPath),
		StaticRelays: staticRelays,
		RelaySource:  relaySource,
		ForcePublic:  false,
		IsDedicated:  false,
		IsClientOnly: isClientOnly,
		EnableRelay:  enableRelay,
	})
	if err != nil {
		// Port might be busy from old session. Retry with random port (0).
		logger.Warn().Err(err).Msg("NewNode failed with requested port, retrying with random port...")
		host, err = corenet.NewNode(globalCtx, corenet.Config{
			ListenAddr:   "/ip4/0.0.0.0/tcp/0",
			PrivateKey:   priv,
			DataDir:      filepath.Dir(dbPath),
			StaticRelays: staticRelays,
			RelaySource:  relaySource,
			ForcePublic:  false,
			IsDedicated:  false,
			IsClientOnly: isClientOnly,
			EnableRelay:  enableRelay,
		})
		if err != nil {
			return C.CString("Failed to build host: " + err.Error())
		}
	}
	globalHost = host

	// 7. Initialize Protocols
	dhtRouting, err := corenet.SetupDHT(globalCtx, host)
	if err != nil {
		return C.CString("Failed to init DHT: " + err.Error())
	}
	if errBitswap := corenet.SetupBitswap(globalCtx, host, dhtRouting, filepath.Dir(dbPath)); errBitswap != nil {
		logger.Error().Err(errBitswap).Msg("Failed to setup Bitswap")
	}
	if errPubSub := corenet.SetupPubSub(globalCtx, host); errPubSub != nil {
		logger.Error().Err(errPubSub).Msg("Failed to setup PubSub")
	}
	if errDiscovery := corenet.SetupDiscovery(globalCtx, host); errDiscovery != nil {
		logger.Error().Err(errDiscovery).Msg("Failed to setup Discovery")
	}

	coreproto.SetupMessaging(host)
	coreproto.SetupMailbox(host, isClientOnly)
	coreproto.SetupPreKeyService(host)
	coreproto.SetupAliasService(host)
	coreproto.SetupProfileService(host)
	coreproto.SetupClusterSync(globalCtx, host)

	// Start the global sequential mailbox sync manager
	go coreproto.StartGlobalMailboxSyncManager(globalCtx, host, priv)

	// Hook the structured message callback to send JSON events to the queue
	coreproto.MessageCallback = func(event coreproto.MessageEvent) {
		data, err := json.Marshal(map[string]interface{}{
			"type":      "message",
			"msg_type":  event.Type,
			"msg_id":    event.MsgID,
			"timestamp": event.Timestamp,
			"sender":    event.Sender,
			"group_id":  event.GroupID,
			"content":   event.Content,
			"unix_time": event.UnixTime,
		})
		if err == nil {
			eventQueue.Push(string(data))
		}
	}

	// Hook the profile update callback to forward profile notifications to Flutter
	coreproto.ProfileUpdateCallback = func(peerID string) {
		event := map[string]string{
			"type":   "profile_updated",
			"sender": peerID,
		}
		data, err := json.Marshal(event)
		if err == nil {
			eventQueue.Push(string(data))
		}
	}

	// Hook the status callback to forward delivery receipts to Flutter
	coreproto.StatusCallback = func(event coreproto.StatusEvent) {
		_ = corestore.UpdateMessageStatus(event.RefID, event.Status)
		data, err := json.Marshal(map[string]interface{}{
			"type":   "delivery_status",
			"ref_id": event.RefID,
			"status": event.Status,
			"sender": event.Sender,
		})
		if err == nil {
			eventQueue.Push(string(data))
		}
	}

	// Hook the subscription status callback to forward push notification status to Flutter
	coreproto.SubscriptionStatusCallback = func(event coreproto.SubscriptionStatusEvent) {
		data, err := json.Marshal(map[string]interface{}{
			"type":     "push_subscription_status",
			"relay_id": event.RelayID,
			"active":   event.Active,
		})
		if err == nil {
			eventQueue.Push(string(data))
		}
	}

	// Background group restoration on startup once connected to at least one peer
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-globalCtx.Done():
				return
			case <-ticker.C:
				if len(host.Network().Peers()) > 0 {
					logger.Info().Msg("Connected to at least one peer. Starting background group restoration...")
					if errRestore := coreproto.RestoreGroups(globalCtx, host, priv); errRestore != nil {
						logger.Error().Err(errRestore).Msg("Background group restoration failed")
					}
					return
				}
			}
		}
	}()

	// Set connection notifications
	var recentlyConnected sync.Map
	host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			remoteID := conn.RemotePeer()
			now := time.Now()
			if last, ok := recentlyConnected.Load(remoteID); ok {
				if now.Sub(last.(time.Time)) < 5*time.Second {
					return
				}
			}
			recentlyConnected.Store(remoteID, now)

			// Push peer connected event to front UI
			peerEv := map[string]string{
				"type":    "peer_connected",
				"peer_id": remoteID.String(),
			}
			data, _ := json.Marshal(peerEv)
			eventQueue.Push(string(data))

			logger.Info().Str("peerID", remoteID.String()).Msg(">>> NEW PEER CONNECTED")

			// Measure and record the peer's custom dial timeout
			coreproto.MeasureAndRecordDialTimeout(globalCtx, host, remoteID)

			// FIX: Network switch — retry any envelopes that failed direct delivery
			// on this peer's previous (stale) connection, e.g. during a WiFi→mobile
			// handover. We wait 2s for the new connection to fully stabilise first.
			go func(peerID peer.ID) {
				time.Sleep(2 * time.Second)
				coreproto.DrainPendingDirectQueue(globalCtx, host, peerID)
			}(remoteID)

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
					go coreproto.StartMailboxSync(globalCtx, host, remoteID, priv)
				} else {
					logger.Info().Str("peerID", remoteID.String()).Msg("Peer is a standard node (not infrastructure), checking if session setup is needed")
					go func(targetID peer.ID) {
						if isKnownChatPeer(targetID.String()) {
							if corestore.HasSession(targetID.String()) {
								logger.Info().Str("peerID", targetID.String()).Msg("Session exists, warming up session...")
								coreproto.ProbeSessionWarmup(globalCtx, host, priv, targetID)
							} else {
								logger.Info().Str("peerID", targetID.String()).Msg("No session exists, initiating session...")
								_ = coreproto.InitiateSession(globalCtx, host, priv, targetID)
							}
						} else {
							logger.Debug().Str("peerID", targetID.String()).Msg("Peer is standard node but not a known contact, skipping session setup")
						}
					}(remoteID)

					// Hybrid avatar download: peer is online now — best time to download their avatar.
					// Only triggers if we have their CID in DB but the local file is missing.
					go func(pid string) {
						_, avatarCID, avatarKey, localPath, err := corestore.GetPeerProfile(pid)
						if err != nil || avatarCID == "" || avatarKey == "" {
							return // No avatar CID known yet — resolve will happen via DHT later
						}
						fileMissing := localPath == ""
						if !fileMissing {
							if _, statErr := os.Stat(localPath); statErr != nil {
								fileMissing = true
							}
						}
						if fileMissing {
							logger.Info().Str("peerID", pid).Msg("peer_connected: peer is online, triggering avatar download")
							coreproto.TriggerAvatarDownload(pid, avatarCID, avatarKey)
						}
					}(remoteID.String())
				}
			}()
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			remoteID := conn.RemotePeer()
			if n.Connectedness(remoteID) != network.Connected {
				peerEv := map[string]string{
					"type":    "peer_disconnected",
					"peer_id": remoteID.String(),
				}
				data, _ := json.Marshal(peerEv)
				eventQueue.Push(string(data))
			}
		},
	})

	// Start reconnection loops in background (grouped by Peer ID to avoid dial backoff race conditions)
	go func() {
		// Group seeds by Peer ID once
		groupedSeeds := make(map[peer.ID][]multiaddr.Multiaddr)
		for _, s := range DefaultSeeds {
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
						dialCtx, cancel := context.WithTimeout(globalCtx, 3*time.Second)
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
						if errDial := host.Connect(globalCtx, addrInfo); errDial != nil {
							logger.Debug().Err(errDial).Str("peerID", addrInfo.ID.String()).Msg("Reconnection failed")
						} else {
							logger.Info().Str("peerID", addrInfo.ID.String()).Msg("Successfully reconnected to seed node")
						}
					}(pi)
				}
			}

			select {
			case <-globalCtx.Done():
				return
			case <-ticker.C:
				continue
			}
		}
	}()

	// Monitor threads
	go corenet.RunDetailedPeerMonitor(globalCtx, host, relaySource)
	go corenet.StartNetworkMonitor(globalCtx, host)

	logger.Info().Msg("Meshsage P2P Embedded Node successfully booted!")

	// Return null (nil) to represent success
	return nil
}

//export SendDirectMessage
func SendDirectMessage(targetStr, contentStr *C.char) *C.char {
	target := C.GoString(targetStr)
	content := C.GoString(contentStr)

	if strings.HasPrefix(target, "@") {
		// 1. Check local DB first for group metadata
		if _, errMeta := corestore.LoadGroupMetadata(target); errMeta == nil {
			return C.CString("Failed to resolve alias: " + target + " is a group alias, cannot send private messages to it")
		}
		// 2. Check remote group metadata
		if meta, errGroup := coreproto.ResolveGroupMetadata(globalCtx, globalHost, target); errGroup == nil && meta.GroupID != "" {
			return C.CString("Failed to resolve alias: " + target + " is a group alias, cannot send private messages to it")
		}

		resolved, err := coreproto.ResolveAlias(globalCtx, globalHost, target)
		if err != nil {
			return C.CString("Failed to resolve alias " + target + ": " + err.Error())
		}
		target = resolved
	}

	targetID, err := peer.Decode(target)
	if err != nil {
		return C.CString("Invalid peer ID: " + err.Error())
	}

	// Use the msgID returned directly from SendMessage (single source of truth)
	msgID, err := coreproto.SendMessage(globalCtx, globalHost, globalPriv, targetID, content)
	if err != nil {
		return C.CString("Failed to send: " + err.Error())
	}
	coreproto.TrackMsgSent() // Track outgoing logical message
	// Return msgID prefixed with "ok:" so Flutter can distinguish success from error
	return C.CString("ok:" + msgID)
}

//export InitiateSession
func InitiateSession(targetStr *C.char) *C.char {
	target := C.GoString(targetStr)

	if strings.HasPrefix(target, "@") {
		resolved, err := coreproto.ResolveAlias(globalCtx, globalHost, target)
		if err != nil {
			return C.CString("Failed to resolve alias " + target + ": " + err.Error())
		}
		target = resolved
	}

	targetID, err := peer.Decode(target)
	if err != nil {
		return C.CString("Invalid peer ID: " + err.Error())
	}

	// Whitelist the peer ID in Connection Gater by saving a blank profile
	if errProfile := corestore.SavePeerProfile(targetID.String(), "", "", "", ""); errProfile != nil {
		logger.Error().Err(errProfile).Str("peerID", targetID.String()).Msg("Failed to whitelist peer profile")
	}

	// Run session initiation / warmup in background to avoid blocking Dart UI thread
	go func() {
		err = coreproto.InitiateSession(globalCtx, globalHost, globalPriv, targetID)
		if err != nil {
			logger.Warn().Err(err).Str("targetID", targetID.String()).Msg("Proactive InitiateSession failed in background")
		} else {
			logger.Info().Str("targetID", targetID.String()).Msg("Proactive InitiateSession succeeded in background")
		}
	}()

	return nil
}

//export SendReadReceipt
func SendReadReceipt(targetStr, msgIDStr *C.char) *C.char {
	target := C.GoString(targetStr)
	msgID := C.GoString(msgIDStr)

	if strings.HasPrefix(target, "@") {
		resolved, err := coreproto.ResolveAlias(globalCtx, globalHost, target)
		if err != nil {
			return C.CString("Failed to resolve alias: " + err.Error())
		}
		target = resolved
	}

	targetID, err := peer.Decode(target)
	if err != nil {
		return C.CString("Invalid peer ID: " + err.Error())
	}

	err = coreproto.SendStatusUpdate(globalCtx, globalHost, targetID, msgID, coreproto.StatusRead)
	if err != nil {
		return C.CString("Failed to send read receipt: " + err.Error())
	}
	return nil
}

//export ResetPeerSession
func ResetPeerSession(peerIDStr *C.char) *C.char {
	peerIDRaw := C.GoString(peerIDStr)
	if globalHost == nil || peerIDRaw == "" {
		return C.CString("Host not initialized")
	}

	if strings.HasPrefix(peerIDRaw, "@") {
		resolved, err := coreproto.ResolveAlias(globalCtx, globalHost, peerIDRaw)
		if err != nil {
			return C.CString("Failed to resolve alias: " + err.Error())
		}
		peerIDRaw = resolved
	}

	peerID, err := peer.Decode(peerIDRaw)
	if err != nil {
		return C.CString("Invalid peer ID: " + err.Error())
	}

	err = coreproto.SendSessionReset(globalCtx, globalHost, peerID)
	if err != nil {
		return C.CString("Failed to send session reset: " + err.Error())
	}
	return nil
}

//export SendGroupChat
func SendGroupChat(groupIDStr, contentStr *C.char) *C.char {
	groupID := C.GoString(groupIDStr)
	content := C.GoString(contentStr)

	err := coreproto.SendGroupMessage(globalCtx, globalHost, groupID, content)
	if err != nil {
		return C.CString("Failed to send group message: " + err.Error())
	}
	// Note: SendGroupMessage already calls TrackMsgSent when publishing to GossipSub.
	return nil
}

//export JoinGroup
func JoinGroup(groupIDStr, membersStr *C.char) *C.char {
	groupID := C.GoString(groupIDStr)
	membersCSV := C.GoString(membersStr)

	var members []string
	if membersCSV != "" {
		parts := strings.Split(membersCSV, ",")
		for _, m := range parts {
			trimmed := strings.TrimSpace(m)
			if trimmed != "" {
				members = append(members, trimmed)
			}
		}
	}

	err := coreproto.JoinGroup(globalCtx, globalHost, globalPriv, groupID, members)
	if err != nil {
		return C.CString("Failed to join group: " + err.Error())
	}
	return nil
}

//export CreateGroup
func CreateGroup(membersStr *C.char) *C.char {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return C.CString("Failed to generate random group ID: " + err.Error())
	}
	groupID := fmt.Sprintf("group-%x", b)

	errStr := JoinGroup(C.CString(groupID), membersStr)
	if errStr != nil {
		return errStr
	}
	return C.CString(groupID)
}

//export SetAlias
func SetAlias(peerIDStr, aliasStr *C.char) *C.char {
	peerID := C.GoString(peerIDStr)
	alias := C.GoString(aliasStr)

	if !strings.HasPrefix(alias, "@") {
		alias = "@" + alias
	}

	err := coreproto.RegisterAlias(globalCtx, globalHost, alias, peerID)
	if err != nil {
		return C.CString("Failed to set alias: " + err.Error())
	}
	return nil
}

//export GetAliasByPeerID
func GetAliasByPeerID(peerIDStr *C.char) *C.char {
	peerID := C.GoString(peerIDStr)
	alias, err := corestore.FindAliasByPeerID(peerID)
	if err != nil {
		return C.CString("")
	}
	return C.CString(alias)
}

//export SearchLocalAliases
func SearchLocalAliases(queryStr *C.char) *C.char {
	query := C.GoString(queryStr)
	results, err := corestore.SearchAliases(query)
	if err != nil {
		return C.CString("[]")
	}
	data, err := json.Marshal(results)
	if err != nil {
		return C.CString("[]")
	}
	return C.CString(string(data))
}

//export ResolveAlias
func ResolveAlias(aliasStr *C.char) *C.char {
	alias := C.GoString(aliasStr)
	peerID, err := coreproto.ResolveAlias(globalCtx, globalHost, alias)
	if err != nil {
		return C.CString("Error: " + err.Error())
	}
	return C.CString(peerID)
}

//export GetLocalPeerID
func GetLocalPeerID() *C.char {
	if globalHost == nil {
		return C.CString("Node not started")
	}
	return C.CString(globalHost.ID().String())
}

//export PollEvent
func PollEvent() *C.char {
	// Pop() now returns "" after 500ms timeout — never blocks forever
	event := eventQueue.Pop()
	return C.CString(event)
}

//export FreeString
func FreeString(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

//export StopNode
func StopNode() {
	coreproto.SaveStatsNow()
	if globalHost != nil {
		logger.Warn().Msg("Stopping the Go node in background...")
		if globalCancel != nil {
			globalCancel()
		}

		oldHost := globalHost
		go func() {
			_ = oldHost.Close()
		}()
		globalHost = nil

		atomic.StoreInt64(&globalPortID, 0)

		eventQueue.Close()
		// Replace with fresh queue for future restarts
		eventQueue = NewQueue()
	}
}

//export InitializeDartApi
func InitializeDartApi(data unsafe.Pointer) C.int {
	return C.int(C.Dart_InitializeApiDL(data))
}

//export RegisterPort
func RegisterPort(portID C.int64_t) {
	atomic.StoreInt64(&globalPortID, int64(portID))
	logger.Info().Int64("portID", int64(portID)).Msg("Registered Dart Native Port ID in Go")
	eventQueue.FlushPending(int64(portID))
}

//export GetNetworkStats
func GetNetworkStats() *C.char {
	return C.CString(coreproto.GetNetworkStatsJSON())
}

//export GetChatHistory
func GetChatHistory(targetIDVal *C.char, isGroupVal C.int, limit C.int, offset C.int) *C.char {
	if globalHost == nil {
		return C.CString("[]")
	}
	targetID := C.GoString(targetIDVal)
	isGroup := isGroupVal != 0
	myID := globalHost.ID().String()

	messages, err := corestore.GetChatMessages(myID, targetID, isGroup, int(limit), int(offset))
	if err != nil {
		logger.Error().Err(err).Str("targetID", targetID).Msg("GetChatHistory: failed to query messages")
		return C.CString("[]")
	}

	data, err := json.Marshal(messages)
	if err != nil {
		logger.Error().Err(err).Msg("GetChatHistory: failed to marshal JSON")
		return C.CString("[]")
	}
	return C.CString(string(data))
}

//export GetChatMetadata
func GetChatMetadata() *C.char {
	if globalHost == nil {
		return C.CString("[]")
	}
	myID := globalHost.ID().String()

	metadataList, err := corestore.GetChatMetadataList(myID)
	if err != nil {
		logger.Error().Err(err).Msg("GetChatMetadata: failed to query metadata list")
		return C.CString("[]")
	}

	data, err := json.Marshal(metadataList)
	if err != nil {
		logger.Error().Err(err).Msg("GetChatMetadata: failed to marshal JSON")
		return C.CString("[]")
	}
	return C.CString(string(data))
}

//export MarkMessagesAsRead
func MarkMessagesAsRead(targetIDVal *C.char, isGroupVal C.int) *C.char {
	if globalHost == nil {
		return C.CString("Error: host not initialized")
	}
	targetID := C.GoString(targetIDVal)
	isGroup := isGroupVal != 0
	myID := globalHost.ID().String()

	err := corestore.MarkChatAsRead(myID, targetID, isGroup)
	if err != nil {
		return C.CString("Error: " + err.Error())
	}
	return nil
}

//export DeleteMessageFFI
func DeleteMessageFFI(msgIDVal *C.char) *C.char {
	msgID := C.GoString(msgIDVal)
	err := corestore.DeleteMessageByID(msgID)
	if err != nil {
		return C.CString("Error: " + err.Error())
	}
	return nil
}

//export ClearChatHistoryFFI
func ClearChatHistoryFFI(targetIDVal *C.char, isGroupVal C.int) *C.char {
	if globalHost == nil {
		return C.CString("Error: host not initialized")
	}
	targetID := C.GoString(targetIDVal)
	isGroup := isGroupVal != 0
	myID := globalHost.ID().String()

	err := corestore.ClearChatHistory(myID, targetID, isGroup)
	if err != nil {
		return C.CString("Error: " + err.Error())
	}
	return nil
}

//export ImportLegacyMessage
func ImportLegacyMessage(senderVal, recipientVal, contentVal, msgIDVal, msgTypeVal, statusVal *C.char, timestampMs C.int64_t) *C.char {
	sender := C.GoString(senderVal)
	recipient := C.GoString(recipientVal)
	content := C.GoString(contentVal)
	msgID := C.GoString(msgIDVal)
	msgType := C.GoString(msgTypeVal)
	status := C.GoString(statusVal)

	if corestore.DB == nil {
		return C.CString("Error: database not initialized")
	}

	// Skip WebRTC signaling and decryption error messages — these must never be stored in SQLite
	if strings.Contains(content, `"msg_type":"call_signal"`) ||
		strings.HasPrefix(content, "[Error:") ||
		strings.HasPrefix(content, `{"type":"offer"`) ||
		strings.HasPrefix(content, `{"type":"answer"`) ||
		strings.HasPrefix(content, `{"type":"candidate"`) {
		logger.Debug().Str("msgID", msgID).Msg("ImportLegacyMessage: skipping signaling/error content")
		return nil // silently skip, not an error
	}

	t := time.Unix(int64(timestampMs)/1000, (int64(timestampMs)%1000)*1000000)
	timestampStr := t.UTC().Format("2006-01-02 15:04:05")

	query := `INSERT INTO messages (sender_id, recipient_id, content, msg_id, msg_hash, msg_type, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	msgHash := msgID

	_, err := corestore.DB.Exec(query, sender, recipient, content, msgID, msgHash, msgType, status, timestampStr)
	if err != nil {
		return C.CString("Error: " + err.Error())
	}
	return nil
}

//export SaveOutgoingMessage
func SaveOutgoingMessage(senderIDVal, recipientIDVal, contentVal, msgIDVal, msgHashVal, msgTypeVal, statusVal *C.char) *C.char {
	senderID := C.GoString(senderIDVal)
	recipientID := C.GoString(recipientIDVal)
	content := C.GoString(contentVal)
	msgID := C.GoString(msgIDVal)
	msgHash := C.GoString(msgHashVal)
	msgType := C.GoString(msgTypeVal)
	status := C.GoString(statusVal)

	err := corestore.SaveMessage(senderID, recipientID, content, msgID, msgHash, msgType, status, 0)
	if err != nil {
		return C.CString("Error: " + err.Error())
	}
	return nil
}

//export CreateGroupProper
func CreateGroupProper(aliasStr, groupTypeStr, membersStr *C.char) *C.char {
	alias := C.GoString(aliasStr)
	groupType := strings.ToUpper(C.GoString(groupTypeStr))
	membersCSV := C.GoString(membersStr)

	if !strings.HasPrefix(alias, "@") {
		alias = "@" + alias
	}

	if groupType != "SECURE" && groupType != "UNSECURE" {
		return C.CString("Error: Invalid group type. Must be SECURE or UNSECURE.")
	}

	var members []string
	if membersCSV != "" {
		parts := strings.Split(membersCSV, ",")
		for _, m := range parts {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if strings.HasPrefix(m, "@") {
				resolved, err := coreproto.ResolveAlias(globalCtx, globalHost, m)
				if err == nil {
					m = resolved
				} else {
					return C.CString("Error: Failed to resolve alias " + m + ": " + err.Error())
				}
			}
			members = append(members, m)
		}
	}

	// Generate Group ID
	hSum := sha256.Sum256([]byte(globalHost.ID().String() + fmt.Sprintf("%d", time.Now().UnixNano())))
	groupID := fmt.Sprintf("group_%x", hSum)[:32]

	// Sign Metadata
	privKey := globalHost.Peerstore().PrivKey(globalHost.ID())
	createdAt := time.Now().Unix()
	dataToSign := []byte(groupID + alias + globalHost.ID().String() + fmt.Sprintf("%d", createdAt))
	sigBytes, err := privKey.Sign(dataToSign)
	if err != nil {
		return C.CString("Error: Failed to sign metadata: " + err.Error())
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Register Group Alias to DHT
	errReg := coreproto.RegisterAlias(globalCtx, globalHost, alias, globalHost.ID().String())
	if errReg != nil {
		return C.CString("Error: Failed to register group alias " + alias + ": " + errReg.Error())
	}

	// Join Group locally
	errJoin := coreproto.JoinGroupProper(globalCtx, globalHost, privKey, groupID, alias, globalHost.ID().String(), groupType, sigB64, createdAt, members)
	if errJoin != nil {
		return C.CString("Error: Failed to join group locally: " + errJoin.Error())
	}

	// Send invitations to members (GINVITE)
	localKey, _ := corestore.GetGroupLocalKey(groupID)
	invitePayload := struct {
		Meta    corestore.GroupMetadata `json:"meta"`
		Members []string                `json:"members"`
		GKey    string                  `json:"gkey"`
	}{
		Meta: corestore.GroupMetadata{
			GroupID:    groupID,
			GroupAlias: alias,
			CreatorID:  globalHost.ID().String(),
			GroupType:  groupType,
			CreatedAt:  createdAt,
			Signature:  sigB64,
		},
		Members: members,
		GKey:    base64.StdEncoding.EncodeToString(localKey),
	}
	inviteBytes, _ := json.Marshal(invitePayload)
	inviteMsg := "GINVITE:" + string(inviteBytes)

	for _, m := range members {
		if m != globalHost.ID().String() {
			targetID, errDec := peer.Decode(m)
			if errDec == nil {
				go func(t peer.ID) {
					if _, errSend := coreproto.SendMessage(globalCtx, globalHost, privKey, t, inviteMsg); errSend != nil {
						logger.Error().Err(errSend).Str("targetID", t.String()).Msg("Failed to send group invite")
					}
				}(targetID)
			}
		}
	}

	return C.CString(groupID)
}

//export JoinGroupProper
func JoinGroupProper(aliasStr *C.char) *C.char {
	alias := C.GoString(aliasStr)
	if !strings.HasPrefix(alias, "@") {
		alias = "@" + alias
	}

	// Resolve metadata
	meta, err := coreproto.ResolveGroupMetadata(globalCtx, globalHost, alias)
	if err != nil {
		return C.CString("Error: Failed to resolve group metadata: " + err.Error())
	}

	if meta.GroupType == "SECURE" {
		return C.CString("Error: This group is SECURE. You must be invited by the Creator.")
	}

	privKey := globalHost.Peerstore().PrivKey(globalHost.ID())

	// Join locally
	errJoin := coreproto.JoinGroupProper(globalCtx, globalHost, privKey, meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.Signature, meta.CreatedAt, []string{})
	if errJoin != nil {
		return C.CString("Error: Failed to join group: " + errJoin.Error())
	}

	// Broadcast GCMD:JOIN to the group
	errCtrl := coreproto.SendGroupControlMessage(globalCtx, globalHost, meta.GroupID, "JOIN", globalHost.ID().String())
	if errCtrl != nil {
		return C.CString("Error: Failed to broadcast join command: " + errCtrl.Error())
	}

	return C.CString(meta.GroupID)
}

//export GroupAddMember
func GroupAddMember(aliasOrIDStr, memberStr *C.char) *C.char {
	aliasOrID := C.GoString(aliasOrIDStr)
	member := C.GoString(memberStr)

	meta, err := corestore.LoadGroupMetadata(aliasOrID)
	if err != nil {
		aliasName := aliasOrID
		if !strings.HasPrefix(aliasName, "@") {
			aliasName = "@" + aliasName
		}
		meta, err = corestore.LoadGroupMetadata(aliasName)
		if err != nil {
			return C.CString("Error: Group metadata not found: " + err.Error())
		}
	}

	if meta.CreatorID != globalHost.ID().String() {
		return C.CString("Error: Only the Creator can add members.")
	}

	if meta.GroupType != "SECURE" {
		return C.CString("Error: This group is public/open. Members join themselves.")
	}

	if strings.HasPrefix(member, "@") {
		resolved, err := coreproto.ResolveAlias(globalCtx, globalHost, member)
		if err == nil {
			member = resolved
		} else {
			return C.CString("Error: Failed to resolve member alias " + member + ": " + err.Error())
		}
	}

	// Save member locally
	err = corestore.AddGroupMemberV2(meta.GroupID, member, "MEMBER")
	if err != nil {
		return C.CString("Error: Failed to add member locally: " + err.Error())
	}

	// Send GINVITE to new member
	privKey := globalHost.Peerstore().PrivKey(globalHost.ID())
	localKey, _ := corestore.GetGroupLocalKey(meta.GroupID)
	existingMembers, _ := corestore.GetGroupMembersV2(meta.GroupID)
	var memberIDs []string
	for _, m := range existingMembers {
		memberIDs = append(memberIDs, m.PeerID)
	}

	invitePayload := struct {
		Meta    corestore.GroupMetadata `json:"meta"`
		Members []string                `json:"members"`
		GKey    string                  `json:"gkey"`
	}{
		Meta:    meta,
		Members: memberIDs,
		GKey:    base64.StdEncoding.EncodeToString(localKey),
	}
	inviteBytes, _ := json.Marshal(invitePayload)
	inviteMsg := "GINVITE:" + string(inviteBytes)

	targetID, errDec := peer.Decode(member)
	if errDec != nil {
		return C.CString("Error: Invalid member peer ID: " + errDec.Error())
	}

	go func() {
		if _, errSend := coreproto.SendMessage(globalCtx, globalHost, privKey, targetID, inviteMsg); errSend != nil {
			logger.Error().Err(errSend).Str("targetID", targetID.String()).Msg("Failed to send group invite to new member")
		}
	}()

	// Broadcast GCMD:ADD to existing members
	errCtrl := coreproto.SendGroupControlMessage(globalCtx, globalHost, meta.GroupID, "ADD", member)
	if errCtrl != nil {
		return C.CString("Error: Failed to broadcast add command: " + errCtrl.Error())
	}

	return nil
}

//export GroupRemoveMember
func GroupRemoveMember(aliasOrIDStr, memberStr *C.char) *C.char {
	aliasOrID := C.GoString(aliasOrIDStr)
	member := C.GoString(memberStr)

	meta, err := corestore.LoadGroupMetadata(aliasOrID)
	if err != nil {
		aliasName := aliasOrID
		if !strings.HasPrefix(aliasName, "@") {
			aliasName = "@" + aliasName
		}
		meta, err = corestore.LoadGroupMetadata(aliasName)
		if err != nil {
			return C.CString("Error: Group metadata not found: " + err.Error())
		}
	}

	if meta.CreatorID != globalHost.ID().String() {
		return C.CString("Error: Only the Creator can remove members.")
	}

	if strings.HasPrefix(member, "@") {
		resolved, err := coreproto.ResolveAlias(globalCtx, globalHost, member)
		if err == nil {
			member = resolved
		} else {
			return C.CString("Error: Failed to resolve member alias: " + err.Error())
		}
	}

	// Broadcast GCMD:REMOVE
	errCtrl := coreproto.SendGroupControlMessage(globalCtx, globalHost, meta.GroupID, "REMOVE", member)
	if errCtrl != nil {
		return C.CString("Error: Failed to broadcast remove command: " + errCtrl.Error())
	}

	// Process locally
	privKey := globalHost.Peerstore().PrivKey(globalHost.ID())
	payload := fmt.Sprintf("GCMD:REMOVE:%s", member)
	dataToSign := []byte(payload + globalHost.ID().String())
	sigBytes, _ := privKey.Sign(dataToSign)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	gMsg := coreproto.GroupMessage{
		SenderID:  globalHost.ID().String(),
		Payload:   payload,
		Signature: sigB64,
	}

	coreproto.ProcessGroupControlMessage(globalCtx, globalHost, meta.GroupID, gMsg)

	return nil
}

//export GroupExit
func GroupExit(aliasOrIDStr *C.char) *C.char {
	aliasOrID := C.GoString(aliasOrIDStr)

	meta, err := corestore.LoadGroupMetadata(aliasOrID)
	if err != nil {
		aliasName := aliasOrID
		if !strings.HasPrefix(aliasName, "@") {
			aliasName = "@" + aliasName
		}
		meta, err = corestore.LoadGroupMetadata(aliasName)
		if err != nil {
			return C.CString("Error: Group metadata not found: " + err.Error())
		}
	}

	if meta.CreatorID == globalHost.ID().String() {
		return C.CString("Error: Creator cannot exit the group. Use GroupDisband instead.")
	}

	// Broadcast GCMD:EXIT
	errCtrl := coreproto.SendGroupControlMessage(globalCtx, globalHost, meta.GroupID, "EXIT", globalHost.ID().String())
	if errCtrl != nil {
		logger.Warn().Msgf("Failed to broadcast exit command: %v", errCtrl)
	}

	// Exit locally (unsubscribe, close topic, delete metadata)
	coreproto.ExitGroupLocally(meta.GroupID)

	return nil
}

//export GroupDisband
func GroupDisband(aliasOrIDStr *C.char) *C.char {
	aliasOrID := C.GoString(aliasOrIDStr)

	meta, err := corestore.LoadGroupMetadata(aliasOrID)
	if err != nil {
		aliasName := aliasOrID
		if !strings.HasPrefix(aliasName, "@") {
			aliasName = "@" + aliasName
		}
		meta, err = corestore.LoadGroupMetadata(aliasName)
		if err != nil {
			return C.CString("Error: Group metadata not found: " + err.Error())
		}
	}

	if meta.CreatorID != globalHost.ID().String() {
		return C.CString("Error: Only the Creator can disband the group.")
	}

	// Broadcast GCMD:DISBAND
	errCtrl := coreproto.SendGroupControlMessage(globalCtx, globalHost, meta.GroupID, "DISBAND", "")
	if errCtrl != nil {
		return C.CString("Error: Failed to broadcast disband command: " + errCtrl.Error())
	}

	// Disband locally
	privKey := globalHost.Peerstore().PrivKey(globalHost.ID())
	payload := "GCMD:DISBAND:"
	dataToSign := []byte(payload + globalHost.ID().String())
	sigBytes, _ := privKey.Sign(dataToSign)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	gMsg := coreproto.GroupMessage{
		SenderID:  globalHost.ID().String(),
		Payload:   payload,
		Signature: sigB64,
	}

	coreproto.ProcessGroupControlMessage(globalCtx, globalHost, meta.GroupID, gMsg)

	return nil
}

//export GetGroupInfo
func GetGroupInfo(aliasOrIDStr *C.char) *C.char {
	aliasOrID := C.GoString(aliasOrIDStr)

	// Try reading by alias first
	aliasName := aliasOrID
	if !strings.HasPrefix(aliasName, "@") {
		aliasName = "@" + aliasName
	}
	meta, err := corestore.LoadGroupMetadata(aliasName)
	if err != nil {
		// If fails, try reading directly by GroupID
		meta, err = corestore.LoadGroupMetadata(aliasOrID)
		if err != nil {
			return C.CString("Error: Group metadata not found: " + err.Error())
		}
	}

	members, err := corestore.GetGroupMembersV2(meta.GroupID)
	if err != nil {
		members = []corestore.GroupMemberV2{}
	}

	type MemberJSON struct {
		PeerID string `json:"peer_id"`
		Role   string `json:"role"`
	}

	memberList := []MemberJSON{}
	for _, m := range members {
		memberList = append(memberList, MemberJSON{
			PeerID: m.PeerID,
			Role:   m.Role,
		})
	}

	info := struct {
		GroupID    string       `json:"group_id"`
		GroupAlias string       `json:"group_alias"`
		CreatorID  string       `json:"creator_id"`
		GroupType  string       `json:"group_type"`
		CreatedAt  int64        `json:"created_at"`
		Members    []MemberJSON `json:"members"`
	}{
		GroupID:    meta.GroupID,
		GroupAlias: meta.GroupAlias,
		CreatorID:  meta.CreatorID,
		GroupType:  meta.GroupType,
		CreatedAt:  meta.CreatedAt,
		Members:    memberList,
	}

	bytes, err := json.Marshal(info)
	if err != nil {
		return C.CString("Error: Failed to serialize group info: " + err.Error())
	}

	return C.CString(string(bytes))
}

//export GetJoinedGroups
func GetJoinedGroups() *C.char {
	if globalHost == nil {
		return C.CString("[]")
	}

	rows, err := corestore.DB.Query(`SELECT DISTINCT group_id FROM group_members_v2 WHERE peer_id = ?`, globalHost.ID().String())
	if err != nil {
		return C.CString("[]")
	}
	defer rows.Close()

	var groupIDs []string
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err == nil {
			groupIDs = append(groupIDs, gid)
		}
	}
	rows.Close() // Close rows early to release database connection in connection pool

	type GroupJSON struct {
		GroupID    string `json:"group_id"`
		GroupAlias string `json:"group_alias"`
		CreatorID  string `json:"creator_id"`
		GroupType  string `json:"group_type"`
		CreatedAt  int64  `json:"created_at"`
	}

	groups := []GroupJSON{}
	for _, gid := range groupIDs {
		meta, err := corestore.LoadGroupMetadata(gid)
		if err == nil {
			groups = append(groups, GroupJSON{
				GroupID:    meta.GroupID,
				GroupAlias: meta.GroupAlias,
				CreatorID:  meta.CreatorID,
				GroupType:  meta.GroupType,
				CreatedAt:  meta.CreatedAt,
			})
		}
	}

	bytes, err := json.Marshal(groups)
	if err != nil {
		return C.CString("[]")
	}

	return C.CString(string(bytes))
}

//export TriggerMailboxFetch
func TriggerMailboxFetch() *C.char {
	if globalHost == nil {
		return C.CString("Error: Node not started")
	}
	priv := globalHost.Peerstore().PrivKey(globalHost.ID())
	fetchedCount := 0
	for _, p := range globalHost.Network().Peers() {
		protos, _ := globalHost.Peerstore().GetProtocols(p)
		isRelay := false
		for _, proto := range protos {
			if string(proto) == coreproto.InfrastructureProtocolID {
				isRelay = true
				break
			}
		}
		if isRelay {
			logger.Info().Str("peerID", p.String()).Msg("FFI: Triggering manual mailbox fetch")
			go coreproto.FetchMailboxMessages(globalCtx, globalHost, p, priv)
			fetchedCount++
		}
	}
	return C.CString(fmt.Sprintf("Triggered fetch on %d relays", fetchedCount))
}

//export UploadFile
func UploadFile(filePathStr *C.char) *C.char {
	if globalHost == nil {
		return C.CString(`{"error":"Node not started"}`)
	}

	filePath := C.GoString(filePathStr)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return C.CString(fmt.Sprintf(`{"error":"Failed to read file: %s"}`, err.Error()))
	}
	filename := filepath.Base(filePath)

	manifestCID, key, thumbnail, err := corestore.UploadFile(globalCtx, data, filename)
	if err != nil {
		return C.CString(fmt.Sprintf(`{"error":"Failed to upload file: %s"}`, err.Error()))
	}
	coreproto.AddFileSent(int64(len(data))) // Track file sent bytes

	// Trigger replication of media file blocks to connected Dedicated Relays
	go coreproto.ReplicateFileToRelays(globalCtx, globalHost, manifestCID)

	resp := struct {
		ManifestCID string `json:"manifest_cid"`
		Key         string `json:"key"`
		Thumbnail   string `json:"thumbnail"`
	}{
		ManifestCID: manifestCID,
		Key:         key,
		Thumbnail:   thumbnail,
	}

	bytes, _ := json.Marshal(resp)
	return C.CString(string(bytes))
}

//export DownloadFile
func DownloadFile(manifestCIDStr, keyB64Str, savePathStr *C.char) *C.char {
	if globalHost == nil {
		return C.CString(`{"error":"Node not started"}`)
	}

	manifestCID := C.GoString(manifestCIDStr)
	keyB64 := C.GoString(keyB64Str)
	savePath := C.GoString(savePathStr)

	// Create a 30-second timeout context for download operation to prevent permanent hangs
	downloadCtx, cancel := context.WithTimeout(globalCtx, 30*time.Second)
	defer cancel()

	data, filename, err := corestore.DownloadFile(downloadCtx, manifestCID, keyB64)
	if err != nil {
		return C.CString(fmt.Sprintf(`{"error":"Failed to download file: %s"}`, err.Error()))
	}
	coreproto.AddFileRecv(int64(len(data))) // Track file received bytes

	// Create directories if they do not exist
	dir := filepath.Dir(savePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return C.CString(fmt.Sprintf(`{"error":"Failed to create directory: %s"}`, err.Error()))
	}

	err = os.WriteFile(savePath, data, 0644)
	if err != nil {
		return C.CString(fmt.Sprintf(`{"error":"Failed to write decrypted file: %s"}`, err.Error()))
	}

	resp := struct {
		Success  bool   `json:"success"`
		Filename string `json:"filename"`
	}{
		Success:  true,
		Filename: filename,
	}

	bytes, _ := json.Marshal(resp)
	return C.CString(string(bytes))
}

//export GetPeerConnInfo
func GetPeerConnInfo(peerIDStr *C.char) *C.char {
	type PeerConnInfoResult struct {
		Type      string `json:"type"` // "direct_quic", "direct_webrtc", "relay", "offline"
		RelayVia  string `json:"relay_via,omitempty"`
		IPAddress string `json:"ip_address,omitempty"`
	}

	peerIDRaw := C.GoString(peerIDStr)
	if globalHost == nil || peerIDRaw == "" {
		b, _ := json.Marshal(PeerConnInfoResult{Type: "offline"})
		return C.CString(string(b))
	}

	peerID, err := peer.Decode(peerIDRaw)
	if err != nil {
		b, _ := json.Marshal(PeerConnInfoResult{Type: "offline"})
		return C.CString(string(b))
	}

	conns := globalHost.Network().ConnsToPeer(peerID)
	if len(conns) == 0 {
		if act, found := coreproto.GetPeerActivity(peerIDRaw); found && time.Since(act.LastSeen) < 5*time.Second {
			// Note: We don't store IP in PeerActivityInfo yet, so it won't be in the fallback cache.
			// But that's okay, it will show up when connection is active.
			b, _ := json.Marshal(PeerConnInfoResult{
				Type:     act.Type,
				RelayVia: act.RelayVia,
			})
			return C.CString(string(b))
		}

		b, _ := json.Marshal(PeerConnInfoResult{Type: "offline"})
		return C.CString(string(b))
	}

	// Priority: direct_webrtc = direct_quic > relay
	// Scan all conns; any direct connection wins immediately.
	result := PeerConnInfoResult{Type: "relay"}
	for _, conn := range conns {
		addrStr := conn.RemoteMultiaddr().String()
		
		// Extract IP address from multiaddr (e.g. /ip4/192.168.1.5/udp/...)
		parts := strings.Split(addrStr, "/")
		var ipAddr string
		if len(parts) >= 3 && (parts[1] == "ip4" || parts[1] == "ip6") {
			ipAddr = parts[2]
		}

		if strings.Contains(addrStr, "p2p-circuit") {
			// Circuit relay connection - extract relay peer ID
			for i, part := range parts {
				if part == "p2p-circuit" && i >= 2 {
					for j := i - 1; j >= 0; j-- {
						if parts[j] == "p2p" && j+1 < i {
							result.RelayVia = parts[j+1]
							break
						}
					}
					break
				}
			}
			if result.Type == "relay" {
				result.Type = "relay"
				result.IPAddress = ipAddr
			}
			// Don't break - keep scanning for a direct connection

		} else if strings.Contains(addrStr, "webrtc-direct") {
			result.Type = "direct_webrtc"
			result.RelayVia = ""
			result.IPAddress = ipAddr
			break // direct wins

		} else {
			result.Type = "direct_quic"
			result.RelayVia = ""
			result.IPAddress = ipAddr
			break // direct wins
		}
	}

	coreproto.UpdatePeerActivity(peerIDRaw, result.Type, result.RelayVia)

	b, _ := json.Marshal(result)
	return C.CString(string(b))
}

//export ConnectPeer
func ConnectPeer(peerIDStr *C.char) *C.char {
	peerIDRaw := C.GoString(peerIDStr)
	if globalHost == nil || peerIDRaw == "" {
		return C.CString("Host not initialized or empty Peer ID")
	}

	if strings.Contains(peerIDRaw, "/") {
		// It's a multiaddress! e.g. /ip4/192.168.49.1/tcp/4001/p2p/12D3Koo...
		ma, err := multiaddr.NewMultiaddr(peerIDRaw)
		if err != nil {
			return C.CString("Invalid multiaddress: " + err.Error())
		}
		pinfo, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			return C.CString("Failed to extract Peer info from multiaddress: " + err.Error())
		}
		corenet.AllowPeerExplicitly(pinfo.ID)

		go func() {
			globalHost.Peerstore().AddAddrs(pinfo.ID, pinfo.Addrs, 5*time.Minute)
			logger.Info().Str("target", pinfo.ID.String()).Str("addr", ma.String()).Msg("ConnectPeer: Attempting connection to explicit multiaddr")
			dialCtx, cancel := context.WithTimeout(globalCtx, 5*time.Second)
			defer cancel()
			if err := globalHost.Connect(dialCtx, *pinfo); err != nil {
				logger.Warn().Err(err).Str("target", pinfo.ID.String()).Msg("ConnectPeer: Dial with explicit multiaddr failed")
			} else {
				logger.Info().Str("target", pinfo.ID.String()).Msg("ConnectPeer: Connected via explicit multiaddr!")

				// Open a stream to verify
				streamCtx, cancelStream := context.WithTimeout(globalCtx, 4*time.Second)
				defer cancelStream()
				if s, errStream := globalHost.NewStream(streamCtx, pinfo.ID, "/p2p-core/msg/1.0.0"); errStream == nil {
					s.Close()
				}
			}
		}()
		return nil
	}

	peerID, err := peer.Decode(peerIDRaw)
	if err != nil {
		return C.CString("Invalid Peer ID: " + err.Error())
	}

	// Ensure default seed addresses are in the peerstore if we are connecting to a seed node
	for _, s := range DefaultSeeds {
		ma, err := multiaddr.NewMultiaddr(s)
		if err == nil {
			pinfo, err := peer.AddrInfoFromP2pAddr(ma)
			if err == nil && pinfo.ID == peerID {
				globalHost.Peerstore().AddAddrs(pinfo.ID, pinfo.Addrs, 1*time.Hour)
			}
		}
	}
	corenet.AllowPeerExplicitly(peerID)

	// Run dial in the background so we don't block the UI
	go func() {
		// Pre-fetch mailbox coordinates in the background as preflight
		coreproto.PrefetchMailboxCoords(peerID)

		connected := false

		// 1. Try to connect using cached addresses first if we have them
		cachedAddrs := globalHost.Peerstore().Addrs(peerID)
		logger.Info().Str("target", peerID.String()).Int("cached_count", len(cachedAddrs)).Msg("ConnectPeer: Checked cached addresses")
		if len(cachedAddrs) > 0 {
			logger.Info().Str("target", peerID.String()).Msg("ConnectPeer: Trying cached addresses first...")
			dialCtx, cancel := context.WithTimeout(globalCtx, 3*time.Second)
			pinfo := peer.AddrInfo{
				ID:    peerID,
				Addrs: cachedAddrs,
			}
			err := globalHost.Connect(dialCtx, pinfo)
			cancel()
			if err == nil {
				connected = true
				logger.Info().Str("target", peerID.String()).Msg("ConnectPeer: Connected via cached addresses!")
			} else {
				logger.Warn().Err(err).Str("target", peerID.String()).Msg("ConnectPeer: Dial with cached addresses failed")
			}
		}

		// 2. If not connected, query Kademlia DHT to find fresh addresses and try again
		if !connected && corenet.GlobalDHT != nil {
			logger.Info().Str("target", peerID.String()).Msg("ConnectPeer: Querying DHT FindPeer for fresh addresses...")
			findCtx, cancel := context.WithTimeout(globalCtx, 5*time.Second)
			pinfo, err := corenet.GlobalDHT.FindPeer(findCtx, peerID)
			cancel()
			if err == nil {
				logger.Info().Str("target", peerID.String()).Int("addrs", len(pinfo.Addrs)).Msg("ConnectPeer: Found fresh addresses via DHT")
				globalHost.Peerstore().AddAddrs(peerID, pinfo.Addrs, 5*time.Minute)

				dialCtx2, cancel2 := context.WithTimeout(globalCtx, 5*time.Second)
				defer cancel2()
				if errConnect := globalHost.Connect(dialCtx2, pinfo); errConnect != nil {
					logger.Warn().Err(errConnect).Str("target", peerID.String()).Msg("ConnectPeer: Dial with fresh addresses failed")
				} else {
					logger.Info().Str("target", peerID.String()).Msg("ConnectPeer: Connected via fresh addresses!")
					connected = true
				}
			} else {
				logger.Warn().Err(err).Str("target", peerID.String()).Msg("ConnectPeer: DHT FindPeer failed")
			}
		}

		if connected {
			logger.Info().Str("target", peerID.String()).Msg("ConnectPeer: Proactively opening test stream as connection proof...")
			startStream := time.Now()
			streamCtx, cancelStream := context.WithTimeout(globalCtx, 4*time.Second)
			s, errStream := globalHost.NewStream(streamCtx, peerID, "/p2p-core/msg/1.0.0")
			cancelStream()

			if errStream == nil {
				elapsed := time.Since(startStream)
				routeType := "DIRECT (QUIC/UDP)"
				conns := globalHost.Network().ConnsToPeer(peerID)
				if len(conns) > 0 {
					addrStr := conns[0].RemoteMultiaddr().String()
					if strings.Contains(addrStr, "p2p-circuit") {
						routeType = "RELAYED (Circuit)"
					} else if strings.Contains(addrStr, "webrtc-direct") {
						routeType = "DIRECT (WebRTC)"
					}
				}
				logger.Info().
					Str("peerID", peerID.String()).
					Dur("elapsed", elapsed).
					Str("route", routeType).
					Msg(">>> CONNECTPEER PROOF: Stream established successfully!")
				s.Close()
			} else {
				logger.Warn().
					Err(errStream).
					Str("target", peerID.String()).
					Msg(">>> CONNECTPEER PROOF: Failed to open test stream")
			}
		}
	}()

	return nil // Success
}

//export GetSeedNodes
func GetSeedNodes() *C.char {
	var seeds []string
	for _, s := range DefaultSeeds {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			continue
		}
		pinfo, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		seeds = append(seeds, pinfo.ID.String())
	}

	// Deduplicate seeds
	uniqueSeeds := make(map[string]bool)
	var result []string
	for _, s := range seeds {
		if !uniqueSeeds[s] {
			uniqueSeeds[s] = true
			result = append(result, s)
		}
	}
	return C.CString(strings.Join(result, ","))
}

//export GetIceServers
func GetIceServers() *C.char {
	var hosts []string

	// 1. Extract hosts from default seeds
	for _, s := range DefaultSeeds {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			continue
		}
		if host, ok := extractHostFromMultiaddr(ma); ok {
			hosts = append(hosts, host)
		}
	}

	// 2. Extract hosts from currently connected peers
	if globalHost != nil {
		for _, peerID := range globalHost.Network().Peers() {
			conns := globalHost.Network().ConnsToPeer(peerID)
			for _, conn := range conns {
				remoteAddr := conn.RemoteMultiaddr()
				if host, ok := extractHostFromMultiaddr(remoteAddr); ok {
					hosts = append(hosts, host)
				}
			}
		}
	}

	// Deduplicate hosts
	uniqueHosts := make(map[string]bool)
	var finalHosts []string
	for _, h := range hosts {
		if !uniqueHosts[h] {
			uniqueHosts[h] = true
			finalHosts = append(finalHosts, h)
		}
	}

	// Format as a compact JSON string to return
	var parts []string
	for _, h := range finalHosts {
		parts = append(parts, fmt.Sprintf(`{"urls":["stun:%s:3478"]}`, h))
		parts = append(parts, fmt.Sprintf(`{"urls":["turn:%s:3478"],"username":"meshuser","credential":"meshpass12345"}`, h))
	}

	jsonStr := "[" + strings.Join(parts, ",") + "]"
	return C.CString(jsonStr)
}

func extractHostFromMultiaddr(ma multiaddr.Multiaddr) (string, bool) {
	var host string
	multiaddr.ForEach(ma, func(c multiaddr.Component) bool {
		name := c.Protocol().Name
		if name == "ip4" || name == "ip6" || name == "dns" || name == "dns4" || name == "dns6" || name == "dnsaddr" {
			val := c.Value()
			if val != "127.0.0.1" && val != "::1" && val != "0.0.0.0" {
				host = val
				return false // Stop iterating
			}
		}
		return true
	})
	if host != "" {
		return host, true
	}
	return "", false
}

//export SetLocalProfile
func SetLocalProfile(displayNameVal, avatarCIDVal, avatarKeyVal *C.char) {
	if globalHost == nil {
		return
	}
	displayName := C.GoString(displayNameVal)
	avatarCID := C.GoString(avatarCIDVal)
	avatarKey := C.GoString(avatarKeyVal)

	coreproto.SetLocalProfileInfo(displayName, avatarCID, avatarKey)

	// Save our own profile to the database under our peerID
	myPeerID := globalHost.ID().String()
	_, _, _, existingPath, _ := corestore.GetPeerProfile(myPeerID)
	// If existingPath is empty but the file exists, set it
	if existingPath == "" {
		profilesDir := filepath.Join(corestore.DataDir, "profiles")
		checkPath := filepath.Join(profilesDir, myPeerID+".jpg")
		if _, err := os.Stat(checkPath); err == nil {
			existingPath = checkPath
		}
	}
	if errSave := corestore.SavePeerProfile(myPeerID, displayName, avatarCID, avatarKey, existingPath); errSave != nil {
		logger.Error().Err(errSave).Str("peerID", myPeerID).Msg("Failed to save local peer profile")
	}

	// Publish our new profile metadata to the DHT
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := coreproto.PublishProfile(ctx, globalHost, displayName, avatarCID)
		if err != nil {
			logger.Warn().Err(err).Msg("FFI: Failed to publish local profile update to DHT")
		}
	}()

	// Replicate avatar image blocks to Dedicated Relays so other peers can
	// download the avatar even when we are offline (same as media files).
	if avatarCID != "" {
		go coreproto.ReplicateFileToRelays(globalCtx, globalHost, avatarCID)
	}

	// Broadcast profile update to all peers with active E2EE sessions
	go func() {
		if corestore.DB == nil {
			return
		}
		rows, err := corestore.DB.Query("SELECT peer_id FROM sessions")
		if err != nil {
			return
		}
		defer rows.Close()

		var targets []string
		for rows.Next() {
			var pid string
			if err := rows.Scan(&pid); err == nil && pid != "" {
				targets = append(targets, pid)
			}
		}

		if len(targets) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			coreproto.BroadcastProfileUpdate(ctx, globalHost, targets, displayName, avatarCID, avatarKey)
		}
	}()
}

//export GetPeerProfile
func GetPeerProfile(peerIDVal *C.char) *C.char {
	peerID := C.GoString(peerIDVal)
	displayName, avatarCID, avatarKey, localPath, err := corestore.GetPeerProfile(peerID)
	if err != nil {
		return C.CString("{}")
	}

	// NOTE: Avatar download is intentionally NOT triggered here.
	// Downloads are triggered either:
	//   (a) automatically when the peer connects (peer_connected handler) — peer is guaranteed online
	//   (b) explicitly by the user via DownloadPeerAvatar FFI — for manual retry
	// This avoids silent background failures and battery drain.

	result := struct {
		DisplayName string `json:"display_name"`
		AvatarCID   string `json:"avatar_cid"`
		AvatarKey   string `json:"avatar_key"`
		LocalPath   string `json:"local_path"`
	}{
		DisplayName: displayName,
		AvatarCID:   avatarCID,
		AvatarKey:   avatarKey,
		LocalPath:   localPath,
	}

	data, err := json.Marshal(result)
	if err != nil {
		return C.CString("{}")
	}
	return C.CString(string(data))
}

//export ResolveOfflineProfile
func ResolveOfflineProfile(peerIDVal *C.char) {
	if globalHost == nil {
		return
	}
	peerID := C.GoString(peerIDVal)
	pid, err := peer.Decode(peerID)
	if err == nil {
		corenet.AllowPeerExplicitly(pid)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		name, _, err := coreproto.ResolveProfile(ctx, globalHost, peerID)
		if err == nil {
			logger.Info().Str("peerID", peerID).Str("name", name).Msg("FFI: Resolved profile from DHT successfully")
			// Notify Dart UI
			event := map[string]string{
				"type":   "profile_updated",
				"sender": peerID,
			}
			data, _ := json.Marshal(event)
			eventQueue.Push(string(data))
		} else {
			logger.Warn().Err(err).Str("peerID", peerID).Msg("FFI: Failed to resolve profile from DHT")
		}
	}()
}

//export DownloadPeerAvatar
// DownloadPeerAvatar is the user-triggered avatar download.
// It clears the dedup cache (allowing retry), looks up the peer's CID from DB,
// and triggers a fresh download. Returns immediately; result fires as profile_updated event.
// Returns: "ok" if download started, "no_cid" if no avatar CID known, "error:<msg>" on failure.
func DownloadPeerAvatar(peerIDVal *C.char) *C.char {
	if globalHost == nil {
		return C.CString("error:node not running")
	}
	peerID := C.GoString(peerIDVal)

	// Clear dedup cache so this re-download is not blocked.
	coreproto.ClearAvatarDownloadAttempt(peerID)

	// Look up avatar CID from DB.
	_, avatarCID, avatarKey, _, err := corestore.GetPeerProfile(peerID)
	if err != nil || avatarCID == "" || avatarKey == "" {
		// No CID in DB yet — try resolving from DHT first, then download.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			
			// If peer is connected, send a session warmup probe so they send us their profile key share
			pid, decodeErr := peer.Decode(peerID)
			if decodeErr == nil && globalHost != nil && len(globalHost.Network().ConnsToPeer(pid)) > 0 {
				logger.Info().Str("peerID", peerID).Msg("DownloadPeerAvatar: peer is online but key is missing, sending warmup probe to request key")
				priv := globalHost.Peerstore().PrivKey(globalHost.ID())
				if priv != nil {
					coreproto.ProbeSessionWarmup(ctx, globalHost, priv, pid)
				}
			}

			name, _, resolveErr := coreproto.ResolveProfile(ctx, globalHost, peerID)
			if resolveErr != nil {
				logger.Warn().Err(resolveErr).Str("peerID", peerID).Msg("DownloadPeerAvatar: DHT resolve failed")
				// Fire profile_updated so Dart can show error state.
				event := map[string]string{"type": "profile_updated", "sender": peerID, "status": "error"}
				data, _ := json.Marshal(event)
				eventQueue.Push(string(data))
				return
			}
			logger.Info().Str("peerID", peerID).Str("name", name).Msg("DownloadPeerAvatar: resolved from DHT, now downloading avatar")
			// Re-read CID from DB after DHT resolve.
			_, cid2, key2, _, _ := corestore.GetPeerProfile(peerID)
			if cid2 != "" && key2 != "" {
				coreproto.TriggerAvatarDownload(peerID, cid2, key2)
			}
			// profile_updated fires internally when download completes.
		}()
		return C.CString("ok:resolving")
	}

	// CID is known — trigger download directly.
	logger.Info().Str("peerID", peerID).Str("cid", avatarCID).Msg("DownloadPeerAvatar: user-triggered download started")
	coreproto.TriggerAvatarDownload(peerID, avatarCID, avatarKey)
	return C.CString("ok:downloading")
}

//export SendProfileKeyShare
func SendProfileKeyShare(peerIDVal *C.char) *C.char {
	if globalHost == nil {
		return C.CString("Node not running")
	}
	peerID := C.GoString(peerIDVal)
	pid, err := peer.Decode(peerID)
	if err != nil {
		return C.CString("Invalid peer ID: " + err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = coreproto.SendProfileKeyShare(ctx, globalHost, pid)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export BroadcastProfileUpdate
func BroadcastProfileUpdate(targetsCSV, displayNameVal, avatarCIDVal, avatarKeyVal *C.char) {
	if globalHost == nil {
		return
	}
	targets := strings.Split(C.GoString(targetsCSV), ",")
	displayName := C.GoString(displayNameVal)
	avatarCID := C.GoString(avatarCIDVal)
	avatarKey := C.GoString(avatarKeyVal)

	ctx := context.Background()
	coreproto.BroadcastProfileUpdate(ctx, globalHost, targets, displayName, avatarCID, avatarKey)
}

//export RegisterFCMToken
func RegisterFCMToken(tokenStr, fcmServicePubKeyB64Str *C.char) *C.char {
	if globalHost == nil {
		return C.CString("Error: Node not started")
	}

	token := C.GoString(tokenStr)
	pubKeyB64 := C.GoString(fcmServicePubKeyB64Str)

	if token == "" || pubKeyB64 == "" {
		return C.CString("Error: Empty token or public key")
	}

	// 1. Decode FCM Service Public Key
	fcmPubBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return C.CString("Error: Invalid public key base64: " + err.Error())
	}

	// 2. Generate Ephemeral Keypair for ECIES
	ephemeralPriv, ephemeralPub, err := corecrypto.GenerateEphemeralKeypair()
	if err != nil {
		return C.CString("Error: Failed to generate ephemeral keypair: " + err.Error())
	}

	// 3. Compute Shared Secret via ECDH
	aesKey, err := corecrypto.DeriveSharedSecret(ephemeralPriv, fcmPubBytes)
	if err != nil {
		return C.CString("Error: Failed to derive shared secret: " + err.Error())
	}

	// 4. Encrypt FCM token using AES-GCM
	ciphertext, err := corecrypto.EncryptMessage(aesKey, token)
	if err != nil {
		return C.CString("Error: Failed to encrypt token: " + err.Error())
	}

	// 5. Construct Signed Payload JSON (what the client signs)
	signedPayload := struct {
		EphemeralPub string `json:"ephemeral_pub"`
		Ciphertext   string `json:"ciphertext"`
	}{
		EphemeralPub: base64.StdEncoding.EncodeToString(ephemeralPub),
		Ciphertext:   ciphertext,
	}

	signedPayloadBytes, _ := json.Marshal(signedPayload)
	signedPayloadStr := string(signedPayloadBytes)

	// 6. Sign the payload using P2P Node Private Key to authenticate the register request
	privKey := globalHost.Peerstore().PrivKey(globalHost.ID())
	sigBytes, err := privKey.Sign([]byte(signedPayloadStr))
	if err != nil {
		return C.CString("Error: Failed to sign payload: " + err.Error())
	}

	senderPubBytes, err := crypto.MarshalPublicKey(privKey.GetPublic())
	if err != nil {
		return C.CString("Error: Failed to marshal sender public key: " + err.Error())
	}

	// 7. Construct Final Payload containing client_sig
	finalPayload := struct {
		EphemeralPub string `json:"ephemeral_pub"`
		Ciphertext   string `json:"ciphertext"`
		ClientSig    string `json:"client_sig"`
	}{
		EphemeralPub: base64.StdEncoding.EncodeToString(ephemeralPub),
		Ciphertext:   ciphertext,
		ClientSig:    base64.StdEncoding.EncodeToString(sigBytes),
	}
	finalPayloadBytes, _ := json.Marshal(finalPayload)
	finalPayloadStr := string(finalPayloadBytes)

	// 8. Construct P2P register request object
	regRequest := struct {
		OwnerID   string `json:"owner_id"`
		Payload   string `json:"payload"`
		Sender    string `json:"sender"`
		Signature string `json:"signature"`
	}{
		OwnerID:   globalHost.ID().String(),
		Payload:   finalPayloadStr,
		Sender:    base64.StdEncoding.EncodeToString(senderPubBytes),
		Signature: base64.StdEncoding.EncodeToString(sigBytes),
	}

	regRequestBytes, _ := json.Marshal(regRequest)

	// 8. Open stream to all seed Dedicated Relays to broadcast registration
	var succeededRelays []string

	for _, s := range DefaultSeeds {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			continue
		}
		pinfo, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}

		dialCtx, cancel := context.WithTimeout(globalCtx, 4*time.Second)
		// Ensure relay address is in the peerstore
		globalHost.Peerstore().AddAddrs(pinfo.ID, pinfo.Addrs, 5*time.Minute)
		corenet.AllowPeerExplicitly(pinfo.ID)

		// Connect and send
		if errConnect := globalHost.Connect(dialCtx, *pinfo); errConnect == nil {
			sStream, errStream := globalHost.NewStream(dialCtx, pinfo.ID, protocol.ID(coreproto.FCMRegisterProtocolID))
			if errStream == nil {
				_, _ = sStream.Write(regRequestBytes)
				sStream.Close()
				succeededRelays = append(succeededRelays, pinfo.ID.String())
			}
		}
		cancel()
	}

	if len(succeededRelays) == 0 {
		return C.CString("Error: Failed to register with any active Dedicated Relay")
	}

	return C.CString("Success: Registered with relays: " + strings.Join(succeededRelays, ", "))
}

func main() {
	// Mandatory main for C-shared libraries, but unused
}
