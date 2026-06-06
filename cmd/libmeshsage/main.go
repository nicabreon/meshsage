package main

/*
#include <stdlib.h>
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
	q.events = append(q.events, event)
	q.cond.Signal()
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

// -----------------------------------------------------------------------------
// EXPORTED C FUNCTIONS
// -----------------------------------------------------------------------------

//export StartNode
func StartNode(dbPathStr, idPathStr *C.char, port C.int, isClientOnlyVal C.int) *C.char {
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

	dbPath := C.GoString(dbPathStr)
	idPath := C.GoString(idPathStr)
	isClientOnly := isClientOnlyVal != 0

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
		})
		if err != nil {
			return C.CString("Failed to build host: " + err.Error())
		}
	}
	globalHost = host

	// 6. Global Modes
	corenet.IsDedicated = false
	corenet.IsClientOnly = isClientOnly
	corenet.ForceClientOnly = isClientOnly

	// 7. Initialize Protocols
	dhtRouting, err := corenet.SetupDHT(globalCtx, host)
	if err != nil {
		return C.CString("Failed to init DHT: " + err.Error())
	}
	_ = corenet.SetupBitswap(globalCtx, host, dhtRouting)
	_ = corenet.SetupPubSub(globalCtx, host)
	_ = corenet.SetupDiscovery(globalCtx, host)

	coreproto.SetupMessaging(host)
	coreproto.SetupMailbox(host, isClientOnly)
	coreproto.SetupPreKeyService(host)
	coreproto.SetupAliasService(host)
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

	// Hook the status callback to forward delivery receipts to Flutter
	coreproto.StatusCallback = func(event coreproto.StatusEvent) {
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
					_ = coreproto.RestoreGroups(globalCtx, host, priv)
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
					// Proactive session warm-up disabled.
					logger.Debug().Str("peerID", remoteID.String()).Msg("Peer is a standard node (not infrastructure)")
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

	// Start reconnection loops in background
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			for _, s := range DefaultSeeds {
				ma, err := multiaddr.NewMultiaddr(s)
				if err != nil {
					continue
				}
				pinfo, err := peer.AddrInfoFromP2pAddr(ma)
				if err != nil {
					continue
				}
				if pinfo.ID == host.ID() {
					continue
				}

				if host.Network().Connectedness(pinfo.ID) == network.Connected {
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
					}(pinfo.ID)
				} else {
					// Clear dial backoff to allow immediate reconnection attempt.
					if s, ok := host.Network().(*swarm.Swarm); ok {
						s.Backoff().Clear(pinfo.ID)
					}
					logger.Debug().Str("peerID", pinfo.ID.String()).Msg("Attempting to reconnect to seed...")
					go func(pi peer.AddrInfo) {
						if errDial := host.Connect(globalCtx, pi); errDial != nil {
							logger.Debug().Err(errDial).Str("peerID", pi.ID.String()).Msg("Reconnection failed")
						} else {
							logger.Info().Str("peerID", pi.ID.String()).Msg("Successfully reconnected to seed node")
						}
					}(*pinfo)
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

		eventQueue.Close()
		// Replace with fresh queue for future restarts
		eventQueue = NewQueue()
	}
}

//export GetNetworkStats
func GetNetworkStats() *C.char {
	return C.CString(coreproto.GetNetworkStatsJSON())
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
					_, _ = coreproto.SendMessage(globalCtx, globalHost, privKey, t, inviteMsg)
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
		_, _ = coreproto.SendMessage(globalCtx, globalHost, privKey, targetID, inviteMsg)
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
			if string(proto) == "/p2p-core/mailbox/1.0.0" {
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
		Type     string `json:"type"` // "direct_quic", "direct_webrtc", "relay", "offline"
		RelayVia string `json:"relay_via,omitempty"`
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
		b, _ := json.Marshal(PeerConnInfoResult{Type: "offline"})
		return C.CString(string(b))
	}

	// Priority: direct_webrtc = direct_quic > relay
	// Scan all conns; any direct connection wins immediately.
	result := PeerConnInfoResult{Type: "relay"}
	for _, conn := range conns {
		addrStr := conn.RemoteMultiaddr().String()

		if strings.Contains(addrStr, "p2p-circuit") {
			// Circuit relay connection - extract relay peer ID
			// Format: /ip4/.../p2p/<relayID>/p2p-circuit/p2p/<targetID>
			parts := strings.Split(addrStr, "/")
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
			result.Type = "relay"
			// Don't break - keep scanning for a direct connection

		} else if strings.Contains(addrStr, "webrtc-direct") {
			// WebRTC Direct - ICE host candidates only (no STUN)
			result.Type = "direct_webrtc"
			result.RelayVia = ""
			break // direct wins

		} else {
			// QUIC or other direct transport
			result.Type = "direct_quic"
			result.RelayVia = ""
			break // direct wins
		}
	}

	b, _ := json.Marshal(result)
	return C.CString(string(b))
}

//export ConnectPeer
func ConnectPeer(peerIDStr *C.char) *C.char {
	peerIDRaw := C.GoString(peerIDStr)
	if globalHost == nil || peerIDRaw == "" {
		return C.CString("Host not initialized or empty Peer ID")
	}

	peerID, err := peer.Decode(peerIDRaw)
	if err != nil {
		return C.CString("Invalid Peer ID: " + err.Error())
	}

	// Run dial in the background so we don't block the UI
	go func() {
		// Pre-fetch mailbox coordinates in the background as preflight
		coreproto.PrefetchMailboxCoords(peerID)

		connected := false
		
		// 1. Try to connect using cached addresses first if we have them
		if len(globalHost.Peerstore().Addrs(peerID)) > 0 {
			logger.Debug().Str("target", peerID.String()).Msg("ConnectPeer: Trying cached addresses first...")
			dialCtx, cancel := context.WithTimeout(globalCtx, 3*time.Second)
			pinfo := peer.AddrInfo{
				ID:    peerID,
				Addrs: globalHost.Peerstore().Addrs(peerID),
			}
			err := globalHost.Connect(dialCtx, pinfo)
			cancel()
			if err == nil {
				connected = true
				logger.Info().Str("target", peerID.String()).Msg("ConnectPeer: Connected via cached addresses!")
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
	}()

	return nil // Success
}

func main() {
	// Mandatory main for C-shared libraries, but unused
}

