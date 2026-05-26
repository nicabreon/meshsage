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
}

func NewQueue() *Queue {
	q := &Queue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *Queue) Push(event string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = append(q.events, event)
	q.cond.Signal()
}

func (q *Queue) Pop() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.events) == 0 {
		q.cond.Wait()
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

	// Build the Node host
	host, err := corenet.NewNode(globalCtx, corenet.Config{
		ListenAddr:   fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
		PrivateKey:   priv,
		DataDir:      filepath.Dir(dbPath),
		StaticRelays: staticRelays,
		RelaySource:  relaySource,
		ForcePublic:  false,
	})
	if err != nil {
		return C.CString("Failed to build host: " + err.Error())
	}
	globalHost = host

	// 6. Global Modes
	corenet.IsDedicated = false
	corenet.IsClientOnly = isClientOnly

	// 7. Initialize Protocols
	dhtRouting, err := corenet.SetupDHT(globalCtx, host)
	if err != nil {
		return C.CString("Failed to init DHT: " + err.Error())
	}
	_ = corenet.SetupBitswap(globalCtx, host, dhtRouting)
	_ = corenet.SetupPubSub(globalCtx, host)
	_ = corenet.SetupDiscovery(host)

	coreproto.SetupMessaging(host)
	coreproto.SetupMailbox(host, isClientOnly)
	coreproto.SetupPreKeyService(host)
	coreproto.SetupAliasService(host)
	coreproto.SetupClusterSync(globalCtx, host)

	// Hook the structured message callback to send JSON events to the queue
	coreproto.MessageCallback = func(event coreproto.MessageEvent) {
		data, err := json.Marshal(map[string]interface{}{
			"type":      "message",
			"msg_type":  event.Type,
			"timestamp": event.Timestamp,
			"sender":    event.Sender,
			"group_id":  event.GroupID,
			"content":   event.Content,
		})
		if err == nil {
			eventQueue.Push(string(data))
		}
	}

	// Restore group memberships
	_ = coreproto.RestoreGroups(globalCtx, host, priv)

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
				time.Sleep(2 * time.Second)
				protos, err := host.Peerstore().GetProtocols(remoteID)
				if err != nil {
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
					logger.Info().Str("peerID", remoteID.String()).Msg("IDENTIFIED INFRASTRUCTURE: Triggering Pre-Key refill, Mailbox fetch, and Notification subscription")
					go coreproto.AutoRefillPreKeys(globalCtx, host, remoteID, priv)
					go coreproto.FetchMailboxMessages(globalCtx, host, remoteID, priv)
					go coreproto.SubscribeNotifications(globalCtx, host, remoteID, nil)
				}
			}()
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
				if host.Network().Connectedness(pinfo.ID) != network.Connected {
					go host.Connect(globalCtx, *pinfo)
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

	targetID, err := peer.Decode(target)
	if err != nil {
		return C.CString("Invalid peer ID: " + err.Error())
	}

	err = coreproto.SendMessage(globalCtx, globalHost, globalPriv, targetID, content)
	if err != nil {
		return C.CString("Failed to send: " + err.Error())
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

	err := coreproto.RegisterAlias(globalCtx, globalHost, peerID, alias)
	if err != nil {
		return C.CString("Failed to set alias: " + err.Error())
	}
	return nil
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
	event := eventQueue.Pop()
	return C.CString(event)
}

//export FreeString
func FreeString(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
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
	errJoin := coreproto.JoinGroupProper(globalCtx, globalHost, privKey, groupID, alias, globalHost.ID().String(), groupType, sigB64, members)
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
					_ = coreproto.SendMessage(globalCtx, globalHost, privKey, t, inviteMsg)
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
	errJoin := coreproto.JoinGroupProper(globalCtx, globalHost, privKey, meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.Signature, []string{})
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

	if !strings.HasPrefix(aliasOrID, "@") {
		aliasOrID = "@" + aliasOrID
	}

	meta, err := corestore.LoadGroupMetadata(aliasOrID)
	if err != nil {
		return C.CString("Error: Group metadata not found: " + err.Error())
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
		_ = coreproto.SendMessage(globalCtx, globalHost, privKey, targetID, inviteMsg)
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

	if !strings.HasPrefix(aliasOrID, "@") {
		aliasOrID = "@" + aliasOrID
	}

	meta, err := corestore.LoadGroupMetadata(aliasOrID)
	if err != nil {
		return C.CString("Error: Group metadata not found: " + err.Error())
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

	if !strings.HasPrefix(aliasOrID, "@") {
		aliasOrID = "@" + aliasOrID
	}

	meta, err := corestore.LoadGroupMetadata(aliasOrID)
	if err != nil {
		return C.CString("Error: Group metadata not found: " + err.Error())
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

	if !strings.HasPrefix(aliasOrID, "@") {
		aliasOrID = "@" + aliasOrID
	}

	meta, err := corestore.LoadGroupMetadata(aliasOrID)
	if err != nil {
		return C.CString("Error: Group metadata not found: " + err.Error())
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

	var memberList []MemberJSON
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

	type GroupJSON struct {
		GroupID    string `json:"group_id"`
		GroupAlias string `json:"group_alias"`
		CreatorID  string `json:"creator_id"`
		GroupType  string `json:"group_type"`
		CreatedAt  int64  `json:"created_at"`
	}

	var groups []GroupJSON
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err == nil {
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
	}

	bytes, err := json.Marshal(groups)
	if err != nil {
		return C.CString("[]")
	}

	return C.CString(string(bytes))
}

func main() {
	// Mandatory main for C-shared libraries, but unused
}

