package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"


	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	coreproto "github.com/nicabreon/meshsage/pkg/protocol"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

// Node represents the P2P stack instance.
type Node struct {
	host host.Host
	ctx  context.Context
	priv crypto.PrivKey
}

var (
	nodeInstance *Node
	nodeMutex    sync.Mutex
)

// Main function is required for c-shared build mode but not used.
func main() {}

// --- Helper Functions ---

func cString(s string) *C.char {
	return C.CString(s)
}

func goString(s *C.char) string {
	return C.GoString(s)
}

// --- Exported C API ---

//export InitNode
func InitNode(port C.int, dataDir *C.char) *C.char {
	nodeMutex.Lock()
	defer nodeMutex.Unlock()

	if nodeInstance != nil {
		return cString("Node already initialized")
	}

	ctx := context.Background()
	path := goString(dataDir)
	identityFile := filepath.Join(path, "identity.key")
	dbFile := filepath.Join(path, "messages.db")

	var priv crypto.PrivKey
	var err error

	if _, statErr := os.Stat(identityFile); os.IsNotExist(statErr) {
		priv, _, err = corecrypto.GenerateKeyPair()
		if err != nil { return cString(err.Error()) }
		if err = corestore.SavePrivateKey(priv, identityFile); err != nil {
			return cString(err.Error())
		}
	} else {
		priv, err = corestore.LoadPrivateKey(identityFile)
		if err != nil { return cString(err.Error()) }
	}

	cfg := corenet.Config{
		ListenAddr: fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", int(port)),
		PrivateKey: priv,
	}

	h, err := corenet.NewNode(ctx, cfg)
	if err != nil { return cString(err.Error()) }

	dhtRouting, err := corenet.SetupDHT(ctx, h)
	if err != nil { return cString(err.Error()) }

	_ = corenet.SetupBitswap(ctx, h, dhtRouting)
	_ = corenet.SetupPubSub(ctx, h)
	_ = corestore.InitDatabase(dbFile)

	coreproto.SetupMessaging(h)
	coreproto.SetupMailbox(h)
	coreproto.SetupAliasService(h)
	_ = corenet.SetupDiscovery(h)

	nodeInstance = &Node{host: h, ctx: ctx, priv: priv}
	return nil // Success
}

//export GetPeerID
func GetPeerID() *C.char {
	if nodeInstance == nil { return cString("") }
	return cString(nodeInstance.host.ID().String())
}

//export RegisterAlias
func RegisterAlias(name *C.char) *C.char {
	if nodeInstance == nil { return cString("Node not initialized") }
	err := coreproto.RegisterAlias(nodeInstance.ctx, nodeInstance.host, goString(name), nodeInstance.host.ID().String())
	if err != nil { return cString(err.Error()) }
	return nil
}

//export ResolveAlias
func ResolveAlias(name *C.char) *C.char {
	if nodeInstance == nil { return cString("") }
	res, err := coreproto.ResolveAlias(nodeInstance.ctx, nodeInstance.host, goString(name))
	if err != nil { return cString("") }
	return cString(res)
}

//export SendMessage
func SendMessage(target *C.char, message *C.char) *C.char {
	if nodeInstance == nil { return cString("Node not initialized") }
	
	targetStr := goString(target)
	msgStr := goString(message)

	if strings.HasPrefix(targetStr, "@") {
		resolved, err := coreproto.ResolveAlias(nodeInstance.ctx, nodeInstance.host, targetStr)
		if err != nil { return cString(err.Error()) }
		targetStr = resolved
	}

	targetID, err := peer.Decode(targetStr)
	if err != nil { return cString(err.Error()) }

	err = coreproto.SendMessage(nodeInstance.ctx, nodeInstance.host, nodeInstance.priv, targetID, msgStr)
	if err != nil { return cString(err.Error()) }
	return nil
}

//export FetchMessages
func FetchMessages() *C.char {
	if nodeInstance == nil { return cString("[]") }
	
	type DecryptedMsg struct {
		Sender    string `json:"sender"`
		Body      string `json:"body"`
		IsFile    bool   `json:"is_file"`
		GroupID   string `json:"group_id,omitempty"`
		CID       string `json:"cid,omitempty"`
		Key       string `json:"key,omitempty"`
		Thumbnail string `json:"thumbnail,omitempty"`
	}

	var result []DecryptedMsg
	myID := nodeInstance.host.ID().String()

	// 1. Fetch personal messages
	personalMsgs, _ := coreproto.FetchOfflineMessages(nodeInstance.ctx, nodeInstance.host, nodeInstance.host.ID())
	
	// 2. Fetch messages for all joined groups
	groupIDs, _ := corestore.GetGroupMemberships(myID)
	var allMsgs []corestore.MailboxMessage
	allMsgs = append(allMsgs, personalMsgs...)

	for _, gid := range groupIDs {
		gID, err := peer.Decode(gid)
		if err != nil { continue }
		gMsgs, _ := coreproto.FetchOfflineMessages(nodeInstance.ctx, nodeInstance.host, gID)
		
		for i := range gMsgs {
			gMsgs[i].RecipientID = gid 
		}
		allMsgs = append(allMsgs, gMsgs...)
	}

	for _, m := range allMsgs {
		var decrypted string
		var decryptErr error
		senderID := m.SenderPubkey

		if m.RecipientID != myID && m.RecipientID != "" {
			// Pesan GRUP
			var gMsg coreproto.GroupMessage
			if err := json.Unmarshal([]byte(m.Payload), &gMsg); err == nil {
				senderID = gMsg.SenderID
				key, err := corestore.GetGroupSenderKey(m.RecipientID, senderID)
				if err == nil {
					decrypted, decryptErr = corecrypto.DecryptMessage(key, gMsg.Payload)
				} else {
					decryptErr = err
				}
			} else {
				decryptErr = err
			}
		} else {
			// Pesan 1:1
			ephemeralKey := corecrypto.DeriveKeyFromPassword(myID + m.SenderPubkey)
			decrypted, decryptErr = corecrypto.DecryptMessage(ephemeralKey, m.Payload)
		}

		if decryptErr != nil { continue }
		
		msgObj := DecryptedMsg{Sender: senderID, Body: decrypted, IsFile: false}
		if m.RecipientID != myID && m.RecipientID != "" {
			msgObj.GroupID = m.RecipientID
		}

		// LOGIKA FILE (Kembali direstorasi)
		if strings.HasPrefix(decrypted, "__FILE__:") {
			parts := strings.Split(decrypted, ":")
			if len(parts) >= 5 {
				msgObj.IsFile = true
				msgObj.CID = parts[1]
				msgObj.Key = parts[2]
				msgObj.Body = fmt.Sprintf("File: %s", parts[3])
				if len(parts) >= 6 { msgObj.Thumbnail = parts[5] }
			}
		} else {
			// Logika stripping Message ID (misal msgID:content)
			parts := strings.SplitN(decrypted, ":", 2)
			if len(parts) == 2 { msgObj.Body = parts[1] }
		}
		
		result = append(result, msgObj)
	}

	jsonBytes, _ := json.Marshal(result)
	return cString(string(jsonBytes))
}

//export CreateGroup
func CreateGroup(groupID *C.char, membersCSV *C.char) *C.char {
	if nodeInstance == nil { return cString("SDK not initialized") }
	gid := C.GoString(groupID)
	mCSV := C.GoString(membersCSV)
	members := strings.Split(mCSV, ",")
	
	err := coreproto.JoinGroup(nodeInstance.ctx, nodeInstance.host, nodeInstance.priv, gid, members)
	if err != nil { return cString(err.Error()) }
	return nil
}

//export SendGroupMessage
func SendGroupMessage(groupID *C.char, message *C.char) *C.char {
	if nodeInstance == nil { return cString("SDK not initialized") }
	gid := C.GoString(groupID)
	msg := C.GoString(message)
	
	err := coreproto.SendGroupMessage(nodeInstance.ctx, nodeInstance.host, gid, msg)
	if err != nil { return cString(err.Error()) }
	return nil
}

//export StopNode
func StopNode() {
	if nodeInstance != nil {
		nodeInstance.host.Close()
		nodeInstance = nil
	}
}
