package protocol

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	"github.com/nicabreon/meshsage/pkg/logger"
)

type GroupMessage struct {
	SenderID  string `json:"sender_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"` // Sender's signature over payload + sender_id
}

type GroupSession struct {
	Topic    *pubsub.Topic
	Sub      *pubsub.Subscription
	Host     host.Host
}

var (
	activeGroups      = make(map[string]*GroupSession)
	groupsMutex       sync.Mutex
	processedMessages = make(map[string]bool)
	processedMutex    sync.Mutex
)

// ---------------------------------------------------------------------------
// PENDING MESSAGE BUFFER
// Stores messages that arrived before the sender's group key was available.
// Flushed automatically once the key arrives via GKEY or GINVITE.
// ---------------------------------------------------------------------------

const (
	pendingMsgTTL     = 5 * time.Minute
	pendingMsgMaxPerSender = 20
)

type pendingGroupMsg struct {
	receivedAt time.Time
	gMsg       GroupMessage
	ctx        context.Context
	session    *GroupSession
	groupID    string
}

var (
	// pendingGroupMessages: groupID → senderID → []pendingGroupMsg
	pendingGroupMessages   = make(map[string]map[string][]pendingGroupMsg)
	pendingGroupMessagesMu sync.Mutex
)

// bufferPendingMessage stores a group message that cannot be decrypted yet (missing key).
func bufferPendingMessage(groupID, senderID string, msg pendingGroupMsg) {
	pendingGroupMessagesMu.Lock()
	defer pendingGroupMessagesMu.Unlock()

	if pendingGroupMessages[groupID] == nil {
		pendingGroupMessages[groupID] = make(map[string][]pendingGroupMsg)
	}

	existing := pendingGroupMessages[groupID][senderID]

	// Prune expired messages
	now := time.Now()
	pruned := existing[:0]
	for _, m := range existing {
		if now.Sub(m.receivedAt) < pendingMsgTTL {
			pruned = append(pruned, m)
		}
	}

	// Enforce max-per-sender cap (drop oldest if over limit)
	if len(pruned) >= pendingMsgMaxPerSender {
		pruned = pruned[1:]
	}

	pendingGroupMessages[groupID][senderID] = append(pruned, msg)
	logger.Debug().
		Str("group", groupID).
		Str("sender", FormatPeerID(senderID)).
		Int("buffered", len(pendingGroupMessages[groupID][senderID])).
		Msg("[Group Buffer] Message buffered (senderKey not yet available)")
}

// FlushPendingGroupMessages tries to decrypt all buffered messages for a given
// group+sender after their key has been received.
// Called from messaging.go after SaveGroupSenderKey().
func FlushPendingGroupMessages(groupID, senderID string) {
	pendingGroupMessagesMu.Lock()
	pending, ok := pendingGroupMessages[groupID][senderID]
	if !ok || len(pending) == 0 {
		pendingGroupMessagesMu.Unlock()
		return
	}
	// Take ownership of the slice and clear from map
	pendingGroupMessages[groupID][senderID] = nil
	pendingGroupMessagesMu.Unlock()

	logger.Info().
		Str("group", groupID).
		Str("sender", FormatPeerID(senderID)).
		Int("count", len(pending)).
		Msg("[Group Buffer] Flushing buffered messages after key received")

	now := time.Now()
	for _, pm := range pending {
		// Drop TTL-expired entries
		if now.Sub(pm.receivedAt) >= pendingMsgTTL {
			logger.Debug().Str("group", groupID).Msg("[Group Buffer] Dropping expired buffered message")
			continue
		}
		decryptAndDispatchGroupMsg(pm.ctx, pm.session, pm.groupID, pm.gMsg)
	}
}

// checkAndMarkProcessed returns true if the message signature has already been processed
func checkAndMarkProcessed(signature string) bool {
	if signature == "" {
		return false
	}
	processedMutex.Lock()
	defer processedMutex.Unlock()
	if processedMessages[signature] {
		return true
	}
	if len(processedMessages) > 10000 {
		processedMessages = make(map[string]bool)
	}
	processedMessages[signature] = true
	return false
}

// JoinGroup is deprecated. Replaced by JoinGroupProper to support metadata governance.
func JoinGroup(ctx context.Context, h host.Host, priv crypto.PrivKey, groupID string, members []string) error {
	// Replaced by JoinGroupProper. We keep this empty or delegate to it with default values for compatibility.
	alias := "@" + groupID
	signature := ""
	return JoinGroupProper(ctx, h, priv, groupID, alias, h.ID().String(), "SECURE", signature, members)
}

// JoinGroupProper joins a GossipSub topic, initializes Group Metadata/Members, and sets up keys
func JoinGroupProper(ctx context.Context, h host.Host, priv crypto.PrivKey, groupID, groupAlias, creatorID, groupType, signature string, members []string) error {
	groupsMutex.Lock()
	defer groupsMutex.Unlock()

	if _, exists := activeGroups[groupID]; exists {
		return nil
	}

	if corenet.GlobalPubSub == nil {
		return fmt.Errorf("PubSub not initialized")
	}

	// 1. Join the GossipSub topic
	topic, err := corenet.GlobalPubSub.Join(groupID)
	if err != nil {
		return err
	}

	// 2. Subscribe
	sub, err := topic.Subscribe()
	if err != nil {
		topic.Close()
		return err
	}

	// 3. Save group metadata to local SQLite
	meta := corestore.GroupMetadata{
		GroupID:    groupID,
		GroupAlias: groupAlias,
		CreatorID:  creatorID,
		GroupType:  groupType,
		CreatedAt:  time.Now().Unix(),
		Signature:  signature,
	}
	_ = corestore.SaveGroupMetadata(meta)

	// 4. Save members and roles to local SQLite
	myID := h.ID().String()
	for _, m := range members {
		role := "MEMBER"
		if m == creatorID {
			role = "CREATOR"
		}
		_ = corestore.AddGroupMemberV2(groupID, m, role)
	}
	// Ensure self is in the member list
	myRole := "MEMBER"
	if myID == creatorID {
		myRole = "CREATOR"
	}
	_ = corestore.AddGroupMemberV2(groupID, myID, myRole)

	// 5. Initialize/Share keys ONLY if it's a SECURE group
	if groupType == "SECURE" {
		localKey, err := corestore.GetGroupLocalKey(groupID)
		if err != nil {
			localKey = make([]byte, 32)
			rand.Read(localKey)
			_ = corestore.SaveGroupLocalKey(groupID, localKey)
		}

		if creatorID != myID {
			go shareKeyWithMember(ctx, h, priv, groupID, creatorID, localKey)
		}

		for _, m := range members {
			if m != myID && m != creatorID {
				go shareKeyWithMember(ctx, h, priv, groupID, m, localKey)
			}
		}
	}

	session := &GroupSession{
		Topic:    topic,
		Sub:      sub,
		Host:     h,
	}
	activeGroups[groupID] = session

	// 6. Start listener goroutine
	go listenGroupMessages(ctx, session, groupID)

	logger.Displayf("[Group] Successfully joined room: %s (%s, %s) with %d members\n",
		groupAlias, groupType, groupID[:8], len(members))
	return nil
}

func shareKeyWithMember(ctx context.Context, h host.Host, priv crypto.PrivKey, groupID, memberID string, key []byte) {
	target, err := peer.Decode(memberID)
	if err != nil { return }

	logger.Debug().Msgf("[GROUP HANDSHAKE] Sharing our local key for group %s with member %s via Double Ratchet...", groupID, FormatPeerID(memberID))
	shareMsg := fmt.Sprintf("GKEY:%s:%s", groupID, base64.StdEncoding.EncodeToString(key))
	
	errSend := SendMessage(ctx, h, priv, target, shareMsg)
	if errSend != nil {
		logger.Error().Err(errSend).Str("group", groupID).Str("member", memberID).Msg("[GROUP HANDSHAKE] Failed to share group key")
	} else {
		logger.Debug().Str("group", groupID).Str("member", memberID).Msg("[GROUP HANDSHAKE] Group key shared successfully")
	}
}

// sendGroupKeyRequest broadcasts a GREQ control message to ask all existing members
// to share their current group key. Called when a new member joins and has no keys yet.
func sendGroupKeyRequest(ctx context.Context, h host.Host, groupID string) {
	groupsMutex.Lock()
	session, exists := activeGroups[groupID]
	groupsMutex.Unlock()

	if !exists {
		return
	}

	privKey := h.Peerstore().PrivKey(h.ID())
	if privKey == nil {
		return
	}

	payload := fmt.Sprintf("GCMD:GREQ:%s", h.ID().String())
	dataToSign := []byte(payload + h.ID().String())
	sigBytes, err := privKey.Sign(dataToSign)
	if err != nil {
		return
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	gMsg := GroupMessage{
		SenderID:  h.ID().String(),
		Payload:   payload,
		Signature: sigB64,
	}
	msgBytes, _ := json.Marshal(gMsg)

	if err := session.Topic.Publish(ctx, msgBytes); err != nil {
		logger.Warn().Err(err).Str("group", groupID).Msg("[GREQ] Failed to broadcast key request")
	} else {
		logger.Info().Str("group", groupID).Msg("[GREQ] Broadcast group key request to existing members")
	}
}

// decryptAndDispatchGroupMsg handles decryption + callback for a single group message.
// Used by both the live listener and the pending-message flusher.
func decryptAndDispatchGroupMsg(ctx context.Context, session *GroupSession, groupID string, gMsg GroupMessage) {
	meta, errLoad := corestore.LoadGroupMetadata(groupID)
	if errLoad != nil { return }

	var plaintext string
	if meta.GroupType == "SECURE" {
		// Look up the sender's key for this group
		senderKey, err := corestore.GetGroupSenderKey(groupID, gMsg.SenderID)
		if err != nil {
			// Key still not available — re-buffer (should not normally happen after flush)
			logger.Warn().Msgf("[Group %s] Still no key for %s after flush, dropping", meta.GroupAlias, FormatPeerID(gMsg.SenderID))
			return
		}

		// Decrypt message using the Sender's specific key
		plaintext, err = corecrypto.DecryptMessage(senderKey, gMsg.Payload)
		if err != nil {
			logger.Error().Msgf("[Group %s] Failed to decrypt message from %s (Key mismatch)", meta.GroupAlias, FormatPeerID(gMsg.SenderID))
			return
		}

		// Rotate sender key in our DB
		hKDF := hmac.New(sha256.New, senderKey)
		hKDF.Write([]byte("GROUP_RATCHET"))
		nextSenderKey := hKDF.Sum(nil)
		corestore.SaveGroupSenderKey(groupID, gMsg.SenderID, nextSenderKey)
	} else {
		// Plain text for UNSECURE groups
		plaintext = gMsg.Payload
	}

	// Verify signature
	if gMsg.Signature != "" {
		sID, _ := peer.Decode(gMsg.SenderID)
		pubKey, err := sID.ExtractPublicKey()
		if err == nil {
			dataToVerify := []byte(gMsg.Payload + gMsg.SenderID)
			sigBytes, _ := base64.StdEncoding.DecodeString(gMsg.Signature)
			valid, _ := pubKey.Verify(dataToVerify, sigBytes)
			if !valid {
				logger.Warn().Msgf("[Group Warning] REJECTED: Invalid signature from %s in group %s", FormatPeerID(gMsg.SenderID), meta.GroupAlias)
				return
			}
		}
	}

	ts := time.Now().Format("02/01 15:04:05")
	logger.Displayf("\033[92m[%s] [Group %s] %s: %s\033[0m\n", ts, meta.GroupAlias, FormatSender(gMsg.SenderID), plaintext)
	if MessageCallback != nil {
		MessageCallback(MessageEvent{
			Type:      "group",
			Timestamp: ts,
			Sender:    gMsg.SenderID,
			GroupID:   groupID,
			Content:   plaintext,
		})
	}
}

func listenGroupMessages(ctx context.Context, session *GroupSession, groupID string) {
	for {
		msg, err := session.Sub.Next(ctx)
		if err != nil {
			return
		}

		// Parse the outer envelope
		var gMsg GroupMessage
		err = json.Unmarshal(msg.Data, &gMsg)
		if err != nil { continue }

		// Don't process our own messages
		if gMsg.SenderID == session.Host.ID().String() { continue }

		// Skip duplicate processing
		if checkAndMarkProcessed(gMsg.Signature) { continue }

		// Check if it is a control command (GCMD:action:target)
		if strings.HasPrefix(gMsg.Payload, "GCMD:") {
			ProcessGroupControlMessage(ctx, session.Host, groupID, gMsg)
			continue
		}

		meta, errLoad := corestore.LoadGroupMetadata(groupID)
		if errLoad != nil { continue }

		if meta.GroupType == "SECURE" {
			// Check if we have the sender's key
			_, err := corestore.GetGroupSenderKey(groupID, gMsg.SenderID)
			if err != nil {
				// Key not available yet — buffer the message instead of dropping it
				bufferPendingMessage(groupID, gMsg.SenderID, pendingGroupMsg{
					receivedAt: time.Now(),
					gMsg:       gMsg,
					ctx:        ctx,
					session:    session,
					groupID:    groupID,
				})
				// Actively request the key via GREQ so we don't just wait passively
				go sendGroupKeyRequest(ctx, session.Host, groupID)
				continue
			}
		}

		// We have the key (or it's UNSECURE) — decrypt and dispatch
		decryptAndDispatchGroupMsg(ctx, session, groupID, gMsg)
	}
}

// SendGroupMessage publishes a message to the group using E2EE (SECURE) or Plaintext (UNSECURE)
func SendGroupMessage(ctx context.Context, h host.Host, groupID string, message string) error {
	groupsMutex.Lock()
	session, exists := activeGroups[groupID]
	groupsMutex.Unlock()

	if !exists {
		return fmt.Errorf("not in group %s. Use /group-join or /group-create first", groupID)
	}

	meta, errLoad := corestore.LoadGroupMetadata(groupID)
	if errLoad != nil { return errLoad }

	var payload string
	if meta.GroupType == "SECURE" {
		localKey, err := corestore.GetGroupLocalKey(groupID)
		if err != nil { return err }

		encrypted, err := corecrypto.EncryptMessage(localKey, message)
		if err != nil { return err }
		payload = encrypted

		// Rotate local key for our next outgoing message
		hKDF := hmac.New(sha256.New, localKey)
		hKDF.Write([]byte("GROUP_RATCHET"))
		nextLocalKey := hKDF.Sum(nil)
		corestore.SaveGroupLocalKey(groupID, nextLocalKey)
	} else {
		payload = message
	}

	// Sign payload + SenderID
	privKey := h.Peerstore().PrivKey(h.ID())
	dataToSign := []byte(payload + h.ID().String())
	sigBytes, _ := privKey.Sign(dataToSign)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	gMsg := GroupMessage{
		SenderID:  h.ID().String(),
		Payload:   payload,
		Signature: sigB64,
	}
	msgBytes, _ := json.Marshal(gMsg)

	// Publish to GossipSub
	err := session.Topic.Publish(ctx, msgBytes)
	if err != nil { return err }

	// Fan-out to offline/mailbox members
	members, err := corestore.GetGroupMembersV2(groupID)
	if err == nil {
		for _, m := range members {
			if m.PeerID == h.ID().String() { continue }
			target, errDec := peer.Decode(m.PeerID)
			if errDec == nil {
				go func(t peer.ID) {
					_ = SendMessage(ctx, h, privKey, t, "GRPM:"+groupID+":"+string(msgBytes))
				}(target)
			}
		}
	}

	return nil
}

// ProcessGroupMessage decodes and displays offline group messages
func ProcessGroupMessage(groupID string, msgBytes []byte) {
	var gMsg GroupMessage
	err := json.Unmarshal(msgBytes, &gMsg)
	if err != nil { return }

	// Skip duplicate processing
	if checkAndMarkProcessed(gMsg.Signature) { return }

	meta, errLoad := corestore.LoadGroupMetadata(groupID)
	if errLoad != nil { return }

	var plaintext string
	if meta.GroupType == "SECURE" {
		senderKey, err := corestore.GetGroupSenderKey(groupID, gMsg.SenderID)
		if err != nil {
			logger.Warn().Msgf("[Group %s] Received offline message from %s but no key found yet", meta.GroupAlias, FormatPeerID(gMsg.SenderID))

			// Buffer offline message too — key may arrive soon via GREQ/GKEY
			groupsMutex.Lock()
			session := activeGroups[groupID]
			groupsMutex.Unlock()

			if session != nil {
				bufferPendingMessage(groupID, gMsg.SenderID, pendingGroupMsg{
					receivedAt: time.Now(),
					gMsg:       gMsg,
					ctx:        context.Background(),
					session:    session,
					groupID:    groupID,
				})
				go sendGroupKeyRequest(context.Background(), session.Host, groupID)
			}
			return
		}

		plaintext, err = corecrypto.DecryptMessage(senderKey, gMsg.Payload)
		if err != nil {
			logger.Error().Msgf("[Group %s] Failed to decrypt offline message from %s (Key mismatch)", meta.GroupAlias, FormatPeerID(gMsg.SenderID))
			return
		}

		// Rotate sender key in our DB
		hKDF := hmac.New(sha256.New, senderKey)
		hKDF.Write([]byte("GROUP_RATCHET"))
		nextSenderKey := hKDF.Sum(nil)
		corestore.SaveGroupSenderKey(groupID, gMsg.SenderID, nextSenderKey)
	} else {
		plaintext = gMsg.Payload
	}

	// Verify signature
	if gMsg.Signature != "" {
		sID, _ := peer.Decode(gMsg.SenderID)
		pubKey, err := sID.ExtractPublicKey()
		if err == nil {
			dataToVerify := []byte(gMsg.Payload + gMsg.SenderID)
			sigBytes, _ := base64.StdEncoding.DecodeString(gMsg.Signature)
			valid, _ := pubKey.Verify(dataToVerify, sigBytes)
			if !valid {
				logger.Warn().Msgf("[Group Warning] REJECTED: Invalid signature on offline message from %s", FormatPeerID(gMsg.SenderID))
				return
			}
		}
	}

	ts := time.Now().Format("02/01 15:04:05")
	logger.Displayf("\033[92m[%s] [Group %s] %s (Offline): %s\033[0m\n", ts, meta.GroupAlias, FormatSender(gMsg.SenderID), plaintext)
	if MessageCallback != nil {
		MessageCallback(MessageEvent{
			Type:      "group",
			Timestamp: ts,
			Sender:    gMsg.SenderID,
			GroupID:   groupID,
			Content:   plaintext,
		})
	}
}

// RestoreGroups restores all active group memberships from database on startup
func RestoreGroups(ctx context.Context, h host.Host, priv crypto.PrivKey) error {
	rows, err := corestore.DB.Query(`SELECT DISTINCT group_id FROM group_members_v2 WHERE peer_id = ?`, h.ID().String())
	if err != nil {
		return err
	}
	defer rows.Close()

	var groupIDs []string
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err == nil {
			groupIDs = append(groupIDs, gid)
		}
	}

	for _, gid := range groupIDs {
		meta, err := corestore.LoadGroupMetadata(gid)
		if err == nil {
			membersV2, err := corestore.GetGroupMembersV2(gid)
			if err == nil {
				var members []string
				for _, m := range membersV2 {
					members = append(members, m.PeerID)
				}
				err = JoinGroupProper(ctx, h, priv, meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.Signature, members)
				if err != nil {
					logger.Error().Err(err).Str("groupID", gid).Msg("Failed to auto-restore group")
				} else {
					logger.Info().Str("groupID", gid).Msg("Auto-restored group membership on startup")
				}
			}
		}
	}
	return nil
}

// ProcessGroupControlMessage validates and executes signed commands for group administration
func ProcessGroupControlMessage(ctx context.Context, h host.Host, groupID string, gMsg GroupMessage) {
	sID, err := peer.Decode(gMsg.SenderID)
	if err != nil { return }
	pubKey, err := sID.ExtractPublicKey()
	if err != nil { return }

	// Verify command signature
	dataToVerify := []byte(gMsg.Payload + gMsg.SenderID)
	sigBytes, _ := base64.StdEncoding.DecodeString(gMsg.Signature)
	valid, err := pubKey.Verify(dataToVerify, sigBytes)
	if !valid || err != nil {
		logger.Error().Msg("Group control message has INVALID signature")
		return
	}

	parts := strings.Split(gMsg.Payload, ":")
	if len(parts) < 3 { return }
	action := parts[1]
	target := parts[2]

	meta, errLoad := corestore.LoadGroupMetadata(groupID)
	if errLoad != nil {
		logger.Error().Str("groupID", groupID).Msg("Failed to load group metadata for control command")
		return
	}

	switch action {
	case "JOIN":
		// Only valid for UNSECURE (open-join) groups
		if meta.GroupType != "UNSECURE" {
			logger.Warn().Msg("GCMD:JOIN ignored on a SECURE group")
			return
		}

		_ = corestore.AddGroupMemberV2(groupID, target, "MEMBER")
		logger.Displayf("[Group %s] @%s joined the public group\n", meta.GroupAlias, FormatPeerID(target))

		// Share our group local key with the new member via 1:1 secure channel (Double Ratchet)
		localKey, err := corestore.GetGroupLocalKey(groupID)
		if err == nil {
			go shareKeyWithMember(ctx, h, h.Peerstore().PrivKey(h.ID()), groupID, target, localKey)
		}

	case "GREQ":
		// Key request from a new member — share our current local key with them
		requesterID := target
		if requesterID == h.ID().String() {
			return // Don't respond to our own request
		}

		logger.Info().
			Str("group", meta.GroupAlias).
			Str("requester", FormatPeerID(requesterID)).
			Msg("[GREQ] Received key request, sharing local key")

		localKey, err := corestore.GetGroupLocalKey(groupID)
		if err == nil {
			go shareKeyWithMember(ctx, h, h.Peerstore().PrivKey(h.ID()), groupID, requesterID, localKey)
		}

	case "ADD":
		// Only valid if sender is Creator
		if gMsg.SenderID != meta.CreatorID {
			logger.Warn().Msg("GCMD:ADD rejected: sender is not Creator")
			return
		}

		_ = corestore.AddGroupMemberV2(groupID, target, "MEMBER")
		logger.Displayf("[Group %s] Creator added @%s to the group\n", meta.GroupAlias, FormatPeerID(target))

		// Share our group local key with the new member
		localKey, err := corestore.GetGroupLocalKey(groupID)
		if err == nil {
			go shareKeyWithMember(ctx, h, h.Peerstore().PrivKey(h.ID()), groupID, target, localKey)
		}

	case "REMOVE":
		// Only valid if sender is Creator
		if gMsg.SenderID != meta.CreatorID {
			logger.Warn().Msg("GCMD:REMOVE rejected: sender is not Creator")
			return
		}

		logger.Displayf("[Group %s] Creator removed @%s from the group\n", meta.GroupAlias, FormatPeerID(target))

		if target == h.ID().String() {
			// We are kicked! Unsubscribe and delete local group
			groupsMutex.Lock()
			if session, exists := activeGroups[groupID]; exists {
				session.Sub.Cancel()
				session.Topic.Close()
				delete(activeGroups, groupID)
			}
			groupsMutex.Unlock()
			_ = corestore.DeleteGroupMetadata(groupID)
			logger.Displayf("[Group] You have been removed from group %s\n", meta.GroupAlias)
		} else {
			_ = corestore.RemoveGroupMemberV2(groupID, target)

			// Rotate our local key for Forward Secrecy
			if meta.GroupType == "SECURE" {
				localKey := make([]byte, 32)
				rand.Read(localKey)
				_ = corestore.SaveGroupLocalKey(groupID, localKey)

				// Share the rotated key only with remaining members
				members, err := corestore.GetGroupMembersV2(groupID)
				if err == nil {
					for _, m := range members {
						if m.PeerID != h.ID().String() && m.PeerID != target {
							go shareKeyWithMember(ctx, h, h.Peerstore().PrivKey(h.ID()), groupID, m.PeerID, localKey)
						}
					}
				}
			}
		}

	case "EXIT":
		logger.Displayf("[Group %s] @%s left the group\n", meta.GroupAlias, FormatPeerID(target))
		_ = corestore.RemoveGroupMemberV2(groupID, target)

		// Rotate local key for Forward Secrecy
		if meta.GroupType == "SECURE" {
			localKey := make([]byte, 32)
			rand.Read(localKey)
			_ = corestore.SaveGroupLocalKey(groupID, localKey)

			members, err := corestore.GetGroupMembersV2(groupID)
			if err == nil {
				for _, m := range members {
					if m.PeerID != h.ID().String() && m.PeerID != target {
						go shareKeyWithMember(ctx, h, h.Peerstore().PrivKey(h.ID()), groupID, m.PeerID, localKey)
					}
				}
			}
		}

	case "DISBAND":
		// Only valid if sender is Creator
		if gMsg.SenderID != meta.CreatorID {
			logger.Warn().Msg("GCMD:DISBAND rejected: sender is not Creator")
			return
		}

		logger.Displayf("[Group %s] Group has been disbanded by the Creator\n", meta.GroupAlias)

		groupsMutex.Lock()
		if session, exists := activeGroups[groupID]; exists {
			session.Sub.Cancel()
			session.Topic.Close()
			delete(activeGroups, groupID)
		}
		groupsMutex.Unlock()
		_ = corestore.DeleteGroupMetadata(groupID)
	}
}

// SendGroupControlMessage broadcasts a group control command (signed by sender) to the GossipSub topic
func SendGroupControlMessage(ctx context.Context, h host.Host, groupID string, action string, target string) error {
	groupsMutex.Lock()
	session, exists := activeGroups[groupID]
	groupsMutex.Unlock()

	if !exists {
		return fmt.Errorf("group session not active locally")
	}

	payload := fmt.Sprintf("GCMD:%s:%s", action, target)
	privKey := h.Peerstore().PrivKey(h.ID())
	dataToSign := []byte(payload + h.ID().String())
	sigBytes, err := privKey.Sign(dataToSign)
	if err != nil {
		return err
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	gMsg := GroupMessage{
		SenderID:  h.ID().String(),
		Payload:   payload,
		Signature: sigB64,
	}
	msgBytes, err := json.Marshal(gMsg)
	if err != nil {
		return err
	}

	return session.Topic.Publish(ctx, msgBytes)
}

// ExitGroupLocally closes the GossipSub topic subscription and removes metadata locally
func ExitGroupLocally(groupID string) {
	groupsMutex.Lock()
	defer groupsMutex.Unlock()
	if session, exists := activeGroups[groupID]; exists {
		session.Sub.Cancel()
		session.Topic.Close()
		delete(activeGroups, groupID)
	}
	_ = corestore.DeleteGroupMetadata(groupID)
}
