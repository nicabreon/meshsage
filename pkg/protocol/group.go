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
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

type GroupMessage struct {
	SenderID  string `json:"sender_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"` // Sender's signature over payload + sender_id
}

type GroupSession struct {
	Topic *pubsub.Topic
	Sub   *pubsub.Subscription
	Host  host.Host
}

var (
	activeGroups      = make(map[string]*GroupSession)
	groupsMutex       sync.Mutex
	processedMessages = make(map[string]bool)
	processedMutex    sync.Mutex

	// GREQ rate-limiting: prevent spamming key requests when many messages arrive
	// before the sender's key is available.
	greqLastSent  = make(map[string]time.Time) // groupID → last GREQ sent time
	greqRateMutex sync.Mutex
	greqCooldown  = 30 * time.Second
)

// ---------------------------------------------------------------------------
// PENDING MESSAGE BUFFER
// Stores messages that arrived before the sender's group key was available.
// Flushed automatically once the key arrives via GKEY or GINVITE.
// ---------------------------------------------------------------------------

const (
	pendingMsgTTL          = 5 * time.Minute
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
	return JoinGroupProper(ctx, h, priv, groupID, alias, h.ID().String(), "SECURE", signature, time.Now().Unix(), members)
}

// JoinGroupProper joins a GossipSub topic, initializes Group Metadata/Members, and sets up keys
func JoinGroupProper(ctx context.Context, h host.Host, priv crypto.PrivKey, groupID, groupAlias, creatorID, groupType, signature string, createdAt int64, members []string) error {
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
	if createdAt == 0 {
		createdAt = time.Now().Unix()
	}
	meta := corestore.GroupMetadata{
		GroupID:    groupID,
		GroupAlias: groupAlias,
		CreatorID:  creatorID,
		GroupType:  groupType,
		CreatedAt:  createdAt,
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

	// Ensure group creator is registered to group_members_v2
	if creatorID != "" {
		_ = corestore.AddGroupMemberV2(groupID, creatorID, "CREATOR")
	}

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
		Topic: topic,
		Sub:   sub,
		Host:  h,
	}
	activeGroups[groupID] = session

	// 6. Start listener goroutine
	go listenGroupMessages(ctx, session, groupID)

	logger.Displayf("[Group] Successfully joined room: %s (%s, %s) with %d members\n",
		groupAlias, groupType, groupID[:8], len(members))
	return nil
}

func shareKeyWithMember(ctx context.Context, h host.Host, priv crypto.PrivKey, groupID, memberID string, key []byte) {
	bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target, err := peer.Decode(memberID)
	if err != nil {
		return
	}

	logger.Debug().Msgf("[GROUP HANDSHAKE] Sharing our local key for group %s with member %s via Double Ratchet...", groupID, FormatPeerID(memberID))

	// Load history of local keys
	var keyB64s []string
	history, errHist := corestore.GetGroupLocalKeyHistory(groupID)
	if errHist == nil && len(history) > 0 {
		for _, k := range history {
			keyB64s = append(keyB64s, base64.StdEncoding.EncodeToString(k))
		}
	} else {
		// Fallback to the single key
		keyB64s = []string{base64.StdEncoding.EncodeToString(key)}
	}

	// Join the base64 keys with commas
	payload := strings.Join(keyB64s, ",")
	shareMsg := fmt.Sprintf("GKEY:%s:%s", groupID, payload)

	_, errSend := SendMessage(bgCtx, h, priv, target, shareMsg)
	if errSend != nil {
		logger.Error().Err(errSend).Str("group", groupID).Str("member", memberID).Msg("[GROUP HANDSHAKE] Failed to share group key")
	} else {
		logger.Debug().Str("group", groupID).Str("member", memberID).Msg("[GROUP HANDSHAKE] Group key shared successfully")
	}
}

// shouldSendGREQ returns true if it is safe to send a GREQ for this group
// (rate-limited to once per greqCooldown to prevent request storms).
func shouldSendGREQ(groupID string) bool {
	greqRateMutex.Lock()
	defer greqRateMutex.Unlock()
	if last, ok := greqLastSent[groupID]; ok {
		if time.Since(last) < greqCooldown {
			return false
		}
	}
	greqLastSent[groupID] = time.Now()
	return true
}

// sendGroupKeyRequest broadcasts a GREQ control message to ask all existing members
// to share their current group key. Called when a new member joins and has no keys yet.
// Rate-limited via shouldSendGREQ to prevent GREQ spam storms.
func sendGroupKeyRequest(ctx context.Context, h host.Host, groupID string) {
	if !shouldSendGREQ(groupID) {
		logger.Debug().Str("group", groupID).Msg("[GREQ] Rate-limited: skipping duplicate key request")
		return
	}

	privKey := h.Peerstore().PrivKey(h.ID())
	if privKey == nil {
		return
	}

	members, err := corestore.GetGroupMembersV2(groupID)
	if err != nil || len(members) == 0 {
		logger.Warn().Str("group", groupID).Msg("[GREQ] Failed to load members or no members found")
		return
	}

	reqMsg := fmt.Sprintf("GCMD:GREQ:%s", groupID)

	for _, m := range members {
		if m.PeerID == h.ID().String() {
			continue
		}
		targetID, errDec := peer.Decode(m.PeerID)
		if errDec != nil {
			continue
		}
		logger.Info().
			Str("group", groupID).
			Str("target", FormatPeerID(m.PeerID)).
			Msg("[GREQ] Sending direct key request to member")

		go func(t peer.ID) {
			bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = SendMessage(bgCtx, h, privKey, t, reqMsg)
		}(targetID)
	}
}

// decryptGroupMsg handles key ratchet (backward history and forward look-ahead) to decrypt secure group messages.
func decryptGroupMsg(meta corestore.GroupMetadata, gMsg GroupMessage) (string, error) {
	if meta.GroupType != "SECURE" {
		return gMsg.Payload, nil
	}

	senderKey, err := corestore.GetGroupSenderKey(meta.GroupID, gMsg.SenderID)
	if err != nil {
		return "", err
	}

	decrypted := false
	var plaintext string

	// 1. Try decrypting using active key
	plaintext, err = corecrypto.DecryptMessage(senderKey, gMsg.Payload)
	if err == nil {
		decrypted = true
		// Rotate sender key in our DB
		hKDF := hmac.New(sha256.New, senderKey)
		hKDF.Write([]byte("GROUP_RATCHET"))
		nextSenderKey := hKDF.Sum(nil)
		corestore.SaveGroupSenderKey(meta.GroupID, gMsg.SenderID, nextSenderKey)
	} else {
		// 2. Try backward check: check historical keys
		historyKeys, _ := corestore.GetGroupSenderKeyHistory(meta.GroupID, gMsg.SenderID)
		for _, oldKey := range historyKeys {
			plaintext, err = corecrypto.DecryptMessage(oldKey, gMsg.Payload)
			if err == nil {
				decrypted = true
				logger.Debug().Msgf("[Group %s] Decrypted offline/out-of-order message from %s using historical key", meta.GroupAlias, FormatPeerID(gMsg.SenderID))
				break
			}
		}

		// 3. Try forward check: look-ahead ratcheting
		if !decrypted {
			tempKey := senderKey
			for step := 1; step <= 10; step++ {
				hKDF := hmac.New(sha256.New, tempKey)
				hKDF.Write([]byte("GROUP_RATCHET"))
				tempKey = hKDF.Sum(nil)

				plaintext, err = corecrypto.DecryptMessage(tempKey, gMsg.Payload)
				if err == nil {
					decrypted = true
					logger.Debug().Msgf("[Group %s] Decrypted message from %s using look-ahead key (+%d steps)", meta.GroupAlias, FormatPeerID(gMsg.SenderID), step)
					// Update active key to new forward key + rotate once for next message
					hKDF2 := hmac.New(sha256.New, tempKey)
					hKDF2.Write([]byte("GROUP_RATCHET"))
					nextSenderKey := hKDF2.Sum(nil)
					corestore.SaveGroupSenderKey(meta.GroupID, gMsg.SenderID, nextSenderKey)
					break
				}
			}
		}
	}

	if !decrypted {
		return "", fmt.Errorf("decryption failed (Key mismatch)")
	}
	return plaintext, nil
}

// decryptAndDispatchGroupMsg handles decryption + callback for a single group message.
// Used by both the live listener and the pending-message flusher.
func decryptAndDispatchGroupMsg(ctx context.Context, session *GroupSession, groupID string, gMsg GroupMessage) {
	meta, errLoad := corestore.LoadGroupMetadata(groupID)
	if errLoad != nil {
		return
	}

	plaintext, err := decryptGroupMsg(meta, gMsg)
	if err != nil {
		logger.Error().Msgf("[Group %s] Failed to decrypt message from %s: %s", meta.GroupAlias, FormatPeerID(gMsg.SenderID), err.Error())

		// Actively request keys via GREQ on decryption failure so we can recover
		if meta.GroupType == "SECURE" {
			go sendGroupKeyRequest(ctx, session.Host, groupID)
		}
		return
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

	msgID := ""
	if gMsg.Signature != "" {
		msgID = fmt.Sprintf("gr-%x", sha256.Sum256([]byte(gMsg.Signature)))[:8]
	} else {
		msgID = fmt.Sprintf("gr-%x", sha256.Sum256([]byte(gMsg.Payload+gMsg.SenderID+ts)))[:8]
	}

	logger.Displayf("\033[92m[%s] [Group %s] %s: %s\033[0m\n", ts, meta.GroupAlias, FormatSender(gMsg.SenderID), plaintext)
	TrackMsgRecv() // Track incoming message
	if MessageCallback != nil {
		MessageCallback(MessageEvent{
			Type:      "group",
			MsgID:     msgID,
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
		AddBytesRecv(len(msg.Data)) // Track incoming GossipSub bytes

		// Parse the outer envelope
		var gMsg GroupMessage
		err = json.Unmarshal(msg.Data, &gMsg)
		if err != nil {
			continue
		}

		// Don't process our own messages
		if gMsg.SenderID == session.Host.ID().String() {
			continue
		}

		// Skip duplicate processing
		if checkAndMarkProcessed(gMsg.Signature) {
			continue
		}

		// Check if it is a control command (GCMD:action:target)
		if strings.HasPrefix(gMsg.Payload, "GCMD:") {
			ProcessGroupControlMessage(ctx, session.Host, groupID, gMsg)
			continue
		}

		meta, errLoad := corestore.LoadGroupMetadata(groupID)
		if errLoad != nil {
			continue
		}

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

func isDirectlyConnected(h host.Host, target peer.ID) bool {
	conns := h.Network().ConnsToPeer(target)
	if len(conns) == 0 {
		return false
	}
	for _, conn := range conns {
		remoteAddr := conn.RemoteMultiaddr()
		if !strings.Contains(remoteAddr.String(), "/p2p-circuit") {
			return true
		}
	}
	return false
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
	if errLoad != nil {
		return errLoad
	}

	logger.Info().
		Str("group", meta.GroupAlias).
		Str("type", meta.GroupType).
		Msg("Sending group message")
	var payload string
	if meta.GroupType == "SECURE" {
		localKey, err := corestore.GetGroupLocalKey(groupID)
		if err != nil {
			return err
		}

		encrypted, err := corecrypto.EncryptMessage(localKey, message)
		if err != nil {
			return err
		}
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
	if err != nil {
		return err
	}
	AddBytesSent(len(msgBytes)) // Track outgoing GossipSub bytes
	TrackMsgSent()              // Track outgoing group message

	// Fan-out via GRPM for members who are not verified online via a direct connection.
	// Get the list of peers currently active in our GossipSub mesh for this topic.
	// GossipSub delivery is highly reliable to peers directly in our mesh.
	meshPeers := session.Topic.ListPeers()
	meshPeerMap := make(map[peer.ID]bool)
	for _, p := range meshPeers {
		meshPeerMap[p] = true
	}

	logger.Info().
		Int("activeMeshPeers", len(meshPeers)).
		Msg("GossipSub mesh membership evaluated")

	// Fan-out via GRPM only for members who are NOT in our GossipSub mesh (offline or backgrounded).
	members, err := corestore.GetGroupMembersV2(groupID)
	if err == nil {
		for _, m := range members {
			if m.PeerID == h.ID().String() {
				continue
			}
			target, errDec := peer.Decode(m.PeerID)
			if errDec != nil {
				continue
			}

			go func(t peer.ID, memberIDStr string) {
				bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				if meshPeerMap[t] {
					logger.Debug().
						Str("peer", FormatPeerID(memberIDStr)).
						Str("group", groupID[:8]).
						Msg("[Group Fan-out] Skipping GRPM: peer is active in GossipSub mesh")
					return
				}

				// Send GRPM via direct stream (falls back to mailbox if unreachable).
				// NOTE: SendMessage requires E2EE session (X3DH + Double Ratchet). If no session
				// exists yet (e.g. TUI restarted while member was offline), the first attempt
				// triggers X3DH in background. Retry once after 3s to catch session completion.
				grpmPayload := "GRPM:" + groupID + ":" + string(msgBytes)
				_, errSend := SendMessage(bgCtx, h, privKey, t, grpmPayload)
				if errSend != nil {
					logger.Warn().
						Err(errSend).
						Str("peer", FormatPeerID(memberIDStr)).
						Str("group", groupID[:8]).
						Msg("[Group Fan-out] GRPM send failed (no session?), retrying in 3s")
					go func() {
						time.Sleep(3 * time.Second)
						retryCtx, retryCancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer retryCancel()
						if _, errRetry := SendMessage(retryCtx, h, privKey, t, grpmPayload); errRetry != nil {
							logger.Warn().Err(errRetry).Str("peer", FormatPeerID(memberIDStr)).
								Str("group", groupID[:8]).Msg("[Group Fan-out] GRPM retry failed")
						} else {
							logger.Info().Str("peer", FormatPeerID(memberIDStr)).
								Str("group", groupID[:8]).Msg("[Group Fan-out] GRPM retry succeeded")
						}
					}()
				}
			}(target, m.PeerID)
		}
	}

	return nil
}

// ProcessGroupMessage decodes and displays offline group messages
func ProcessGroupMessage(groupID string, msgBytes []byte, msgHash string) bool {
	var gMsg GroupMessage
	err := json.Unmarshal(msgBytes, &gMsg)
	if err != nil {
		return true
	}

	// Skip duplicate processing
	if checkAndMarkProcessed(gMsg.Signature) {
		return true
	}

	meta, errLoad := corestore.LoadGroupMetadata(groupID)
	if errLoad != nil {
		return false
	}

	var plaintext string
	if meta.GroupType == "SECURE" {
		_, err := corestore.GetGroupSenderKey(groupID, gMsg.SenderID)
		if err != nil {
			logger.Warn().Msgf("[Group %s] Received offline message from %s but no key found yet", meta.GroupAlias, FormatPeerID(gMsg.SenderID))

			// Buffer offline message too — key may arrive soon via GREQ/GKEY
			groupsMutex.Lock()
			session := activeGroups[groupID]
			groupsMutex.Unlock()

			bufferPendingMessage(groupID, gMsg.SenderID, pendingGroupMsg{
				receivedAt: time.Now(),
				gMsg:       gMsg,
				ctx:        context.Background(),
				session:    session,
				groupID:    groupID,
			})
			go sendGroupKeyRequest(context.Background(), session.Host, groupID)
			return false
		}
	}

	var errDec error
	plaintext, errDec = decryptGroupMsg(meta, gMsg)
	if errDec != nil {
		logger.Error().Msgf("[Group %s] Failed to decrypt offline message from %s: %s", meta.GroupAlias, FormatPeerID(gMsg.SenderID), errDec.Error())

		if meta.GroupType == "SECURE" {
			groupsMutex.Lock()
			session := activeGroups[groupID]
			groupsMutex.Unlock()

			bufferPendingMessage(groupID, gMsg.SenderID, pendingGroupMsg{
				receivedAt: time.Now(),
				gMsg:       gMsg,
				ctx:        context.Background(),
				session:    session,
				groupID:    groupID,
			})
			go sendGroupKeyRequest(context.Background(), session.Host, groupID)
		}
		return false
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
				return true
			}
		}
	}

	ts := time.Now().Format("02/01 15:04:05")

	msgID := ""
	if gMsg.Signature != "" {
		msgID = fmt.Sprintf("gr-%x", sha256.Sum256([]byte(gMsg.Signature)))[:8]
	} else {
		msgID = fmt.Sprintf("gr-%x", sha256.Sum256([]byte(gMsg.Payload+gMsg.SenderID+ts)))[:8]
	}

	// Save to local SQLite messages database (for deduplication cache recovery)
	if msgHash != "" {
		_ = corestore.SaveMessage(gMsg.SenderID, groupID, plaintext, msgID, msgHash, "group")
	}

	logger.Displayf("\033[92m[%s] [Group %s] %s (Offline): %s\033[0m\n", ts, meta.GroupAlias, FormatSender(gMsg.SenderID), plaintext)
	TrackMsgRecv() // Track incoming message
	if MessageCallback != nil {
		MessageCallback(MessageEvent{
			Type:      "group",
			MsgID:     msgID,
			Timestamp: ts,
			Sender:    gMsg.SenderID,
			GroupID:   groupID,
			Content:   plaintext,
		})
	}
	return true
}

// RestoreGroups restores all active group memberships from database on startup
func RestoreGroups(ctx context.Context, h host.Host, priv crypto.PrivKey) error {
	logger.Info().Msg("[RestoreGroups] Querying distinct group_ids from group_members_v2...")
	rows, err := corestore.DB.Query(`SELECT DISTINCT group_id FROM group_members_v2 WHERE peer_id = ?`, h.ID().String())
	if err != nil {
		logger.Error().Err(err).Msg("[RestoreGroups] Failed to query group_members_v2")
		return err
	}
	logger.Info().Msg("[RestoreGroups] Query successful, parsing rows...")
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
				err = JoinGroupProper(ctx, h, priv, meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.Signature, meta.CreatedAt, members)
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
	if err != nil {
		return
	}
	pubKey, err := sID.ExtractPublicKey()
	if err != nil {
		return
	}

	// Verify command signature
	dataToVerify := []byte(gMsg.Payload + gMsg.SenderID)
	sigBytes, _ := base64.StdEncoding.DecodeString(gMsg.Signature)
	valid, err := pubKey.Verify(dataToVerify, sigBytes)
	if !valid || err != nil {
		logger.Error().Msg("Group control message has INVALID signature")
		return
	}

	parts := strings.Split(gMsg.Payload, ":")
	if len(parts) < 3 {
		return
	}
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
