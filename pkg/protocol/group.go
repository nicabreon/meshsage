
package protocol

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	Signature string `json:"signature"` // Tanda tangan identitas asli pengirim
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

// JoinGroup joins a GossipSub topic and initializes Sender Keys
func JoinGroup(ctx context.Context, h host.Host, priv crypto.PrivKey, groupID string, members []string) error {
	groupsMutex.Lock()
	defer groupsMutex.Unlock()

	if _, exists := activeGroups[groupID]; exists {
		return nil
	}

	if corenet.GlobalPubSub == nil {
		return fmt.Errorf("PubSub not initialized")
	}

	// 1. Join the topic
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

	// 3. Initialize or retrieve our local Sender Key for this group
	localKey, err := corestore.GetGroupLocalKey(groupID)
	if err != nil {
		// Generate new random key if none exists
		localKey = make([]byte, 32)
		rand.Read(localKey)
		corestore.SaveGroupLocalKey(groupID, localKey)
	}

	// 4. Save members and share our key with them
	corestore.AddGroupMember(groupID, h.ID().String())
	for _, m := range members {
		corestore.AddGroupMember(groupID, m)
		if m != h.ID().String() {
			go shareKeyWithMember(ctx, h, priv, groupID, m, localKey)
		}
	}


	session := &GroupSession{
		Topic:    topic,
		Sub:      sub,
		Host:     h,
	}
	activeGroups[groupID] = session

	// 5. Start listener goroutine
	go listenGroupMessages(ctx, session, groupID)

	logger.Displayf("[Group] Successfully joined room: %s with %d members\n", groupID, len(members))
	return nil
}

func shareKeyWithMember(ctx context.Context, h host.Host, priv crypto.PrivKey, groupID, memberID string, key []byte) {
	target, err := peer.Decode(memberID)
	if err != nil { return }

	logger.Debug().Msgf("[GROUP HANDSHAKE] Sharing our local key for group %s with member %s via Double Ratchet...", groupID, FormatPeerID(memberID))
	// Format: GKEY:<groupID>:<Base64Key>
	shareMsg := fmt.Sprintf("GKEY:%s:%s", groupID, base64.StdEncoding.EncodeToString(key))
	
	// We use the 1:1 SendMessage which is already secure (X3DH)
	errSend := SendMessage(ctx, h, priv, target, shareMsg)
	if errSend != nil {
		logger.Error().Err(errSend).Str("group", groupID).Str("member", memberID).Msg("[GROUP HANDSHAKE] Failed to share group key")
	} else {
		logger.Debug().Str("group", groupID).Str("member", memberID).Msg("[GROUP HANDSHAKE] Group key shared successfully")
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

		// Look up the sender's key for this group
		senderKey, err := corestore.GetGroupSenderKey(groupID, gMsg.SenderID)
		if err != nil {
			logger.Warn().Msgf("[Group %s] Received message from %s but no key found yet", groupID, FormatPeerID(gMsg.SenderID))
			continue
		}

		// Decrypt message using the Sender's specific key
		logger.Debug().Msg("[GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---")
		logger.Debug().Msgf("[GROUP E2EE] Incoming Ciphertext: %s", gMsg.Payload)
		plaintext, err := corecrypto.DecryptMessage(senderKey, gMsg.Payload)
		if err != nil {
			logger.Error().Msgf("[Group %s] Failed to decrypt message from %s (Key mismatch)", groupID, FormatPeerID(gMsg.SenderID))
			continue
		}
		logger.Debug().Msgf("[GROUP E2EE] Decrypted Result: %s", plaintext)

		// --- RATCHET: Putar kunci pengirim di database kita agar sinkron dengan pesan dia selanjutnya ---
		hKDF := hmac.New(sha256.New, senderKey)
		hKDF.Write([]byte("GROUP_RATCHET"))
		nextSenderKey := hKDF.Sum(nil)
		corestore.SaveGroupSenderKey(groupID, gMsg.SenderID, nextSenderKey)
		logger.Debug().Msgf("[Group Ratchet] Rotated sender key for @%s in group %s", FormatPeerID(gMsg.SenderID), groupID)

		// --- VERIFIKASI TANDA TANGAN ---
		if gMsg.Signature != "" {
			sID, _ := peer.Decode(gMsg.SenderID)
			pubKey, err := sID.ExtractPublicKey()
			if err == nil {
				dataToVerify := []byte(gMsg.Payload + gMsg.SenderID)
				sigBytes, _ := base64.StdEncoding.DecodeString(gMsg.Signature)
				valid, _ := pubKey.Verify(dataToVerify, sigBytes)
				if !valid {
					logger.Warn().Msgf("[Group Warning] REJECTED: Invalid signature from %s in group %s", FormatPeerID(gMsg.SenderID), groupID)
					continue
				}
				logger.Debug().Msgf("[Group Security] Message from @%s verified with Digital Signature.", FormatPeerID(gMsg.SenderID))
			}
		}

		ts := time.Now().Format("02/01 15:04:05")
		logger.Displayf("\033[92m[%s] [Group %s] %s: %s\033[0m\n", ts, groupID, FormatSender(gMsg.SenderID), plaintext)
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
}

// SendGroupMessage publishes an encrypted message to the group using OUR sender key
func SendGroupMessage(ctx context.Context, h host.Host, groupID string, message string) error {
	groupsMutex.Lock()
	session, exists := activeGroups[groupID]
	groupsMutex.Unlock()

	if !exists {
		return fmt.Errorf("not in group %s. Use /join first", groupID)
	}

	// 1. Get our local key
	localKey, err := corestore.GetGroupLocalKey(groupID)
	if err != nil { return err }

	// 2. Encrypt the payload with our key
	logger.Debug().Msg("[GROUP E2EE] --- LAYER 1: GROUP ENCRYPTION ---")
	logger.Debug().Msgf("[GROUP E2EE] Original Text: %s", message)
	encrypted, err := corecrypto.EncryptMessage(localKey, message)
	if err == nil {
		logger.Debug().Msgf("[GROUP E2EE] Encrypted Result (B64): %s", encrypted)
	}
	if err != nil { return err }

	// --- RATCHET: Putar kunci lokal kita untuk pesan grup berikutnya ---
	hKDF := hmac.New(sha256.New, localKey)
	hKDF.Write([]byte("GROUP_RATCHET"))
	nextLocalKey := hKDF.Sum(nil)
	corestore.SaveGroupLocalKey(groupID, nextLocalKey)
	logger.Debug().Msgf("[Group Ratchet] Rotated our local key for group %s", groupID)

	// 3. DIGITAL SIGNATURE: Tanda tangani Payload + SenderID
	privKey := h.Peerstore().PrivKey(h.ID())
	dataToSign := []byte(encrypted + h.ID().String())
	sigBytes, _ := privKey.Sign(dataToSign)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	gMsg := GroupMessage{
		SenderID:  h.ID().String(),
		Payload:   encrypted,
		Signature: sigB64,
	}
	msgBytes, _ := json.Marshal(gMsg)

	// 4. Publish to PubSub (for online members)
	err = session.Topic.Publish(ctx, msgBytes)
	if err != nil { return err }

	// 4. Store in Mailbox (for offline members)
	// Fan-out: Send the message individually to each member.
	// SendMessage will automatically handle direct-send or mailbox fallback with X3DH.
	members, err := corestore.GetGroupMembers(groupID)
	logger.Debug().Interface("members", members).Err(err).Msg("SendGroupMessage: Group members retrieved")
	if err == nil {
		for _, m := range members {
			if m == h.ID().String() {
				continue
			}
			target, err := peer.Decode(m)
			if err == nil {
				logger.Debug().Str("target", target.String()).Msg("SendGroupMessage: Launching SendMessage goroutine")
				go func(t peer.ID) {
					sendErr := SendMessage(ctx, h, h.Peerstore().PrivKey(h.ID()), t, "GRPM:"+groupID+":"+string(msgBytes))
					if sendErr != nil {
						logger.Error().Err(sendErr).Str("target", t.String()).Msg("SendGroupMessage: SendMessage failed")
					} else {
						logger.Debug().Str("target", t.String()).Msg("SendGroupMessage: SendMessage completed successfully")
					}
				}(target)
			} else {
				logger.Error().Err(err).Str("memberID", m).Msg("SendGroupMessage: Failed to decode member peerID")
			}
		}
	}
	
	return nil
}

func ProcessGroupMessage(groupID string, msgBytes []byte) {
	// Parse the outer envelope
	var gMsg GroupMessage
	err := json.Unmarshal(msgBytes, &gMsg)
	if err != nil { return }

	// Skip duplicate processing
	if checkAndMarkProcessed(gMsg.Signature) { return }

	// Look up the sender's key for this group
	senderKey, err := corestore.GetGroupSenderKey(groupID, gMsg.SenderID)
	if err != nil {
		logger.Warn().Msgf("[Group %s] Received offline message from %s but no key found yet", groupID, FormatPeerID(gMsg.SenderID))
		return
	}

	// Decrypt message using the Sender's specific key
	logger.Debug().Msg("[GROUP E2EE] --- LAYER 1: GROUP DECRYPTION (OFFLINE) ---")
	logger.Debug().Msgf("[GROUP E2EE] Incoming Ciphertext: %s", gMsg.Payload)
	plaintext, err := corecrypto.DecryptMessage(senderKey, gMsg.Payload)
	if err != nil {
		logger.Error().Msgf("[Group %s] Failed to decrypt offline message from %s (Key mismatch)", groupID, FormatPeerID(gMsg.SenderID))
		return
	}

	// --- RATCHET: Putar kunci pengirim di database kita agar sinkron dengan pesan dia selanjutnya ---
	hKDF := hmac.New(sha256.New, senderKey)
	hKDF.Write([]byte("GROUP_RATCHET"))
	nextSenderKey := hKDF.Sum(nil)
	corestore.SaveGroupSenderKey(groupID, gMsg.SenderID, nextSenderKey)
	logger.Debug().Msgf("[Group Ratchet] Rotated sender key for @%s in group %s", FormatPeerID(gMsg.SenderID), groupID)
	
	logger.Debug().Msgf("[GROUP E2EE] Decrypted Result: %s", plaintext)

	// --- VERIFIKASI TANDA TANGAN (OFFLINE) ---
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
			logger.Debug().Msgf("[Group Security] Offline Message from @%s verified.", FormatPeerID(gMsg.SenderID))
		}
	}

	ts := time.Now().Format("02/01 15:04:05")
	logger.Displayf("\033[92m[%s] [Group %s] %s (Offline): %s\033[0m\n", ts, groupID, FormatSender(gMsg.SenderID), plaintext)
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

// RestoreGroups loads groups that we are members of from the database and joins them.
func RestoreGroups(ctx context.Context, h host.Host, priv crypto.PrivKey) error {
	groups, err := corestore.GetGroupMemberships(h.ID().String())
	if err != nil {
		return err
	}
	for _, gid := range groups {
		members, err := corestore.GetGroupMembers(gid)
		if err == nil {
			err = JoinGroup(ctx, h, priv, gid, members)
			if err != nil {
				logger.Error().Err(err).Str("groupID", gid).Msg("Failed to auto-restore group membership")
			} else {
				logger.Info().Str("groupID", gid).Msg("Auto-restored group membership on startup")
			}
		}
	}
	return nil
}

