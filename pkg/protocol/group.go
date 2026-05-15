
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

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
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
	activeGroups = make(map[string]*GroupSession)
	groupsMutex  sync.Mutex
)

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

	fmt.Printf("[Group] Successfully joined room: %s with %d members\n", groupID, len(members))
	return nil
}

func shareKeyWithMember(ctx context.Context, h host.Host, priv crypto.PrivKey, groupID, memberID string, key []byte) {
	target, err := peer.Decode(memberID)
	if err != nil { return }

	fmt.Printf("[GROUP HANDSHAKE] Sharing our local key for group %s with member %s via Double Ratchet...\n", groupID, FormatPeerID(memberID))
	// Format: GKEY:<groupID>:<Base64Key>
	shareMsg := fmt.Sprintf("GKEY:%s:%s", groupID, base64.StdEncoding.EncodeToString(key))
	
	// We use the 1:1 SendMessage which is already secure (X3DH)
	_ = SendMessage(ctx, h, priv, target, shareMsg)
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

		// Look up the sender's key for this group
		senderKey, err := corestore.GetGroupSenderKey(groupID, gMsg.SenderID)
		if err != nil {
			fmt.Printf("[Group %s] Received message from %s but no key found yet\n", groupID, FormatPeerID(gMsg.SenderID))
			continue
		}

		// Decrypt message using the Sender's specific key
		fmt.Printf("[GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---\n")
		fmt.Printf("[GROUP E2EE] Incoming Ciphertext: %s\n", gMsg.Payload)
		plaintext, err := corecrypto.DecryptMessage(senderKey, gMsg.Payload)
		if err != nil {
			fmt.Printf("[Group %s] Failed to decrypt message from %s (Key mismatch)\n", groupID, FormatPeerID(gMsg.SenderID))
			continue
		}
		fmt.Printf("[GROUP E2EE] Decrypted Result: %s\n", plaintext)

		// --- RATCHET: Putar kunci pengirim di database kita agar sinkron dengan pesan dia selanjutnya ---
		hKDF := hmac.New(sha256.New, senderKey)
		hKDF.Write([]byte("GROUP_RATCHET"))
		nextSenderKey := hKDF.Sum(nil)
		corestore.SaveGroupSenderKey(groupID, gMsg.SenderID, nextSenderKey)
		fmt.Printf("[Group Ratchet] Rotated sender key for @%s in group %s\n", FormatPeerID(gMsg.SenderID), groupID)

		// --- VERIFIKASI TANDA TANGAN ---
		if gMsg.Signature != "" {
			sID, _ := peer.Decode(gMsg.SenderID)
			pubKey, err := sID.ExtractPublicKey()
			if err == nil {
				dataToVerify := []byte(gMsg.Payload + gMsg.SenderID)
				sigBytes, _ := base64.StdEncoding.DecodeString(gMsg.Signature)
				valid, _ := pubKey.Verify(dataToVerify, sigBytes)
				if !valid {
					fmt.Printf("[Group Warning] REJECTED: Invalid signature from %s in group %s\n", FormatPeerID(gMsg.SenderID), groupID)
					continue
				}
				fmt.Printf("[Group Security] Message from @%s verified with Digital Signature.\n", FormatPeerID(gMsg.SenderID))
			}
		}

		fmt.Printf("\n[Group %s] @%s: %s\n> ", groupID, FormatPeerID(gMsg.SenderID), plaintext)
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
	fmt.Printf("[GROUP E2EE] --- LAYER 1: GROUP ENCRYPTION ---\n")
	fmt.Printf("[GROUP E2EE] Original Text: %s\n", message)
	encrypted, err := corecrypto.EncryptMessage(localKey, message)
	if err == nil {
		fmt.Printf("[GROUP E2EE] Encrypted Result (B64): %s\n", encrypted)
	}
	if err != nil { return err }

	// --- RATCHET: Putar kunci lokal kita untuk pesan grup berikutnya ---
	hKDF := hmac.New(sha256.New, localKey)
	hKDF.Write([]byte("GROUP_RATCHET"))
	nextLocalKey := hKDF.Sum(nil)
	corestore.SaveGroupLocalKey(groupID, nextLocalKey)
	fmt.Printf("[Group Ratchet] Rotated our local key for group %s\n", groupID)

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
	if err == nil {
		for _, m := range members {
			if m == h.ID().String() {
				continue
			}
			target, err := peer.Decode(m)
			if err == nil {
				// We prefix with GRPM: so the receiver knows it's a group message
				go SendMessage(ctx, h, h.Peerstore().PrivKey(h.ID()), target, "GRPM:"+groupID+":"+string(msgBytes))
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

	// Look up the sender's key for this group
	senderKey, err := corestore.GetGroupSenderKey(groupID, gMsg.SenderID)
	if err != nil {
		fmt.Printf("[Group %s] Received offline message from %s but no key found yet\n", groupID, FormatPeerID(gMsg.SenderID))
		return
	}

	// Decrypt message using the Sender's specific key
	fmt.Printf("[GROUP E2EE] --- LAYER 1: GROUP DECRYPTION (OFFLINE) ---\n")
	fmt.Printf("[GROUP E2EE] Incoming Ciphertext: %s\n", gMsg.Payload)
	plaintext, err := corecrypto.DecryptMessage(senderKey, gMsg.Payload)
	if err != nil {
		fmt.Printf("[Group %s] Failed to decrypt offline message from %s (Key mismatch)\n", groupID, FormatPeerID(gMsg.SenderID))
		return
	}

	// --- RATCHET: Putar kunci pengirim di database kita agar sinkron dengan pesan dia selanjutnya ---
	hKDF := hmac.New(sha256.New, senderKey)
	hKDF.Write([]byte("GROUP_RATCHET"))
	nextSenderKey := hKDF.Sum(nil)
	corestore.SaveGroupSenderKey(groupID, gMsg.SenderID, nextSenderKey)
	fmt.Printf("[Group Ratchet] Rotated sender key for @%s in group %s\n", FormatPeerID(gMsg.SenderID), groupID)
	
	fmt.Printf("[GROUP E2EE] Decrypted Result: %s\n", plaintext)

	// --- VERIFIKASI TANDA TANGAN (OFFLINE) ---
	if gMsg.Signature != "" {
		sID, _ := peer.Decode(gMsg.SenderID)
		pubKey, err := sID.ExtractPublicKey()
		if err == nil {
			dataToVerify := []byte(gMsg.Payload + gMsg.SenderID)
			sigBytes, _ := base64.StdEncoding.DecodeString(gMsg.Signature)
			valid, _ := pubKey.Verify(dataToVerify, sigBytes)
			if !valid {
				fmt.Printf("[Group Warning] REJECTED: Invalid signature on offline message from %s\n", FormatPeerID(gMsg.SenderID))
				return
			}
			fmt.Printf("[Group Security] Offline Message from @%s verified.\n", FormatPeerID(gMsg.SenderID))
		}
	}

	fmt.Printf("\n[Group %s] @%s (Offline): %s\n> ", groupID, FormatPeerID(gMsg.SenderID), plaintext)
}
