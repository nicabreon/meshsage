package protocol

import (
	"crypto/sha256"
	"fmt"
	"strings"

	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

// FormatPeerID returns a shortened, unique PeerID representation for UI/logs
func FormatPeerID(id string) string {
	if len(id) > 8 {
		return "..." + id[len(id)-8:]
	}
	return id
}

// MessageEvent represents a structured, decrypted chat or log event for client frontends
type MessageEvent struct {
	Type      string `json:"type"` // "direct", "group", "file"
	MsgID     string `json:"msg_id,omitempty"`
	Timestamp string `json:"timestamp"`
	Sender    string `json:"sender"`
	GroupID   string `json:"group_id,omitempty"`
	Content   string `json:"content"`
	UnixTime  int64  `json:"unix_time,omitempty"`
}

// StatusEvent represents a delivery status update for a previously sent message
type StatusEvent struct {
	RefID  string `json:"ref_id"` // ID of the original sent message
	Status string `json:"status"` // e.g. "delivered"
	Sender string `json:"sender"` // peer who acknowledged
}

// MessageCallback is a global hook invoked when new direct or group messages are decrypted
var MessageCallback func(event MessageEvent)

// StatusCallback is a global hook invoked when a delivery status update is received
var StatusCallback func(event StatusEvent)

// SubscriptionStatusEvent represents a change in mailbox notification subscription status
type SubscriptionStatusEvent struct {
	RelayID string `json:"relay_id"`
	Active  bool   `json:"active"`
}

// SubscriptionStatusCallback is a global hook invoked when push notification subscription status changes
var SubscriptionStatusCallback func(event SubscriptionStatusEvent)

// FormatSender returns a human-friendly sender label:
//   - "@alias" if the peer has a known alias registered locally
//   - "...abc12345" (short) if no alias is registered
func FormatSender(peerID string) string {
	// Prefer alias — cleaner display in group chat
	if alias, err := corestore.FindAliasByPeerID(peerID); err == nil && alias != "" {
		return alias
	}
	return FormatPeerID(peerID)
}

// GetAliasCoordinate ensures the alias starts with @ and returns its hex hash
func GetAliasCoordinate(alias string) string {
	if !strings.HasPrefix(alias, "@") {
		alias = "@" + alias
	}
	hash := sha256.Sum256([]byte(alias))
	return fmt.Sprintf("%x", hash)
}
