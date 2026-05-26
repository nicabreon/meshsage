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
	Timestamp string `json:"timestamp"`
	Sender    string `json:"sender"`
	GroupID   string `json:"group_id,omitempty"`
	Content   string `json:"content"`
}

// MessageCallback is a global hook invoked when new direct or group messages are decrypted
var MessageCallback func(event MessageEvent)

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
