package protocol

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// FormatPeerID returns the full PeerID for traceability
func FormatPeerID(id string) string {
	return id
}

// GetAliasCoordinate ensures the alias starts with @ and returns its hex hash
func GetAliasCoordinate(alias string) string {
	if !strings.HasPrefix(alias, "@") {
		alias = "@" + alias
	}
	hash := sha256.Sum256([]byte(alias))
	return fmt.Sprintf("%x", hash)
}
