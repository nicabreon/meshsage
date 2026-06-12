package storage

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// GroupMetadata represents the persistent metadata of a group.
type GroupMetadata struct {
	GroupID    string `json:"group_id"`
	GroupAlias string `json:"group_alias"`
	CreatorID  string `json:"creator_id"`
	GroupType  string `json:"group_type"`
	CreatedAt  int64  `json:"created_at"`
	Signature  string `json:"signature"`
}

// GroupMemberV2 represents a member record with role.
type GroupMemberV2 struct {
	PeerID string
	Role   string
}

// SaveGroupMetadata persists a group's metadata.
func SaveGroupMetadata(meta GroupMetadata) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_metadata 
		(group_id, group_alias, creator_id, group_type, created_at, signature) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.CreatedAt, meta.Signature)
	return err
}

// LoadGroupMetadata retrieves a group's metadata by its ID or Alias.
func LoadGroupMetadata(idOrAlias string) (meta GroupMetadata, err error) {
	if DB == nil {
		return meta, fmt.Errorf("database not initialized")
	}

	// Clean the alias search term
	alias := idOrAlias
	if !strings.HasPrefix(alias, "@") {
		alias = "@" + alias
	}

	row := DB.QueryRow(`SELECT group_id, group_alias, creator_id, group_type, created_at, signature 
		FROM group_metadata WHERE group_id = ? OR group_alias = ? OR group_alias = ?`,
		idOrAlias, idOrAlias, alias)

	err = row.Scan(&meta.GroupID, &meta.GroupAlias, &meta.CreatorID, &meta.GroupType, &meta.CreatedAt, &meta.Signature)
	return
}

// GetGroupType returns the group type ("SECURE" or "UNSECURE").
func GetGroupType(groupID string) (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database not initialized")
	}
	var gtype string
	err := DB.QueryRow("SELECT group_type FROM group_metadata WHERE group_id = ?", groupID).Scan(&gtype)
	return gtype, err
}

// DeleteGroupMetadata removes a group completely from database (disband).
func DeleteGroupMetadata(groupID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err1 := DB.Exec(`DELETE FROM group_metadata WHERE group_id = ?`, groupID)
	_, err2 := DB.Exec(`DELETE FROM group_members_v2 WHERE group_id = ?`, groupID)
	if err1 != nil {
		return err1
	}
	return err2
}

// AddGroupMemberV2 inserts or updates a group member with their role.
func AddGroupMemberV2(groupID, peerID, role string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_members_v2 
		(group_id, peer_id, role, joined_at) VALUES (?, ?, ?, ?)`,
		groupID, peerID, role, time.Now().Unix())
	return err
}

// RemoveGroupMemberV2 deletes a member from the group.
func RemoveGroupMemberV2(groupID, peerID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`DELETE FROM group_members_v2 WHERE group_id = ? AND peer_id = ?`, groupID, peerID)
	return err
}

// GetGroupMembersV2 retrieves all members and their roles in a group.
func GetGroupMembersV2(groupID string) ([]GroupMemberV2, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(`SELECT peer_id, role FROM group_members_v2 WHERE group_id = ? ORDER BY joined_at ASC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []GroupMemberV2
	for rows.Next() {
		var m GroupMemberV2
		if err := rows.Scan(&m.PeerID, &m.Role); err == nil {
			members = append(members, m)
		}
	}
	return members, nil
}

// SaveGroupLocalKey saves the local sender key for a group (with history).
func SaveGroupLocalKey(groupID string, key []byte) error {
	keyB64 := base64.StdEncoding.EncodeToString(key)
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_local_keys (group_id, sender_key) VALUES (?, ?)`,
		groupID, keyB64)
	if err != nil {
		return err
	}
	_, _ = DB.Exec(`INSERT OR IGNORE INTO group_local_key_history (group_id, sender_key) VALUES (?, ?)`,
		groupID, keyB64)
	// Prune history to keep only the last 20 keys
	_, _ = DB.Exec(`DELETE FROM group_local_key_history WHERE group_id = ? AND rowid NOT IN (
		SELECT rowid FROM group_local_key_history WHERE group_id = ? ORDER BY rowid DESC LIMIT 20
	)`, groupID, groupID)
	return nil
}

// GetGroupLocalKey retrieves the current local sender key for a group.
func GetGroupLocalKey(groupID string) ([]byte, error) {
	var keyStr string
	err := DB.QueryRow(`SELECT sender_key FROM group_local_keys WHERE group_id = ?`, groupID).Scan(&keyStr)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(keyStr)
}

// GetGroupLocalKeyHistory retrieves all historical local sender keys for a group.
func GetGroupLocalKeyHistory(groupID string) ([][]byte, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(`SELECT sender_key FROM group_local_key_history WHERE group_id = ? ORDER BY rowid DESC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys [][]byte
	for rows.Next() {
		var keyStr string
		if err := rows.Scan(&keyStr); err == nil {
			if k, errDec := base64.StdEncoding.DecodeString(keyStr); errDec == nil {
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}

// SaveGroupSenderKey saves a peer's sender key for a group (with history).
func SaveGroupSenderKey(groupID, senderID string, key []byte) error {
	keyB64 := base64.StdEncoding.EncodeToString(key)
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_sender_keys (group_id, sender_id, sender_key) VALUES (?, ?, ?)`,
		groupID, senderID, keyB64)
	if err != nil {
		return err
	}
	_, _ = DB.Exec(`INSERT OR IGNORE INTO group_sender_key_history (group_id, sender_id, sender_key) VALUES (?, ?, ?)`,
		groupID, senderID, keyB64)
	// Prune history to keep only the last 20 keys
	_, _ = DB.Exec(`DELETE FROM group_sender_key_history WHERE group_id = ? AND sender_id = ? AND rowid NOT IN (
		SELECT rowid FROM group_sender_key_history WHERE group_id = ? AND sender_id = ? ORDER BY rowid DESC LIMIT 20
	)`, groupID, senderID, groupID, senderID)
	return nil
}

// GetGroupSenderKey retrieves the current sender key from a specific peer in a group.
func GetGroupSenderKey(groupID, senderID string) ([]byte, error) {
	var keyStr string
	err := DB.QueryRow(`SELECT sender_key FROM group_sender_keys WHERE group_id = ? AND sender_id = ?`,
		groupID, senderID).Scan(&keyStr)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(keyStr)
}

// GetGroupSenderKeyHistory retrieves all historical sender keys from a specific peer in a group.
func GetGroupSenderKeyHistory(groupID, senderID string) ([][]byte, error) {
	rows, err := DB.Query(`SELECT sender_key FROM group_sender_key_history WHERE group_id = ? AND sender_id = ? ORDER BY rowid DESC`,
		groupID, senderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys [][]byte
	for rows.Next() {
		var keyStr string
		if err := rows.Scan(&keyStr); err == nil {
			if k, errDec := base64.StdEncoding.DecodeString(keyStr); errDec == nil {
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}
