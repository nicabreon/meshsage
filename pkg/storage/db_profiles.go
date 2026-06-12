package storage

import "fmt"

// SavePeerProfile stores or updates a cached peer profile record.
func SavePeerProfile(peerID, displayName, avatarCID, avatarKey, localPath string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	// Load existing first to merge fields
	existingName, existingCID, existingKey, existingPath, err := GetPeerProfile(peerID)
	if err == nil {
		if displayName == "" {
			displayName = existingName
		}
		if avatarCID == "" {
			avatarCID = existingCID
		}
		if avatarKey == "" {
			avatarKey = existingKey
		}
		// If avatarCID has changed, discard the old localPath unless a new one is provided.
		// localPath stays empty if not explicitly given (already the value passed in).
		if existingCID == "" || avatarCID == existingCID {
			if localPath == "" {
				localPath = existingPath
			}
		}
	}

	_, err = DB.Exec(`
		INSERT OR REPLACE INTO profile_store (peer_id, display_name, avatar_cid, avatar_key, local_path, updated_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		peerID, displayName, avatarCID, avatarKey, localPath)
	return err
}

// GetPeerProfile loads a cached peer profile record.
func GetPeerProfile(peerID string) (displayName, avatarCID, avatarKey, localPath string, err error) {
	if DB == nil {
		return "", "", "", "", fmt.Errorf("database not initialized")
	}
	row := DB.QueryRow("SELECT display_name, avatar_cid, avatar_key, local_path FROM profile_store WHERE peer_id = ?", peerID)
	err = row.Scan(&displayName, &avatarCID, &avatarKey, &localPath)
	return
}
