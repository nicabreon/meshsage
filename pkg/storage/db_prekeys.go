package storage

import "fmt"

// SavePreKey stores a signed one-time public key in the relay or local DB.
func SavePreKey(ownerID, keyID, pubKey, privKey, sig string) error {
	var valToSave string
	var err error
	if privKey != "" {
		valToSave, err = EncryptColumn(privKey)
		if err != nil {
			return err
		}
	}
	_, err = DB.Exec("INSERT OR REPLACE INTO prekeys (owner_id, key_id, public_key, private_key, signature) VALUES (?, ?, ?, ?, ?)",
		ownerID, keyID, pubKey, valToSave, sig)
	return err
}

// DeletePreKeysByOwner deletes all pre-keys associated with an owner ID.
func DeletePreKeysByOwner(ownerID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec("DELETE FROM prekeys WHERE owner_id = ?", ownerID)
	return err
}

// DeletePublicPreKeysByOwner deletes only pre-keys that have NO private key stored
// (i.e. keys that belong to other users cached on this relay node).
// This preserves the local node's own private keys during PREKEY_CLEAR cluster events.
func DeletePublicPreKeysByOwner(ownerID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec("DELETE FROM prekeys WHERE owner_id = ? AND (private_key IS NULL OR private_key = '')", ownerID)
	return err
}

// DeletePreKeyByID deletes a specific pre-key by its unique key ID.
func DeletePreKeyByID(keyID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec("DELETE FROM prekeys WHERE key_id = ?", keyID)
	return err
}

// DeletePublicPreKeyByID deletes a pre-key by ID only if its private_key column is NULL or empty.
func DeletePublicPreKeyByID(keyID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec("DELETE FROM prekeys WHERE key_id = ? AND (private_key IS NULL OR private_key = '')", keyID)
	return err
}

// FindPrivateKeyByID retrieves the private key associated with a KeyID (for receivers).
func FindPrivateKeyByID(keyID string) (string, error) {
	var encryptedPriv string
	err := DB.QueryRow("SELECT private_key FROM prekeys WHERE key_id = ?", keyID).Scan(&encryptedPriv)
	if err != nil {
		return "", err
	}
	return DecryptColumn(encryptedPriv)
}

// FetchOnePreKey retrieves one pre-key. If it belongs to someone else, it's DELETED (one-time use).
// If it belongs to selfID, it is NOT deleted so we can still use it for decryption.
func FetchOnePreKey(targetOwnerID string, selfID string) (keyID string, pubKey string, sig string, err error) {
	row := DB.QueryRow("SELECT key_id, public_key, signature FROM prekeys WHERE owner_id = ? ORDER BY created_at ASC LIMIT 1", targetOwnerID)
	err = row.Scan(&keyID, &pubKey, &sig)
	if err == nil {
		// Enforce One-Time Use ONLY if it's not our own key
		if targetOwnerID != selfID {
			DB.Exec("DELETE FROM prekeys WHERE key_id = ?", keyID)
		}
	}
	return
}

// GetPreKeyCount returns how many keys are left for a user.
func GetPreKeyCount(ownerID string) int {
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM prekeys WHERE owner_id = ?", ownerID).Scan(&count)
	return count
}
