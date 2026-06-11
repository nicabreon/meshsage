package storage

import (
	"encoding/base64"
	"fmt"
)

// SaveSession persists the Double Ratchet session state for a peer.
func SaveSession(peerID, remoteIdentityKey, rootKey, sendChainKey, recvChainKey, remoteRatchetPub, localRatchetPriv, localRatchetPub string, n, m, pn, outboundMsgsSinceRatchet uint32) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR REPLACE INTO sessions 
		(peer_id, remote_identity_key, root_key, send_chain_key, recv_chain_key, remote_ratchet_pubkey, local_ratchet_privkey, local_ratchet_pubkey, n, m, pn, outbound_msgs_since_ratchet, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		peerID, remoteIdentityKey, rootKey, sendChainKey, recvChainKey, remoteRatchetPub, localRatchetPriv, localRatchetPub, n, m, pn, outboundMsgsSinceRatchet)
	return err
}

// LoadSession retrieves the Double Ratchet session state for a peer.
func LoadSession(peerID string) (remoteIdentityKey, rootKey, sendChainKey, recvChainKey, remoteRatchetPub, localRatchetPriv, localRatchetPub string, n, m, pn, outboundMsgsSinceRatchet uint32, err error) {
	if DB == nil {
		return "", "", "", "", "", "", "", 0, 0, 0, 0, fmt.Errorf("database not initialized")
	}
	row := DB.QueryRow(`SELECT remote_identity_key, root_key, send_chain_key, recv_chain_key, remote_ratchet_pubkey, local_ratchet_privkey, local_ratchet_pubkey, n, m, pn, outbound_msgs_since_ratchet FROM sessions WHERE peer_id = ?`, peerID)
	err = row.Scan(&remoteIdentityKey, &rootKey, &sendChainKey, &recvChainKey, &remoteRatchetPub, &localRatchetPriv, &localRatchetPub, &n, &m, &pn, &outboundMsgsSinceRatchet)
	return
}

// SaveSkippedKey stores a message key for an out-of-order message.
func SaveSkippedKey(peerID string, counter uint32, key []byte) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR REPLACE INTO skipped_keys (peer_id, counter, msg_key) VALUES (?, ?, ?)`,
		peerID, counter, base64.StdEncoding.EncodeToString(key))
	return err
}

// GetSkippedKey retrieves and DELETES a message key for an out-of-order message.
func GetSkippedKey(peerID string, counter uint32) ([]byte, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	var keyStr string
	err := DB.QueryRow(`SELECT msg_key FROM skipped_keys WHERE peer_id = ? AND counter = ?`, peerID, counter).Scan(&keyStr)
	if err != nil {
		return nil, err
	}
	// Delete after retrieval (one-time use)
	DB.Exec(`DELETE FROM skipped_keys WHERE peer_id = ? AND counter = ?`, peerID, counter)
	return base64.StdEncoding.DecodeString(keyStr)
}

// ClearSkippedKeys removes ALL skipped keys for a peer.
// Must be called whenever a DH Ratchet step occurs or a new X3DH session is established,
// because old epoch keys are permanently invalid.
func ClearSkippedKeys(peerID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`DELETE FROM skipped_keys WHERE peer_id = ?`, peerID)
	return err
}

// DeleteSession removes the Double Ratchet session for a peer.
func DeleteSession(peerID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`DELETE FROM sessions WHERE peer_id = ?`, peerID)
	if err != nil {
		return err
	}
	// Also clear skipped keys
	_ = ClearSkippedKeys(peerID)
	return nil
}

// HasSession returns true if a Double Ratchet session exists for the given peerID.
func HasSession(peerID string) bool {
	if DB == nil {
		return false
	}
	var count int
	err := DB.QueryRow(`SELECT COUNT(1) FROM sessions WHERE peer_id = ? AND root_key != ''`, peerID).Scan(&count)
	return err == nil && count > 0
}
