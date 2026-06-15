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
	encRoot, err := EncryptColumn(rootKey)
	if err != nil {
		return err
	}
	encSend, err := EncryptColumn(sendChainKey)
	if err != nil {
		return err
	}
	encRecv, err := EncryptColumn(recvChainKey)
	if err != nil {
		return err
	}
	encLocalRatchet, err := EncryptColumn(localRatchetPriv)
	if err != nil {
		return err
	}

	_, err = DB.Exec(`INSERT OR REPLACE INTO sessions 
		(peer_id, remote_identity_key, root_key, send_chain_key, recv_chain_key, remote_ratchet_pubkey, local_ratchet_privkey, local_ratchet_pubkey, n, m, pn, outbound_msgs_since_ratchet, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		peerID, remoteIdentityKey, encRoot, encSend, encRecv, remoteRatchetPub, encLocalRatchet, localRatchetPub, n, m, pn, outboundMsgsSinceRatchet)
	return err
}

// LoadSession retrieves the Double Ratchet session state for a peer.
func LoadSession(peerID string) (remoteIdentityKey, rootKey, sendChainKey, recvChainKey, remoteRatchetPub, localRatchetPriv, localRatchetPub string, n, m, pn, outboundMsgsSinceRatchet uint32, err error) {
	if DB == nil {
		return "", "", "", "", "", "", "", 0, 0, 0, 0, fmt.Errorf("database not initialized")
	}
	var encRoot, encSend, encRecv, encLocalRatchet string
	row := DB.QueryRow(`SELECT remote_identity_key, root_key, send_chain_key, recv_chain_key, remote_ratchet_pubkey, local_ratchet_privkey, local_ratchet_pubkey, n, m, pn, outbound_msgs_since_ratchet FROM sessions WHERE peer_id = ?`, peerID)
	err = row.Scan(&remoteIdentityKey, &encRoot, &encSend, &encRecv, &remoteRatchetPub, &encLocalRatchet, &localRatchetPub, &n, &m, &pn, &outboundMsgsSinceRatchet)
	if err != nil {
		return
	}
	rootKey, err = DecryptColumn(encRoot)
	if err != nil {
		return
	}
	sendChainKey, err = DecryptColumn(encSend)
	if err != nil {
		return
	}
	recvChainKey, err = DecryptColumn(encRecv)
	if err != nil {
		return
	}
	localRatchetPriv, err = DecryptColumn(encLocalRatchet)
	return
}

// SaveSkippedKey stores a message key for an out-of-order message.
func SaveSkippedKey(peerID string, ratchetPub []byte, counter uint32, key []byte) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	ratchetPubB64 := base64.StdEncoding.EncodeToString(ratchetPub)
	_, err := DB.Exec(`INSERT OR REPLACE INTO skipped_keys_v2 (peer_id, ratchet_pub, counter, msg_key) VALUES (?, ?, ?, ?)`,
		peerID, ratchetPubB64, counter, base64.StdEncoding.EncodeToString(key))
	return err
}

// GetSkippedKey retrieves and DELETES a message key for an out-of-order message.
func GetSkippedKey(peerID string, ratchetPub []byte, counter uint32) ([]byte, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	var keyStr string
	ratchetPubB64 := base64.StdEncoding.EncodeToString(ratchetPub)
	err := DB.QueryRow(`SELECT msg_key FROM skipped_keys_v2 WHERE peer_id = ? AND ratchet_pub = ? AND counter = ?`, peerID, ratchetPubB64, counter).Scan(&keyStr)
	if err != nil {
		return nil, err
	}
	// Delete after retrieval (one-time use)
	DB.Exec(`DELETE FROM skipped_keys_v2 WHERE peer_id = ? AND ratchet_pub = ? AND counter = ?`, peerID, ratchetPubB64, counter)
	return base64.StdEncoding.DecodeString(keyStr)
}

// ClearSkippedKeys removes ALL skipped keys for a peer.
// Used when resetting sessions or destroying stale states.
func ClearSkippedKeys(peerID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`DELETE FROM skipped_keys_v2 WHERE peer_id = ?`, peerID)
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

// GetSessionUpdateTime returns the last updated time (in UTC) for the session of a peerID.
func GetSessionUpdateTime(peerID string) (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database not initialized")
	}
	var updatedAt string
	err := DB.QueryRow(`SELECT updated_at FROM sessions WHERE peer_id = ?`, peerID).Scan(&updatedAt)
	if err != nil {
		return "", err
	}
	return updatedAt, nil
}
