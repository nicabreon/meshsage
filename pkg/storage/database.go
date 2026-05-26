package storage

import (
	"database/sql"
	"encoding/base64"
	"fmt"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// InitDatabase initializes the local SQLite database.
func InitDatabase(dbPath string) error {
	var err error
	// modernc.org/sqlite uses the "sqlite" driver name
	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	
	// Enable WAL mode for better concurrency
	DB.Exec("PRAGMA journal_mode=WAL;")
	DB.Exec("PRAGMA busy_timeout=5000;")
	DB.SetMaxOpenConns(1) // SQLite works best with 1 writer for modernc

	// Create messages table if it doesn't exist (For local history)
	query := `
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender_id TEXT NOT NULL,
		recipient_id TEXT NOT NULL,
		content TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	-- Create mailbox table for Store-and-Forward (Offline Messages)
	CREATE TABLE IF NOT EXISTS mailbox (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		msg_hash TEXT UNIQUE NOT NULL,
		recipient_id TEXT NOT NULL,
		sender_pubkey TEXT NOT NULL,
		payload TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME DEFAULT (datetime('now', '+7 days'))
	);
	
	-- Create block_metadata table for Garbage Collection
	CREATE TABLE IF NOT EXISTS block_metadata (
		cid TEXT PRIMARY KEY,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	-- Create prekeys table for X3DH (Double Ratchet)
	CREATE TABLE IF NOT EXISTS prekeys (
		owner_id TEXT NOT NULL,
		key_id TEXT PRIMARY KEY,
		public_key TEXT NOT NULL,
		private_key TEXT,
		signature TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	-- Create sessions table for Double Ratchet state
	CREATE TABLE IF NOT EXISTS sessions (
		peer_id TEXT PRIMARY KEY,
		remote_identity_key TEXT,
		root_key TEXT,
		send_chain_key TEXT,
		recv_chain_key TEXT,
		remote_ratchet_pubkey TEXT,
		local_ratchet_privkey TEXT,
		local_ratchet_pubkey TEXT,
		n INTEGER DEFAULT 0,
		m INTEGER DEFAULT 0,
		pn INTEGER DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Create skipped_keys table for out-of-order messages
	CREATE TABLE IF NOT EXISTS skipped_keys (
		peer_id TEXT,
		counter INTEGER,
		msg_key TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (peer_id, counter)
	);

	-- 7. Group Sender Keys (Keys received from others)
	CREATE TABLE IF NOT EXISTS group_sender_keys (
		group_id TEXT,
		sender_id TEXT,
		sender_key TEXT,
		counter INTEGER DEFAULT 0,
		PRIMARY KEY (group_id, sender_id)
	);

	-- 8. Local Group Keys (Our own keys that we share)
	CREATE TABLE IF NOT EXISTS group_local_keys (
		group_id TEXT PRIMARY KEY,
		sender_key TEXT NOT NULL
	);

	-- 9. Group Members
	CREATE TABLE IF NOT EXISTS group_members (
		group_id TEXT,
		peer_id TEXT,
		PRIMARY KEY (group_id, peer_id)
	);

	-- Create alias_store table for persistent alias registry
	CREATE TABLE IF NOT EXISTS alias_store (
		alias_hash TEXT PRIMARY KEY,
		alias_name TEXT NOT NULL,
		peer_id TEXT NOT NULL,
		pubkey_bytes BLOB NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Performance & Concurrency Tuning
	DB.Exec("PRAGMA journal_mode = WAL;")
	DB.Exec("PRAGMA synchronous = NORMAL;")
	DB.Exec("PRAGMA busy_timeout = 5000;")
	DB.SetMaxOpenConns(1)

	return nil
}

// SavePreKey stores a signed one-time public key in the relay or local DB
func SavePreKey(ownerID, keyID, pubKey, privKey, sig string) error {
	_, err := DB.Exec("INSERT OR REPLACE INTO prekeys (owner_id, key_id, public_key, private_key, signature) VALUES (?, ?, ?, ?, ?)",
		ownerID, keyID, pubKey, privKey, sig)
	return err
}

// FindPrivateKeyByID retrieves the private key associated with a KeyID (for receivers)
func FindPrivateKeyByID(keyID string) (string, error) {
	var privKey string
	err := DB.QueryRow("SELECT private_key FROM prekeys WHERE key_id = ?", keyID).Scan(&privKey)
	return privKey, err
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

// GetPreKeyCount returns how many keys are left for a user
func GetPreKeyCount(ownerID string) int {
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM prekeys WHERE owner_id = ?", ownerID).Scan(&count)
	return count
}

// SaveMessage stores a message in the local database.
func SaveMessage(senderID, recipientID, content string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	query := `INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)`
	_, err := DB.Exec(query, senderID, recipientID, content)
	if err != nil {
		return fmt.Errorf("failed to insert message: %w", err)
	}
	return nil
}

// MailboxMessage represents a pending offline message
type MailboxMessage struct {
	ID           int    `json:"id"`
	MsgHash      string `json:"msg_hash"`
	RecipientID  string `json:"recipient_id"`
	SenderPubkey string `json:"sender_pubkey"`
	Payload      string `json:"payload"`
	Timestamp    string `json:"timestamp"`
}

// SaveMailboxMessage stores an encrypted offline message for a recipient
func SaveMailboxMessage(msgHash, recipientID, senderPubkey, payload string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	query := `INSERT OR IGNORE INTO mailbox (msg_hash, recipient_id, sender_pubkey, payload) VALUES (?, ?, ?, ?)`
	_, err := DB.Exec(query, msgHash, recipientID, senderPubkey, payload)
	return err
}

// DeleteMailboxMessageByHash removes a message from the cluster by its unique hash
func DeleteMailboxMessageByHash(msgHash string) error {
	if DB == nil { return nil }
	_, err := DB.Exec(`DELETE FROM mailbox WHERE msg_hash = ?`, msgHash)
	return err
}

// GetMailboxMessages retrieves all pending messages for a recipient
func GetMailboxMessages(recipientID string) ([]MailboxMessage, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := DB.Query(`SELECT id, msg_hash, sender_pubkey, payload FROM mailbox WHERE recipient_id = ? ORDER BY timestamp ASC`, recipientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []MailboxMessage
	for rows.Next() {
		var msg MailboxMessage
		if err := rows.Scan(&msg.ID, &msg.MsgHash, &msg.SenderPubkey, &msg.Payload); err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

// ClearMailboxMessages deletes messages after they've been delivered
func ClearMailboxMessages(recipientID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := DB.Exec(`DELETE FROM mailbox WHERE recipient_id = ?`, recipientID)
	return err
}

// GetMailboxUsage returns the total size of payloads in the mailbox table
func GetMailboxUsage() (int64, error) {
	var totalSize int64
	err := DB.QueryRow("SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM mailbox").Scan(&totalSize)
	return totalSize, err
}

// EvictOldestMessages deletes messages from the mailbox until the total size is below the target
func EvictOldestMessages(targetUsage int64) error {
	for {
		current, err := GetMailboxUsage()
		if err != nil { return err }
		if current <= targetUsage { break }

		// Delete the single oldest message
		_, err = DB.Exec("DELETE FROM mailbox WHERE id = (SELECT id FROM mailbox ORDER BY timestamp ASC LIMIT 1)")
		if err != nil { return err }
		fmt.Printf("[Storage] Evicted 1 old message to free up space (Current usage: %d bytes)\n", current)
	}
	return nil
}

// SaveSession persists the Double Ratchet session state for a peer
func SaveSession(peerID, remoteIdentityKey, rootKey, sendChainKey, recvChainKey, remoteRatchetPub, localRatchetPriv, localRatchetPub string, n, m, pn uint32) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec(`INSERT OR REPLACE INTO sessions 
		(peer_id, remote_identity_key, root_key, send_chain_key, recv_chain_key, remote_ratchet_pubkey, local_ratchet_privkey, local_ratchet_pubkey, n, m, pn, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		peerID, remoteIdentityKey, rootKey, sendChainKey, recvChainKey, remoteRatchetPub, localRatchetPriv, localRatchetPub, n, m, pn)
	return err
}

// LoadSession retrieves the Double Ratchet session state for a peer
func LoadSession(peerID string) (remoteIdentityKey, rootKey, sendChainKey, recvChainKey, remoteRatchetPub, localRatchetPriv, localRatchetPub string, n, m, pn uint32, err error) {
	if DB == nil { return "", "", "", "", "", "", "", 0, 0, 0, fmt.Errorf("database not initialized") }
	row := DB.QueryRow(`SELECT remote_identity_key, root_key, send_chain_key, recv_chain_key, remote_ratchet_pubkey, local_ratchet_privkey, local_ratchet_pubkey, n, m, pn FROM sessions WHERE peer_id = ?`, peerID)
	err = row.Scan(&remoteIdentityKey, &rootKey, &sendChainKey, &recvChainKey, &remoteRatchetPub, &localRatchetPriv, &localRatchetPub, &n, &m, &pn)
	return
}

// SaveSkippedKey stores a message key for an out-of-order message
func SaveSkippedKey(peerID string, counter uint32, key []byte) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec(`INSERT OR REPLACE INTO skipped_keys (peer_id, counter, msg_key) VALUES (?, ?, ?)`,
		peerID, counter, base64.StdEncoding.EncodeToString(key))
	return err
}

// GetSkippedKey retrieves and DELETES a message key for an out-of-order message
func GetSkippedKey(peerID string, counter uint32) ([]byte, error) {
	if DB == nil { return nil, fmt.Errorf("database not initialized") }
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
// because old epoch keys are permanently invalid and would cause "cipher: message authentication failed".
func ClearSkippedKeys(peerID string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec(`DELETE FROM skipped_keys WHERE peer_id = ?`, peerID)
	return err
}

// SaveAlias persists an alias record to the database
func SaveAlias(aliasHash, aliasName, peerID string, pubkeyBytes []byte) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec(`INSERT OR REPLACE INTO alias_store (alias_hash, alias_name, peer_id, pubkey_bytes, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		aliasHash, aliasName, peerID, pubkeyBytes)
	return err
}

// LoadAlias retrieves an alias record from the database
func LoadAlias(aliasHash string) (aliasName, peerID string, pubkeyBytes []byte, err error) {
	if DB == nil { return "", "", nil, fmt.Errorf("database not initialized") }
	row := DB.QueryRow(`SELECT alias_name, peer_id, pubkey_bytes FROM alias_store WHERE alias_hash = ?`, aliasHash)
	err = row.Scan(&aliasName, &peerID, &pubkeyBytes)
	return
}

// FindAliasByPeerID looks up the registered alias name for a given peer ID.
func FindAliasByPeerID(peerID string) (string, error) {
	if DB == nil { return "", fmt.Errorf("database not initialized") }
	var aliasName string
	row := DB.QueryRow(`SELECT alias_name FROM alias_store WHERE peer_id = ? LIMIT 1`, peerID)
	err := row.Scan(&aliasName)
	return aliasName, err
}

// DeleteAliasByPubkey removes an old alias when a user changes their name
func DeleteAliasByHash(aliasHash string) error {
	if DB == nil { return nil }
	_, err := DB.Exec(`DELETE FROM alias_store WHERE alias_hash = ?`, aliasHash)
	return err
}

// TrackBlock records when a block was added for later GC
func TrackBlock(cidStr string) error {
	if DB == nil { return nil }
	_, err := DB.Exec(`INSERT OR IGNORE INTO block_metadata (cid) VALUES (?)`, cidStr)
	return err
}

// GetExpiredBlocks finds CIDs older than the specified days
func GetExpiredBlocks(days int) ([]string, error) {
	if DB == nil { return nil, nil }
	rows, err := DB.Query(`SELECT cid FROM block_metadata WHERE timestamp < datetime('now', '-' || ? || ' days')`, days)
	if err != nil { return nil, err }
	defer rows.Close()

	var cids []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err == nil {
			cids = append(cids, c)
		}
	}
	return cids, nil
}

// CleanupExpiredMessages removes messages from the mailbox that have passed their expires_at time
func CleanupExpiredMessages() error {
	if DB == nil { return nil }
	res, err := DB.Exec("DELETE FROM mailbox WHERE expires_at < datetime('now')")
	if err == nil {
		count, _ := res.RowsAffected()
		if count > 0 {
			fmt.Printf("[Storage] Cleaned up %d expired messages from mailbox\n", count)
		}
	}
	return err
}

// RemoveBlockMetadata removes CID from tracking
func RemoveBlockMetadata(cidStr string) error {
	if DB == nil { return nil }
	_, err := DB.Exec(`DELETE FROM block_metadata WHERE cid = ?`, cidStr)
	return err
}

// --- Group Messaging Helpers ---

func SaveGroupLocalKey(groupID string, key []byte) error {
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_local_keys (group_id, sender_key) VALUES (?, ?)`,
		groupID, base64.StdEncoding.EncodeToString(key))
	return err
}

func GetGroupLocalKey(groupID string) ([]byte, error) {
	var keyStr string
	err := DB.QueryRow(`SELECT sender_key FROM group_local_keys WHERE group_id = ?`, groupID).Scan(&keyStr)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(keyStr)
}

func SaveGroupSenderKey(groupID, senderID string, key []byte) error {
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_sender_keys (group_id, sender_id, sender_key) VALUES (?, ?, ?)`,
		groupID, senderID, base64.StdEncoding.EncodeToString(key))
	return err
}

func GetGroupSenderKey(groupID, senderID string) ([]byte, error) {
	var keyStr string
	err := DB.QueryRow(`SELECT sender_key FROM group_sender_keys WHERE group_id = ? AND sender_id = ?`,
		groupID, senderID).Scan(&keyStr)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(keyStr)
}

func AddGroupMember(groupID, peerID string) error {
	_, err := DB.Exec(`INSERT OR IGNORE INTO group_members (group_id, peer_id) VALUES (?, ?)`,
		groupID, peerID)
	return err
}

func GetGroupMembers(groupID string) ([]string, error) {
	rows, err := DB.Query(`SELECT peer_id FROM group_members WHERE group_id = ?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var pid string
		if err := rows.Scan(&pid); err == nil {
			members = append(members, pid)
		}
	}
	return members, nil
}

func GetGroupMemberships(peerID string) ([]string, error) {
	rows, err := DB.Query(`SELECT group_id FROM group_members WHERE peer_id = ?`, peerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err == nil {
			groups = append(groups, gid)
		}
	}
	return groups, nil
}

