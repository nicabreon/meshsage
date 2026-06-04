package storage

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/nicabreon/meshsage/pkg/crypto"
	_ "modernc.org/sqlite"
)

var DB *sql.DB

// InitDatabase initializes the local SQLite database.
func InitDatabase(dbPath string) error {
	if DB != nil {
		oldDB := DB
		DB = nil
		go func() {
			_ = oldDB.Close()
		}()
	}
	var err error
	// modernc.org/sqlite uses the "sqlite" driver name
	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Single writer: required for modernc/sqlite to avoid SQLITE_BUSY
	DB.SetMaxOpenConns(1)

	// Critical: set busy_timeout FIRST before any other PRAGMA.
	// We use 3 seconds (3000ms) to avoid long hangs on startup if there is lock contention.
	DB.Exec("PRAGMA busy_timeout=3000;")
	DB.Exec("PRAGMA journal_mode=WAL;")
	DB.Exec("PRAGMA synchronous=NORMAL;")
	DB.Exec("PRAGMA cache_size=-8000;")   // 8MB page cache
	// Force checkpoint: clears any stale WAL file from a previous crashed session.
	// Safe to call even if WAL is clean — it's a no-op in that case.
	DB.Exec("PRAGMA wal_checkpoint(TRUNCATE);")

	// Perform SQLite integrity check on startup to verify database file health (after busy_timeout is set)
	var integrityResult string
	err = DB.QueryRow("PRAGMA integrity_check(1);").Scan(&integrityResult)
	if err != nil || integrityResult != "ok" {
		return fmt.Errorf("database integrity check failed: %s (err: %v)", integrityResult, err)
	}

	// Create messages table if it doesn't exist (For local history)
	query := `
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender_id TEXT NOT NULL,
		recipient_id TEXT NOT NULL,
		content TEXT NOT NULL,
		msg_id TEXT,
		msg_hash TEXT,
		msg_type TEXT,
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

	-- 7b. Group Sender Keys History (for decrypting out-of-order or offline messages)
	CREATE TABLE IF NOT EXISTS group_sender_key_history (
		group_id TEXT,
		sender_id TEXT,
		sender_key TEXT,
		saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (group_id, sender_id, sender_key)
	);

	-- 8. Local Group Keys (Our own keys that we share)
	CREATE TABLE IF NOT EXISTS group_local_keys (
		group_id TEXT PRIMARY KEY,
		sender_key TEXT NOT NULL
	);

	-- 8b. Local Group Keys History
	CREATE TABLE IF NOT EXISTS group_local_key_history (
		group_id TEXT,
		sender_key TEXT,
		saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (group_id, sender_key)
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
	);

	-- Create group_metadata table for cryptographic group chat ownership
	CREATE TABLE IF NOT EXISTS group_metadata (
		group_id TEXT PRIMARY KEY,
		group_alias TEXT UNIQUE NOT NULL,
		creator_id TEXT NOT NULL,
		group_type TEXT CHECK(group_type IN ('SECURE', 'UNSECURE')) NOT NULL,
		created_at INTEGER NOT NULL,
		signature TEXT NOT NULL
	);

	-- Create group_members_v2 table for proper member role management
	CREATE TABLE IF NOT EXISTS group_members_v2 (
		group_id TEXT,
		peer_id TEXT,
		role TEXT CHECK(role IN ('CREATOR', 'MEMBER')) DEFAULT 'MEMBER',
		joined_at INTEGER NOT NULL,
		PRIMARY KEY (group_id, peer_id)
	);

	-- Create zkp_members table for ZKP public keys of active members
	CREATE TABLE IF NOT EXISTS zkp_members (
		peer_id TEXT PRIMARY KEY,
		zkp_x TEXT NOT NULL,
		zkp_y TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- 10. Network stats (cumulative data usage, persisted across sessions)
	CREATE TABLE IF NOT EXISTS network_stats (
		id INTEGER PRIMARY KEY CHECK(id = 1),
		total_sent INTEGER NOT NULL DEFAULT 0,
		total_recv INTEGER NOT NULL DEFAULT 0,
		msg_sent INTEGER NOT NULL DEFAULT 0,
		msg_recv INTEGER NOT NULL DEFAULT 0,
		handshakes INTEGER NOT NULL DEFAULT 0,
		file_sent INTEGER NOT NULL DEFAULT 0,
		file_recv INTEGER NOT NULL DEFAULT 0,
		last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	-- 11. Persistent mailbox deduplication cache (hashes of successfully decrypted offline messages)
	CREATE TABLE IF NOT EXISTS processed_mailbox_messages (
		msg_hash TEXT PRIMARY KEY,
		processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Run migrations to add missing columns to messages table if they do not exist
	_, _ = DB.Exec("ALTER TABLE messages ADD COLUMN msg_id TEXT;")
	_, _ = DB.Exec("ALTER TABLE messages ADD COLUMN msg_hash TEXT;")
	_, _ = DB.Exec("ALTER TABLE messages ADD COLUMN msg_type TEXT;")

	// Database versioning & migration runner
	var currentVersion int
	err = DB.QueryRow("PRAGMA user_version;").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to query database version: %w", err)
	}

	if currentVersion < 1 {
		// Version 1: Initial schema with group_local_key_history table
		// (Already created by IF NOT EXISTS query above)
		_, err = DB.Exec("PRAGMA user_version = 1;")
		if err != nil {
			return fmt.Errorf("failed to update user_version to 1: %w", err)
		}
		currentVersion = 1
	}

	// Future migrations go here:
	// if currentVersion < 2 { ... }

	// Performance & Concurrency Tuning (applied again after schema creation)
	// These are idempotent and safe to call multiple times.
	DB.Exec("PRAGMA journal_mode = WAL;")
	DB.Exec("PRAGMA synchronous = NORMAL;")
	DB.Exec("PRAGMA busy_timeout = 10000;")
	DB.Exec("PRAGMA wal_checkpoint(PASSIVE);")
	DB.SetMaxOpenConns(1)

	return nil
}

// EnsureColumn checks if a column exists in a table, and adds it if it is missing.
// This is extremely useful for running ALTER TABLE commands dynamically during startup.
func EnsureColumn(tableName, columnName, columnDefinition string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	// Query column info from SQLite table_info
	rows, err := DB.Query(fmt.Sprintf("PRAGMA table_info(%s);", tableName))
	if err != nil {
		return err
	}
	defer rows.Close()

	exists := false
	for rows.Next() {
		var cid int
		var name, dType string
		var notNull, pk int
		var dfltVal interface{}
		if err := rows.Scan(&cid, &name, &dType, &notNull, &dfltVal, &pk); err != nil {
			return err
		}
		if strings.ToLower(name) == strings.ToLower(columnName) {
			exists = true
			break
		}
	}

	if !exists {
		// Column is missing, add it dynamically
		alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s;", tableName, columnName, columnDefinition)
		_, err = DB.Exec(alterQuery)
		if err != nil {
			return fmt.Errorf("failed to add column %s to %s: %w", columnName, tableName, err)
		}
	}
	return nil
}


// SavePreKey stores a signed one-time public key in the relay or local DB
func SavePreKey(ownerID, keyID, pubKey, privKey, sig string) error {
	_, err := DB.Exec("INSERT OR REPLACE INTO prekeys (owner_id, key_id, public_key, private_key, signature) VALUES (?, ?, ?, ?, ?)",
		ownerID, keyID, pubKey, privKey, sig)
	return err
}

// DeletePreKeysByOwner deletes all pre-keys associated with an owner ID
func DeletePreKeysByOwner(ownerID string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec("DELETE FROM prekeys WHERE owner_id = ?", ownerID)
	return err
}

// DeletePublicPreKeysByOwner deletes only pre-keys that have NO private key stored
// (i.e. keys that belong to other users cached on this relay node).
// This preserves the local node's own private keys during PREKEY_CLEAR cluster events.
func DeletePublicPreKeysByOwner(ownerID string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec("DELETE FROM prekeys WHERE owner_id = ? AND (private_key IS NULL OR private_key = '')", ownerID)
	return err
}

// DeletePreKeyByID deletes a specific pre-key by its unique key ID
func DeletePreKeyByID(keyID string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec("DELETE FROM prekeys WHERE key_id = ?", keyID)
	return err
}

// DeletePublicPreKeyByID deletes a pre-key by ID only if its private_key column is NULL or empty string.
func DeletePublicPreKeyByID(keyID string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec("DELETE FROM prekeys WHERE key_id = ? AND (private_key IS NULL OR private_key = '')", keyID)
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
func SaveMessage(senderID, recipientID, content, msgID, msgHash, msgType string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	query := `INSERT INTO messages (sender_id, recipient_id, content, msg_id, msg_hash, msg_type) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := DB.Exec(query, senderID, recipientID, content, msgID, msgHash, msgType)
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

// SaveProcessedMailboxMessage stores a message hash that has been successfully processed
func SaveProcessedMailboxMessage(msgHash string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR IGNORE INTO processed_mailbox_messages (msg_hash) VALUES (?)`, msgHash)
	return err
}

// IsMailboxMessageProcessed checks if a message hash has already been successfully processed
func IsMailboxMessageProcessed(msgHash string) bool {
	if DB == nil {
		return false
	}
	var exists int
	err := DB.QueryRow(`SELECT 1 FROM processed_mailbox_messages WHERE msg_hash = ?`, msgHash).Scan(&exists)
	return err == nil
}

// DeleteProcessedMailboxMessage removes a message hash (e.g. if decryption failed)
func DeleteProcessedMailboxMessage(msgHash string) error {
	if DB == nil {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM processed_mailbox_messages WHERE msg_hash = ?`, msgHash)
	return err
}

// GetMessageByHash retrieves a message by its hash
func GetMessageByHash(msgHash string) (string, string, string, string, string, error) {
	if DB == nil {
		return "", "", "", "", "", fmt.Errorf("database not initialized")
	}
	var senderID, recipientID, content, msgID, msgType string
	err := DB.QueryRow(`SELECT sender_id, recipient_id, content, COALESCE(msg_id, ''), COALESCE(msg_type, '') FROM messages WHERE msg_hash = ?`, msgHash).Scan(&senderID, &recipientID, &content, &msgID, &msgType)
	return senderID, recipientID, content, msgID, msgType, err
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

// DeleteSession removes the Double Ratchet session for a peer
func DeleteSession(peerID string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec(`DELETE FROM sessions WHERE peer_id = ?`, peerID)
	if err != nil {
		return err
	}
	// Also clear skipped keys
	_ = ClearSkippedKeys(peerID)
	return nil
}

// HasSession returns true if a Double Ratchet session exists for the given peerID.
// Used for proactive session warm-up: when a known peer reconnects, we can
// immediately probe them to ensure the bidirectional DR session is healthy
// before the user sends the first message.
func HasSession(peerID string) bool {
	if DB == nil { return false }
	var count int
	err := DB.QueryRow(`SELECT COUNT(1) FROM sessions WHERE peer_id = ? AND root_key != ''`, peerID).Scan(&count)
	return err == nil && count > 0
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
// It excludes aliases that are registered as group aliases, and returns the most recently updated one.
func FindAliasByPeerID(peerID string) (string, error) {
	if DB == nil { return "", fmt.Errorf("database not initialized") }
	var aliasName string
	row := DB.QueryRow(`
		SELECT alias_name FROM alias_store 
		WHERE peer_id = ? 
		  AND alias_name NOT IN (SELECT group_alias FROM group_metadata)
		ORDER BY updated_at DESC
		LIMIT 1`, peerID)
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
	keyB64 := base64.StdEncoding.EncodeToString(key)
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_local_keys (group_id, sender_key) VALUES (?, ?)`,
		groupID, keyB64)
	if err != nil {
		return err
	}

	// Add to history
	_, _ = DB.Exec(`INSERT OR IGNORE INTO group_local_key_history (group_id, sender_key) VALUES (?, ?)`,
		groupID, keyB64)

	// Prune history to keep only the last 20 keys
	_, _ = DB.Exec(`DELETE FROM group_local_key_history WHERE group_id = ? AND rowid NOT IN (
		SELECT rowid FROM group_local_key_history WHERE group_id = ? ORDER BY rowid DESC LIMIT 20
	)`, groupID, groupID)

	return nil
}

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


func GetGroupLocalKey(groupID string) ([]byte, error) {
	var keyStr string
	err := DB.QueryRow(`SELECT sender_key FROM group_local_keys WHERE group_id = ?`, groupID).Scan(&keyStr)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(keyStr)
}

func SaveGroupSenderKey(groupID, senderID string, key []byte) error {
	keyB64 := base64.StdEncoding.EncodeToString(key)
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_sender_keys (group_id, sender_id, sender_key) VALUES (?, ?, ?)`,
		groupID, senderID, keyB64)
	if err != nil {
		return err
	}

	// Add to history
	_, _ = DB.Exec(`INSERT OR IGNORE INTO group_sender_key_history (group_id, sender_id, sender_key) VALUES (?, ?, ?)`,
		groupID, senderID, keyB64)

	// Prune history to keep only the last 20 keys
	_, _ = DB.Exec(`DELETE FROM group_sender_key_history WHERE group_id = ? AND sender_id = ? AND rowid NOT IN (
		SELECT rowid FROM group_sender_key_history WHERE group_id = ? AND sender_id = ? ORDER BY rowid DESC LIMIT 20
	)`, groupID, senderID, groupID, senderID)

	return nil
}

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

// GroupMetadata represents the persistent metadata of a group
type GroupMetadata struct {
	GroupID    string `json:"group_id"`
	GroupAlias string `json:"group_alias"`
	CreatorID  string `json:"creator_id"`
	GroupType  string `json:"group_type"`
	CreatedAt  int64  `json:"created_at"`
	Signature  string `json:"signature"`
}

// SaveGroupMetadata persists a group's metadata
func SaveGroupMetadata(meta GroupMetadata) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_metadata 
		(group_id, group_alias, creator_id, group_type, created_at, signature) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.CreatedAt, meta.Signature)
	return err
}

// LoadGroupMetadata retrieves a group's metadata by its ID or Alias
func LoadGroupMetadata(idOrAlias string) (meta GroupMetadata, err error) {
	if DB == nil { return meta, fmt.Errorf("database not initialized") }
	
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

// GetGroupType returns the group type ("SECURE" or "UNSECURE")
func GetGroupType(groupID string) (string, error) {
	if DB == nil { return "", fmt.Errorf("database not initialized") }
	var gtype string
	err := DB.QueryRow("SELECT group_type FROM group_metadata WHERE group_id = ?", groupID).Scan(&gtype)
	return gtype, err
}

// AddGroupMemberV2 inserts or updates a group member with their role
func AddGroupMemberV2(groupID, peerID, role string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec(`INSERT OR REPLACE INTO group_members_v2 
		(group_id, peer_id, role, joined_at) VALUES (?, ?, ?, ?)`,
		groupID, peerID, role, time.Now().Unix())
	return err
}

// RemoveGroupMemberV2 deletes a member from the group
func RemoveGroupMemberV2(groupID, peerID string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec(`DELETE FROM group_members_v2 WHERE group_id = ? AND peer_id = ?`, groupID, peerID)
	return err
}

// GroupMemberV2 represents a member record with role
type GroupMemberV2 struct {
	PeerID string
	Role   string
}

// GetGroupMembersV2 retrieves all members and their roles in a group
func GetGroupMembersV2(groupID string) ([]GroupMemberV2, error) {
	if DB == nil { return nil, fmt.Errorf("database not initialized") }
	rows, err := DB.Query(`SELECT peer_id, role FROM group_members_v2 WHERE group_id = ? ORDER BY joined_at ASC`, groupID)
	if err != nil { return nil, err }
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

// DeleteGroupMetadata removes a group completely from database (disband)
func DeleteGroupMetadata(groupID string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err1 := DB.Exec(`DELETE FROM group_metadata WHERE group_id = ?`, groupID)
	_, err2 := DB.Exec(`DELETE FROM group_members_v2 WHERE group_id = ?`, groupID)
	if err1 != nil { return err1 }
	return err2
}

// SaveZKPMember stores a ZKP public key for a member
func SaveZKPMember(peerID string, xB64 string, yB64 string) error {
	if DB == nil { return fmt.Errorf("database not initialized") }
	_, err := DB.Exec("INSERT OR REPLACE INTO zkp_members (peer_id, zkp_x, zkp_y) VALUES (?, ?, ?)", peerID, xB64, yB64)
	return err
}

// GetZKPMembers retrieves all active ZKP member public keys
func GetZKPMembers() (map[string]crypto.PubKeyPoint, error) {
	if DB == nil { return nil, fmt.Errorf("database not initialized") }
	rows, err := DB.Query("SELECT peer_id, zkp_x, zkp_y FROM zkp_members")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	members := make(map[string]crypto.PubKeyPoint)
	for rows.Next() {
		var peerID, xB64, yB64 string
		if err := rows.Scan(&peerID, &xB64, &yB64); err != nil {
			return nil, err
		}
		xBytes, _ := base64.StdEncoding.DecodeString(xB64)
		yBytes, _ := base64.StdEncoding.DecodeString(yB64)
		members[peerID] = crypto.PubKeyPoint{
			X: new(big.Int).SetBytes(xBytes),
			Y: new(big.Int).SetBytes(yBytes),
		}
	}
	return members, nil
}

// CleanZKPMembersExceptOwner deletes all ZKP members except the specified owner ID
func CleanZKPMembersExceptOwner(ownerID string) error {
	_, err := DB.Exec(`DELETE FROM zkp_members WHERE peer_id != ?`, ownerID)
	return err
}

// LoadNetworkStats loads cumulative data usage counters from the database.
// Returns [totalSent, totalRecv, msgSent, msgRecv, handshakes, fileSent, fileRecv].
func LoadNetworkStats() ([7]int64, error) {
	var s [7]int64
	err := DB.QueryRow(`
		SELECT total_sent, total_recv, msg_sent, msg_recv, handshakes, file_sent, file_recv
		FROM network_stats WHERE id = 1`).Scan(
		&s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6])
	return s, err
}

// SaveNetworkStats persists cumulative data usage counters to the database.
func SaveNetworkStats(totalSent, totalRecv, msgSent, msgRecv, handshakes, fileSent, fileRecv int64) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO network_stats
			(id, total_sent, total_recv, msg_sent, msg_recv, handshakes, file_sent, file_recv, last_updated)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		totalSent, totalRecv, msgSent, msgRecv, handshakes, fileSent, fileRecv)
	return err
}
