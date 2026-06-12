package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// DB is the global SQLite database connection. All storage functions use this handle.
var DB *sql.DB

// DataDir is the directory where the database file and related data are stored.
var DataDir string

// InitDatabase initializes the local SQLite database, creates schema tables, and runs migrations.
func InitDatabase(dbPath string) error {
	DataDir = filepath.Dir(dbPath)
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
	DB.Exec("PRAGMA busy_timeout=3000;")
	DB.Exec("PRAGMA journal_mode=WAL;")
	DB.Exec("PRAGMA synchronous=NORMAL;")
	DB.Exec("PRAGMA cache_size=-8000;") // 8MB page cache
	// Force checkpoint: clears any stale WAL file from a previous crashed session.
	DB.Exec("PRAGMA wal_checkpoint(TRUNCATE);")

	// Perform SQLite integrity check on startup
	var integrityResult string
	err = DB.QueryRow("PRAGMA integrity_check(1);").Scan(&integrityResult)
	if err != nil || integrityResult != "ok" {
		return fmt.Errorf("database integrity check failed: %s (err: %v)", integrityResult, err)
	}

	query := `
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender_id TEXT NOT NULL,
		recipient_id TEXT NOT NULL,
		content TEXT NOT NULL,
		msg_id TEXT,
		msg_hash TEXT,
		msg_type TEXT,
		status TEXT DEFAULT 'unread',
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
		outbound_msgs_since_ratchet INTEGER DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Create skipped_keys_v2 table for out-of-order messages (isolated by ratchet epoch)
	CREATE TABLE IF NOT EXISTS skipped_keys_v2 (
		peer_id TEXT,
		ratchet_pub TEXT,
		counter INTEGER,
		msg_key TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (peer_id, ratchet_pub, counter)
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
	
	-- 11. Persistent mailbox deduplication cache
	CREATE TABLE IF NOT EXISTS processed_mailbox_messages (
		msg_hash TEXT PRIMARY KEY,
		processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	-- 12. Persistent envelope deduplication cache
	CREATE TABLE IF NOT EXISTS processed_envelopes (
		env_hash TEXT PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- 13. Persistent profile registry cache
	CREATE TABLE IF NOT EXISTS profile_store (
		peer_id TEXT PRIMARY KEY,
		display_name TEXT NOT NULL,
		avatar_cid TEXT DEFAULT "",
		avatar_key TEXT DEFAULT "",
		local_path TEXT DEFAULT "",
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Run migrations to add missing columns to messages table if they do not exist
	_, _ = DB.Exec("ALTER TABLE messages ADD COLUMN msg_id TEXT;")
	_, _ = DB.Exec("ALTER TABLE messages ADD COLUMN msg_hash TEXT;")
	_, _ = DB.Exec("ALTER TABLE messages ADD COLUMN msg_type TEXT;")
	_ = EnsureColumn("messages", "status", "TEXT DEFAULT 'unread'")
	_, _ = DB.Exec("ALTER TABLE sessions ADD COLUMN outbound_msgs_since_ratchet INTEGER DEFAULT 0;")

	// Database versioning & migration runner
	var currentVersion int
	err = DB.QueryRow("PRAGMA user_version;").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to query database version: %w", err)
	}

	if currentVersion < 1 {
		_, err = DB.Exec("PRAGMA user_version = 1;")
		if err != nil {
			return fmt.Errorf("failed to update user_version to 1: %w", err)
		}
		currentVersion = 1
	}

	// Future migrations go here:
	// if currentVersion < 2 { ... }

	// Performance & Concurrency Tuning (applied again after schema creation)
	DB.Exec("PRAGMA journal_mode = WAL;")
	DB.Exec("PRAGMA synchronous = NORMAL;")
	DB.Exec("PRAGMA busy_timeout = 10000;")
	DB.Exec("PRAGMA wal_checkpoint(PASSIVE);")
	DB.SetMaxOpenConns(1)

	return nil
}

// EnsureColumn checks if a column exists in a table, and adds it if it is missing.
func EnsureColumn(tableName, columnName, columnDefinition string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

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
		alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s;", tableName, columnName, columnDefinition)
		_, err = DB.Exec(alterQuery)
		if err != nil {
			return fmt.Errorf("failed to add column %s to %s: %w", columnName, tableName, err)
		}
	}
	return nil
}
