package storage

import "fmt"

// MailboxMessage represents a pending offline message stored on a relay.
type MailboxMessage struct {
	ID           int    `json:"id"`
	MsgHash      string `json:"msg_hash"`
	RecipientID  string `json:"recipient_id"`
	SenderPubkey string `json:"sender_pubkey"`
	Payload      string `json:"payload"`
	Timestamp    string `json:"timestamp"`
}

// SaveMailboxMessage stores an encrypted offline message for a recipient.
func SaveMailboxMessage(msgHash, recipientID, senderPubkey, payload string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	query := `INSERT OR IGNORE INTO mailbox (msg_hash, recipient_id, sender_pubkey, payload) VALUES (?, ?, ?, ?)`
	_, err := DB.Exec(query, msgHash, recipientID, senderPubkey, payload)
	return err
}

// DeleteMailboxMessageByHash removes a message from the cluster by its unique hash.
func DeleteMailboxMessageByHash(msgHash string) error {
	if DB == nil {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM mailbox WHERE msg_hash = ?`, msgHash)
	return err
}

// GetMailboxMessages retrieves all pending messages for a recipient.
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

// ClearMailboxMessages deletes messages after they've been delivered.
func ClearMailboxMessages(recipientID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`DELETE FROM mailbox WHERE recipient_id = ?`, recipientID)
	return err
}

// GetMailboxUsage returns the total size of payloads in the mailbox table.
func GetMailboxUsage() (int64, error) {
	var totalSize int64
	err := DB.QueryRow("SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM mailbox").Scan(&totalSize)
	return totalSize, err
}

// EvictOldestMessages deletes messages from the mailbox until the total size is below the target.
func EvictOldestMessages(targetUsage int64) error {
	for {
		current, err := GetMailboxUsage()
		if err != nil {
			return err
		}
		if current <= targetUsage {
			break
		}
		_, err = DB.Exec("DELETE FROM mailbox WHERE id = (SELECT id FROM mailbox ORDER BY timestamp ASC LIMIT 1)")
		if err != nil {
			return err
		}
	}
	return nil
}

// CleanupExpiredMessages removes messages from the mailbox that have passed their expires_at time.
func CleanupExpiredMessages() error {
	if DB == nil {
		return nil
	}
	_, err := DB.Exec("DELETE FROM mailbox WHERE expires_at < datetime('now')")
	return err
}

// SaveProcessedMailboxMessage stores a message hash that has been successfully processed.
func SaveProcessedMailboxMessage(msgHash string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR IGNORE INTO processed_mailbox_messages (msg_hash) VALUES (?)`, msgHash)
	return err
}

// IsMailboxMessageProcessed checks if a message hash has already been successfully processed.
func IsMailboxMessageProcessed(msgHash string) bool {
	if DB == nil {
		return false
	}
	var exists int
	err := DB.QueryRow(`SELECT 1 FROM processed_mailbox_messages WHERE msg_hash = ?`, msgHash).Scan(&exists)
	return err == nil
}

// DeleteProcessedMailboxMessage removes a message hash (e.g. if decryption failed).
func DeleteProcessedMailboxMessage(msgHash string) error {
	if DB == nil {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM processed_mailbox_messages WHERE msg_hash = ?`, msgHash)
	return err
}

// SaveProcessedEnvelope persists an envelope hash that has been successfully decrypted/processed.
func SaveProcessedEnvelope(envHash string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR IGNORE INTO processed_envelopes (env_hash) VALUES (?)`, envHash)
	return err
}

// IsEnvelopeProcessed checks if an envelope hash has already been successfully processed.
func IsEnvelopeProcessed(envHash string) bool {
	if DB == nil {
		return false
	}
	var exists int
	err := DB.QueryRow(`SELECT 1 FROM processed_envelopes WHERE env_hash = ?`, envHash).Scan(&exists)
	return err == nil && exists == 1
}
