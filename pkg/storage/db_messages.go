package storage

import "fmt"

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

// GetMessageByHash retrieves a message by its hash.
// Returns (senderID, recipientID, content, msgID, msgType, error).
func GetMessageByHash(msgHash string) (string, string, string, string, string, error) {
	if DB == nil {
		return "", "", "", "", "", fmt.Errorf("database not initialized")
	}
	var senderID, recipientID, content, msgID, msgType string
	err := DB.QueryRow(`SELECT sender_id, recipient_id, content, COALESCE(msg_id, ''), COALESCE(msg_type, '') FROM messages WHERE msg_hash = ?`, msgHash).Scan(&senderID, &recipientID, &content, &msgID, &msgType)
	return senderID, recipientID, content, msgID, msgType, err
}
