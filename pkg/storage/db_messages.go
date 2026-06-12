package storage

import (
	"database/sql"
	"fmt"
)

// ChatMessageResult represents a message returned for UI rendering
type ChatMessageResult struct {
	ID          int    `json:"id"`
	SenderID    string `json:"sender_id"`
	RecipientID string `json:"recipient_id"`
	Content     string `json:"content"`
	MsgID       string `json:"msg_id"`
	MsgHash     string `json:"msg_hash"`
	MsgType     string `json:"msg_type"`
	Status      string `json:"status"`
	Timestamp   string `json:"timestamp"`
}

// ChatMetadata represents metadata about a chat room
type ChatMetadata struct {
	RoomID      string            `json:"room_id"`
	IsGroup     bool              `json:"is_group"`
	UnreadCount int               `json:"unread_count"`
	LastMessage ChatMessageResult `json:"last_message"`
}

// SaveMessage stores a message in the local database with a delivery/read status.
func SaveMessage(senderID, recipientID, content, msgID, msgHash, msgType, status string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if status == "" {
		status = "unread"
	}
	query := `INSERT INTO messages (sender_id, recipient_id, content, msg_id, msg_hash, msg_type, status) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := DB.Exec(query, senderID, recipientID, content, msgID, msgHash, msgType, status)
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

// UpdateMessageStatus updates the delivery or read status of a message based on ID or hash.
func UpdateMessageStatus(refID string, status string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	query := `UPDATE messages SET status = ? WHERE msg_id = ? OR msg_hash = ?`
	_, err := DB.Exec(query, status, refID, refID)
	if err != nil {
		return fmt.Errorf("failed to update message status: %w", err)
	}
	return nil
}

// MarkChatAsRead marks all incoming messages in a chat room as read.
func MarkChatAsRead(myID, targetID string, isGroup bool) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	var err error
	if isGroup {
		query := `UPDATE messages SET status = 'read' WHERE recipient_id = ? AND status != 'read'`
		_, err = DB.Exec(query, targetID)
	} else {
		query := `UPDATE messages SET status = 'read' WHERE sender_id = ? AND recipient_id = ? AND status != 'read'`
		_, err = DB.Exec(query, targetID, myID)
	}
	if err != nil {
		return fmt.Errorf("failed to mark chat as read: %w", err)
	}
	return nil
}

// GetChatMessages retrieves paginated messages for a chat room.
func GetChatMessages(myID, targetID string, isGroup bool, limit, offset int) ([]ChatMessageResult, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	var query string
	var args []interface{}

	if isGroup {
		query = `SELECT id, sender_id, recipient_id, content, COALESCE(msg_id, ''), COALESCE(msg_hash, ''), COALESCE(msg_type, ''), COALESCE(status, 'unread'), timestamp 
		         FROM messages 
		         WHERE recipient_id = ? 
		         ORDER BY timestamp DESC, id DESC`
		args = []interface{}{targetID}
	} else {
		query = `SELECT id, sender_id, recipient_id, content, COALESCE(msg_id, ''), COALESCE(msg_hash, ''), COALESCE(msg_type, ''), COALESCE(status, 'unread'), timestamp 
		         FROM messages 
		         WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) 
		         ORDER BY timestamp DESC, id DESC`
		args = []interface{}{myID, targetID, targetID, myID}
	}

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
		if offset > 0 {
			query += " OFFSET ?"
			args = append(args, offset)
		}
	}

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer rows.Close()

	var results []ChatMessageResult
	for rows.Next() {
		var r ChatMessageResult
		err := rows.Scan(&r.ID, &r.SenderID, &r.RecipientID, &r.Content, &r.MsgID, &r.MsgHash, &r.MsgType, &r.Status, &r.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message row: %w", err)
		}
		results = append(results, r)
	}
	return results, nil
}

// GetChatMetadataList retrieves metadata about all active chat rooms.
func GetChatMetadataList(myID string) ([]ChatMetadata, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// 1. Get unique room IDs and types
	roomQuery := `SELECT DISTINCT 
	                CASE WHEN msg_type = 'group' THEN recipient_id
	                     WHEN sender_id = ? THEN recipient_id
	                     ELSE sender_id 
	                END as room_id,
	                CASE WHEN msg_type = 'group' THEN 1 ELSE 0 END as is_group
	              FROM messages`
	
	rows, err := DB.Query(roomQuery, myID)
	if err != nil {
		return nil, fmt.Errorf("failed to query rooms: %w", err)
	}
	defer rows.Close()

	type room struct {
		id      string
		isGroup bool
	}
	var rooms []room
	for rows.Next() {
		var r room
		var isGroup int
		if err := rows.Scan(&r.id, &isGroup); err != nil {
			return nil, err
		}
		r.isGroup = (isGroup != 0)
		if r.id != "" {
			rooms = append(rooms, r)
		}
	}

	var metadataList []ChatMetadata
	for _, rm := range rooms {
		// 2. Query unread count
		var unreadCount int
		var unreadErr error
		if rm.isGroup {
			unreadErr = DB.QueryRow("SELECT COUNT(1) FROM messages WHERE recipient_id = ? AND sender_id != ? AND status = 'unread'", rm.id, myID).Scan(&unreadCount)
		} else {
			unreadErr = DB.QueryRow("SELECT COUNT(1) FROM messages WHERE sender_id = ? AND recipient_id = ? AND status = 'unread'", rm.id, myID).Scan(&unreadCount)
		}
		if unreadErr != nil {
			unreadCount = 0
		}

		// 3. Query last message
		var lastMsg ChatMessageResult
		var lastQuery string
		var lastArgs []interface{}
		if rm.isGroup {
			lastQuery = `SELECT id, sender_id, recipient_id, content, COALESCE(msg_id, ''), COALESCE(msg_hash, ''), COALESCE(msg_type, ''), COALESCE(status, 'unread'), timestamp 
			             FROM messages 
			             WHERE recipient_id = ? 
			             ORDER BY timestamp DESC, id DESC LIMIT 1`
			lastArgs = []interface{}{rm.id}
		} else {
			lastQuery = `SELECT id, sender_id, recipient_id, content, COALESCE(msg_id, ''), COALESCE(msg_hash, ''), COALESCE(msg_type, ''), COALESCE(status, 'unread'), timestamp 
			             FROM messages 
			             WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) 
			             ORDER BY timestamp DESC, id DESC LIMIT 1`
			lastArgs = []interface{}{myID, rm.id, rm.id, myID}
		}

		errLast := DB.QueryRow(lastQuery, lastArgs...).Scan(
			&lastMsg.ID, &lastMsg.SenderID, &lastMsg.RecipientID, &lastMsg.Content,
			&lastMsg.MsgID, &lastMsg.MsgHash, &lastMsg.MsgType, &lastMsg.Status, &lastMsg.Timestamp,
		)
		if errLast != nil && errLast != sql.ErrNoRows {
			// Skip setting last message if error
			continue
		}

		metadataList = append(metadataList, ChatMetadata{
			RoomID:      rm.id,
			IsGroup:     rm.isGroup,
			UnreadCount: unreadCount,
			LastMessage: lastMsg,
		})
	}

	return metadataList, nil
}

// DeleteMessageByID deletes a message by its ID.
func DeleteMessageByID(msgID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`DELETE FROM messages WHERE msg_id = ?`, msgID)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}
	return nil
}

// ClearChatHistory deletes all messages for a room.
func ClearChatHistory(myID, targetID string, isGroup bool) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	var err error
	if isGroup {
		_, err = DB.Exec(`DELETE FROM messages WHERE recipient_id = ?`, targetID)
	} else {
		_, err = DB.Exec(`DELETE FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)`, myID, targetID, targetID, myID)
	}
	if err != nil {
		return fmt.Errorf("failed to clear chat history: %w", err)
	}
	return nil
}
