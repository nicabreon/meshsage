package storage

// TrackBlock records when a block was added for later GC.
func TrackBlock(cidStr string) error {
	if DB == nil {
		return nil
	}
	_, err := DB.Exec(`INSERT OR IGNORE INTO block_metadata (cid) VALUES (?)`, cidStr)
	return err
}

// GetExpiredBlocks finds CIDs older than the specified days.
func GetExpiredBlocks(days int) ([]string, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(`SELECT cid FROM block_metadata WHERE timestamp < datetime('now', '-' || ? || ' days')`, days)
	if err != nil {
		return nil, err
	}
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

// RemoveBlockMetadata removes CID from tracking.
func RemoveBlockMetadata(cidStr string) error {
	if DB == nil {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM block_metadata WHERE cid = ?`, cidStr)
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
