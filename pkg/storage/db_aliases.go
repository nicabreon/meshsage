package storage

import "fmt"

// SaveAlias persists an alias record to the database.
func SaveAlias(aliasHash, aliasName, peerID string, pubkeyBytes []byte) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR REPLACE INTO alias_store (alias_hash, alias_name, peer_id, pubkey_bytes, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		aliasHash, aliasName, peerID, pubkeyBytes)
	return err
}

// LoadAlias retrieves an alias record from the database.
func LoadAlias(aliasHash string) (aliasName, peerID string, pubkeyBytes []byte, err error) {
	if DB == nil {
		return "", "", nil, fmt.Errorf("database not initialized")
	}
	row := DB.QueryRow(`SELECT alias_name, peer_id, pubkey_bytes FROM alias_store WHERE alias_hash = ?`, aliasHash)
	err = row.Scan(&aliasName, &peerID, &pubkeyBytes)
	return
}

// FindAliasByPeerID looks up the registered alias name for a given peer ID.
// It excludes aliases that are registered as group aliases, and returns the most recently updated one.
func FindAliasByPeerID(peerID string) (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database not initialized")
	}
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

// DeleteAliasByHash removes an alias record by its hash.
func DeleteAliasByHash(aliasHash string) error {
	if DB == nil {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM alias_store WHERE alias_hash = ?`, aliasHash)
	return err
}

// AliasSearchResult represents an alias search match.
type AliasSearchResult struct {
	AliasName string `json:"alias_name"`
	PeerID    string `json:"peer_id"`
}

// SearchAliases searches the local alias store for aliases or peer IDs matching the query.
func SearchAliases(query string) ([]AliasSearchResult, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	queryParam := "%" + query + "%"
	rows, err := DB.Query(`
		SELECT alias_name, peer_id FROM alias_store 
		WHERE alias_name LIKE ? OR peer_id LIKE ? 
		ORDER BY updated_at DESC 
		LIMIT 20`, queryParam, queryParam)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AliasSearchResult
	for rows.Next() {
		var name, pid string
		if err := rows.Scan(&name, &pid); err != nil {
			continue
		}
		results = append(results, AliasSearchResult{AliasName: name, PeerID: pid})
	}
	return results, nil
}

