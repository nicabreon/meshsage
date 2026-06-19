package storage

import (
	"database/sql"
	"fmt"
)

// SaveBlock persists a block to the blockchain_blocks table.
func SaveBlock(height int64, hash, prevHash string, ts int64, validator, signature, txsJSON string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`INSERT OR REPLACE INTO blockchain_blocks 
		(height, block_hash, prev_block_hash, timestamp, validator_peer_id, validator_signature, transactions_json) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		height, hash, prevHash, ts, validator, signature, txsJSON)
	return err
}

// GetBlock retrieves a single block by its height.
func GetBlock(height int64) (hash, prevHash string, ts int64, validator, signature, txsJSON string, err error) {
	if DB == nil {
		err = fmt.Errorf("database not initialized")
		return
	}
	row := DB.QueryRow(`SELECT block_hash, prev_block_hash, timestamp, validator_peer_id, validator_signature, transactions_json 
		FROM blockchain_blocks WHERE height = ?`, height)
	err = row.Scan(&hash, &prevHash, &ts, &validator, &signature, &txsJSON)
	return
}

// GetLatestBlockHeight returns the highest block height in the blockchain ledger.
// Returns -1 if no blocks exist yet.
func GetLatestBlockHeight() (int64, error) {
	if DB == nil {
		return -1, fmt.Errorf("database not initialized")
	}
	var height int64
	err := DB.QueryRow(`SELECT COALESCE(MAX(height), -1) FROM blockchain_blocks`).Scan(&height)
	if err != nil {
		if err == sql.ErrNoRows {
			return -1, nil
		}
		return -1, err
	}
	return height, nil
}

// GetLatestBlockHash returns the hash of the latest block, or empty string if no blocks exist.
func GetLatestBlockHash() (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database not initialized")
	}
	var hash string
	err := DB.QueryRow(`SELECT block_hash FROM blockchain_blocks ORDER BY height DESC LIMIT 1`).Scan(&hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return hash, nil
}

// DeleteBlocksFromHeight deletes all blocks starting from the specified height (used during reorgs).
func DeleteBlocksFromHeight(height int64) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`DELETE FROM blockchain_blocks WHERE height >= ?`, height)
	return err
}

// GetAliasRegistrationHeight searches the ledger blocks transactions JSON to find the height where the alias was registered.
// Returns -1 and an error if not found.
func GetAliasRegistrationHeight(alias string) (int64, error) {
	if DB == nil {
		return -1, fmt.Errorf("database not initialized")
	}
	var height int64
	queryParam := "%\"alias\":\"" + alias + "\"%"
	err := DB.QueryRow(`SELECT height FROM blockchain_blocks WHERE transactions_json LIKE ? LIMIT 1`, queryParam).Scan(&height)
	if err != nil {
		return -1, err
	}
	return height, nil
}
