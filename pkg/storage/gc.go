package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/ipfs/go-cid"
	corenet "github.com/nicabreon/meshsage/pkg/network"
)

// StartGarbageCollector runs a background loop that deletes old file chunks.
// interval: how often to check for expired blocks (e.g., 1 hour)
// maxAgeDays: how many days to keep a block before deleting (e.g., 7 days)
func StartGarbageCollector(ctx context.Context, interval time.Duration, maxAgeDays int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fmt.Printf("[GC] Garbage Collector started. Policy: Delete blocks older than %d days.\n", maxAgeDays)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runGC(maxAgeDays)
		}
	}
}

func runGC(maxAgeDays int) {
	fmt.Println("[GC] Running scheduled cleanup...")

	expiredCIDs, err := GetExpiredBlocks(maxAgeDays)
	if err != nil {
		fmt.Printf("[GC Error] Failed to query expired blocks: %v\n", err)
		return
	}

	if len(expiredCIDs) == 0 {
		fmt.Println("[GC] No expired blocks found.")
		return
	}

	deletedCount := 0
	for _, cStr := range expiredCIDs {
		c, err := cid.Decode(cStr)
		if err != nil {
			continue
		}

		// Remove from Bitswap Blockstore
		err = corenet.GlobalBlockStore.DeleteBlock(context.Background(), c)
		if err != nil {
			fmt.Printf("[GC Error] Failed to delete block %s: %v\n", cStr, err)
			continue
		}

		// Remove from metadata tracking
		_ = RemoveBlockMetadata(cStr)
		deletedCount++
	}

	fmt.Printf("[GC Success] Cleaned up %d expired blocks from local storage.\n", deletedCount)
}
