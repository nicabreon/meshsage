package storage

import (
	"context"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
)

// StartGarbageCollector runs a background loop that deletes old file chunks.
// interval: how often to check for expired blocks (e.g., 1 hour)
// maxAgeDays: how many days to keep a block before deleting (e.g., 7 days)
func StartGarbageCollector(ctx context.Context, interval time.Duration, maxAgeDays int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger.Info().Msgf("Garbage Collector started. Policy: Delete blocks older than %d days.", maxAgeDays)

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
	logger.Info().Msg("Running scheduled cleanup...")

	expiredCIDs, err := GetExpiredBlocks(maxAgeDays)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to query expired blocks")
		return
	}

	if len(expiredCIDs) == 0 {
		logger.Info().Msg("No expired blocks found.")
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
			logger.Error().Err(err).Str("cid", cStr).Msg("Failed to delete block")
			continue
		}

		// Remove from metadata tracking
		_ = RemoveBlockMetadata(cStr)
		deletedCount++
	}

	logger.Info().Msgf("Cleaned up %d expired blocks from local storage.", deletedCount)
}

