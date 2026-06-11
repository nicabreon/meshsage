package protocol

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/nicabreon/meshsage/pkg/logger"
)

var (
	activeSyncs        = make(map[peer.ID]struct{})
	activeSyncsMutex   sync.Mutex
	activeFetches      = make(map[peer.ID]struct{})
	activeFetchesMutex sync.Mutex
)

func StartMailboxSync(ctx context.Context, h host.Host, relayID peer.ID, privKey crypto.PrivKey) {
	// Quick non-blocking guard check before spawning goroutines.
	activeSyncsMutex.Lock()
	if _, exists := activeSyncs[relayID]; exists {
		activeSyncsMutex.Unlock()
		logger.Debug().Str("peerID", relayID.String()).Msg("Mailbox sync already running for relay, skipping duplicate setup")
		return
	}
	// Mark as running immediately — the goroutine below will unmark on exit.
	activeSyncs[relayID] = struct{}{}
	activeSyncsMutex.Unlock()

	// 1. Refill pre-keys
	go AutoRefillPreKeys(ctx, h, relayID, privKey)

	// 2. Fetch mailbox messages immediately (staggered to avoid rate limiting on startup)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
			FetchMailboxMessages(ctx, h, relayID, privKey)
		}
	}()

	// 3. Keep-alive subscription loop.
	// IMPORTANT: This goroutine owns the activeSyncs guard for relayID.
	// The guard is released only when this goroutine exits (ctx cancelled),
	// preventing duplicate loops if the relay reconnects while this loop runs.
	go func() {
		defer func() {
			activeSyncsMutex.Lock()
			delete(activeSyncs, relayID)
			activeSyncsMutex.Unlock()
			logger.Debug().Str("peerID", relayID.String()).Msg("Mailbox sync loop exited, guard released")
		}()

		backoff := 15 * time.Second
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			statusChan := make(chan bool, 2)
			go SubscribeNotifications(ctx, h, relayID, statusChan)

			// Wait for subscription status or context cancel
			var subscribed bool
			select {
			case <-ctx.Done():
				return
			case subscribed = <-statusChan:
			}

			if subscribed {
				backoff = 15 * time.Second // Reset backoff on success
				// Successfully subscribed — wait until lost or ctx cancelled.
				select {
				case <-ctx.Done():
					return
				case <-statusChan:
					// Lost subscription, will retry after backoff below.
				}
			}

			// Back-off before retrying to avoid hammering the relay.
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Increase backoff for next failure
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
	}()

	// 4. Concurrent 30-second pre-key refill check loop.
	go func() {
		refillTicker := time.NewTicker(30 * time.Second)
		defer refillTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-refillTicker.C:
				go AutoRefillPreKeys(ctx, h, relayID, privKey)
			}
		}
	}()
}

func ReplicateFileToRelays(ctx context.Context, h host.Host, manifestCID string) {
	// Find all connected dedicated relays
	var relays []peer.ID
	for _, p := range h.Network().Peers() {
		protos, err := h.Peerstore().GetProtocols(p)
		if err != nil {
			continue
		}
		isDedicated := false
		for _, proto := range protos {
			if string(proto) == DedicatedProtocolID {
				isDedicated = true
				break
			}
		}
		if isDedicated {
			relays = append(relays, p)
		}
	}

	if len(relays) == 0 {
		logger.Warn().Msg("[Replication] No connected Dedicated Relays found to replicate file")
		return
	}

	logger.Info().Str("cid", manifestCID).Int("count", len(relays)).Msg("[Replication] Requesting file replication to dedicated relays...")

	for _, relayID := range relays {
		go func(rID peer.ID) {
			sCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			s, err := h.NewStream(sCtx, rID, protocol.ID(MailboxProtocolID))
			if err != nil {
				logger.Warn().Str("relay", rID.String()).Err(err).Msg("[Replication] Failed to open mailbox stream to relay")
				return
			}
			defer s.Close()

			cmd := fmt.Sprintf("REPLICATE %s\n", manifestCID)
			_, err = s.Write([]byte(cmd))
			if err != nil {
				logger.Warn().Str("relay", rID.String()).Err(err).Msg("[Replication] Failed to write REPLICATE command to relay")
				return
			}

			buf := bufio.NewReader(s)
			resp, err := buf.ReadString('\n')
			if err != nil {
				logger.Warn().Str("relay", rID.String()).Err(err).Msg("[Replication] Failed to read response from relay")
				return
			}

			if strings.TrimSpace(resp) == "OK" {
				logger.Info().Str("relay", rID.String()).Msg("[Replication] Dedicated Relay accepted replication request")
			} else {
				logger.Warn().Str("relay", rID.String()).Str("resp", resp).Msg("[Replication] Dedicated Relay returned non-OK status")
			}
		}(relayID)
	}
}

func StartGlobalMailboxSyncManager(ctx context.Context, h host.Host, privKey crypto.PrivKey) {
	logger.Info().Msg("Starting Global Mailbox Sync Manager (1m fallback polling)...")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 1. Find all connected peers
			peers := h.Network().Peers()
			if len(peers) == 0 {
				continue
			}

			// 2. Filter to find peers that support the mailbox protocol
			var relays []peer.ID
			for _, p := range peers {
				protos, err := h.Peerstore().GetProtocols(p)
				if err != nil {
					continue
				}
				isRelay := false
				for _, proto := range protos {
					if string(proto) == InfrastructureProtocolID {
						isRelay = true
						break
					}
				}
				if isRelay {
					relays = append(relays, p)
				}
			}

			// 3. Fetch from each relay sequentially (synchronously)
			for _, rID := range relays {
				FetchMailboxMessages(ctx, h, rID, privKey)
			}
		}
	}
}
