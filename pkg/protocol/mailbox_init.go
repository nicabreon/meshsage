package protocol

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/nicabreon/meshsage/pkg/logger"
	corenet "github.com/nicabreon/meshsage/pkg/network"
)

var (
	rateLimitMap             = make(map[string]time.Time)
	rateLimitMutex           sync.Mutex
	notifyRegistry           = make(map[string]network.Stream)
	notifyMutex              sync.RWMutex
	processedMailboxMessages sync.Map
)

const (
	MailboxProtocolID        = "/p2p-core/mailbox/1.0.0"
	InfrastructureProtocolID = "/p2p-core/infra/1.1.0"
	DedicatedProtocolID      = "/p2p-core/infra/dedicated/1.1.0"
	NotifyProtocolID         = "/p2p-core/notify/1.0.0"
	MaxMessageSize           = 1024 * 1024
	MaxHybridQuota           = 50 * 1024 * 1024
)

func SetupMailbox(h host.Host, isClientOnly bool) {
	logger.Debug().Str("protocol", MailboxProtocolID).Msg("Setting up mailbox stream handler")
	h.SetStreamHandler(protocol.ID(MailboxProtocolID), func(s network.Stream) {
		handleMailboxStream(h, s)
	})

	actAsRelay := !isClientOnly && !corenet.IsNetworkWeak
	logger.Info().Bool("actAsRelay", actAsRelay).Msg("Mailbox service decision")

	if actAsRelay {
		logger.Debug().Str("protocol", InfrastructureProtocolID).Msg("Registering infrastructure marker")
		h.SetStreamHandler(protocol.ID(InfrastructureProtocolID), func(s network.Stream) {
			s.Close()
		})

		// Jika memang Dedicated Relay, daftarkan marker tambahan
		if corenet.IsDedicated {
			logger.Debug().Str("protocol", DedicatedProtocolID).Msg("Registering DEDICATED infrastructure marker")
			h.SetStreamHandler(protocol.ID(DedicatedProtocolID), func(s network.Stream) {
				s.Close()
			})

			// Register FCM register handler
			SetupFCMRegisterHandler(h)
		}

		logger.Debug().Str("protocol", NotifyProtocolID).Msg("Setting up notification handler")
		h.SetStreamHandler(protocol.ID(NotifyProtocolID), func(s network.Stream) {
			handleNotifyStream(s)
		})
	}

	// BUG-08 FIX: Periodic cleanup rateLimitMap agar tidak memory leak pada relay long-running
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rateLimitMutex.Lock()
			for k, t := range rateLimitMap {
				if time.Since(t) > 5*time.Minute {
					delete(rateLimitMap, k)
				}
			}
			rateLimitMutex.Unlock()
			logger.Debug().Msg("Rate limit map cleaned up")
		}
	}()
}

func handleNotifyStream(s network.Stream) {
	scanner := bufio.NewScanner(s)
	if scanner.Scan() {
		coord := strings.TrimSpace(scanner.Text())
		if coord == "" {
			s.Close()
			return
		}

		notifyMutex.Lock()
		if old, ok := notifyRegistry[coord]; ok {
			old.Close()
		}
		notifyRegistry[coord] = s
		notifyMutex.Unlock()

		logger.Debug().Str("coord", coord).Msg("Notification stream established")

		go func() {
			for scanner.Scan() {
			}
			notifyMutex.Lock()
			if notifyRegistry[coord] == s {
				delete(notifyRegistry, coord)
			}
			notifyMutex.Unlock()
			s.Close()
			logger.Debug().Str("coord", coord).Msg("Notification stream closed")
		}()
	}
}

func SubscribeNotifications(ctx context.Context, h host.Host, relayID peer.ID, statusChan chan<- bool) {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	s, err := h.NewStream(dialCtx, relayID, protocol.ID(NotifyProtocolID))
	cancel()
	if err != nil {
		if statusChan != nil {
			statusChan <- false
		}
		return
	}

	coord := GetMailboxCoordinate(h.ID())
	_, err = fmt.Fprintf(s, "%s\n", coord)
	if err != nil {
		s.Close()
		if statusChan != nil {
			statusChan <- false
		}
		return
	}

	logger.Info().Str("peerID", relayID.String()).Msg("Subscribed to push notifications")
	if statusChan != nil {
		statusChan <- true
	}

	go func() {
		scanner := bufio.NewScanner(s)
		for scanner.Scan() {
			text := scanner.Text()
			if text == "PING" {
				logger.Debug().Str("peerID", relayID.String()).Msg("Received PUSH notification! Triggering fetch...")
				go FetchMailboxMessages(ctx, h, relayID, h.Peerstore().PrivKey(h.ID()))
			}
		}
		s.Close()
		logger.Warn().Str("peerID", relayID.String()).Msg("Subscription lost to relay. Reverting to fast polling")
		if statusChan != nil {
			statusChan <- false
		}
	}()
}

func NotifyRecipient(coord string) {
	notifyMutex.RLock()
	s, ok := notifyRegistry[coord]
	notifyMutex.RUnlock()

	if ok {
		go func() {
			logger.Debug().Str("coord", FormatPeerID(coord)).Msg("Pushing PING notification to active stream")
			_, err := fmt.Fprintf(s, "PING\n")
			if err != nil {
				s.Close()
				notifyMutex.Lock()
				if notifyRegistry[coord] == s {
					delete(notifyRegistry, coord)
				}
				notifyMutex.Unlock()
			}
		}()
	}
}

// ResetMailboxRateLimiter clears the mailbox request rate limiting state (mainly for testing).
func ResetMailboxRateLimiter() {
	rateLimitMutex.Lock()
	rateLimitMap = make(map[string]time.Time)
	rateLimitMutex.Unlock()
}

// ResetProcessedMailboxMessages clears the processed mailbox messages cache.
func ResetProcessedMailboxMessages() {
	processedMailboxMessages.Range(func(key, value interface{}) bool {
		processedMailboxMessages.Delete(key)
		return true
	})
}
