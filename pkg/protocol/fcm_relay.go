package protocol

import (
	"context"
	"encoding/json"
	"io"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/nicabreon/meshsage/pkg/logger"
)

const FCMRegisterProtocolID = "/p2p-core/fcm-register/1.0.0"

// FCMRegisterRequest matches the format sent by client nodes
type FCMRegisterRequest struct {
	OwnerID   string `json:"owner_id"`
	Payload   string `json:"payload"`
	Sender    string `json:"sender"`
	Signature string `json:"signature"`
}

// SetupFCMRegisterHandler configures a Dedicated Relay to listen for incoming client FCM tokens
func SetupFCMRegisterHandler(h host.Host) {
	logger.Info().Str("protocol", FCMRegisterProtocolID).Msg("Setting up FCM registration handler on Dedicated Relay")
	h.SetStreamHandler(protocol.ID(FCMRegisterProtocolID), func(s network.Stream) {
		defer s.Close()

		buf, err := io.ReadAll(s)
		if err != nil {
			logger.Warn().Err(err).Msg("FCM Register: Failed to read request body")
			return
		}

		var req FCMRegisterRequest
		if err := json.Unmarshal(buf, &req); err != nil {
			logger.Warn().Err(err).Msg("FCM Register: Failed to unmarshal JSON payload")
			return
		}

		if req.OwnerID == "" || req.Payload == "" || req.Sender == "" || req.Signature == "" {
			logger.Warn().Msg("FCM Register: Received incomplete registration fields")
			return
		}

		// Re-broadcast as a ClusterEvent to the cluster sync PubSub topic.
		// The FCM Service Daemon will listen on this topic, decrypt, and persist the mapping.
		event := ClusterEvent{
			Type:      "FCM_REGISTER",
			OwnerID:   req.OwnerID,
			Payload:   req.Payload,
			Sender:    req.Sender,
			Signature: req.Signature,
		}

		BroadcastClusterEvent(context.Background(), event)
		logger.Info().Str("owner_id", req.OwnerID).Msg("FCM Register: Successfully broadcasted registration to cluster sync topic")
	})
}
