package network

import (
	"context"

	"github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/nicabreon/meshsage/pkg/logger"
)

var GlobalPubSub *pubsub.PubSub

func SetupPubSub(ctx context.Context, h host.Host) error {
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return err
	}
	GlobalPubSub = ps
	logger.Debug().Msg("GossipSub Router initialized")
	return nil
}
