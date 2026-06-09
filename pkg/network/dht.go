package network

import (
	"context"

	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/nicabreon/meshsage/pkg/logger"
)

var (
	GlobalDHT *dht.IpfsDHT
)

func SetupDHT(ctx context.Context, h host.Host) (*dht.IpfsDHT, error) {
	mode := dht.ModeAuto
	if IsClientOnly {
		mode = dht.ModeClient
	} else if IsDedicated {
		mode = dht.ModeServer
	}
	d, err := dht.New(ctx, h, dht.Mode(mode))
	if err != nil {
		return nil, err
	}

	// Bootstrap in the background — never block StartNode waiting for remote peers.
	// If bootstrap peers are unreachable (emulator, offline), the app still starts instantly.
	go func() {
		if err := d.Bootstrap(ctx); err != nil {
			logger.Warn().Err(err).Msg("DHT bootstrap failed (will retry on reconnect)")
		} else {
			logger.Debug().Msg("Kademlia DHT bootstrapped successfully")
		}
	}()

	GlobalDHT = d
	logger.Debug().Msg("Kademlia DHT initialized (bootstrap running in background)")
	return d, nil
}
