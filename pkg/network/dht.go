package network

import (
	"context"
	"sync"

	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/nicabreon/meshsage/pkg/logger"
)

var (
	GlobalDHT *dht.IpfsDHT
	once      sync.Once
)

func SetupDHT(ctx context.Context, h host.Host) (*dht.IpfsDHT, error) {
	var err error
	once.Do(func() {
		GlobalDHT, err = dht.New(ctx, h, dht.Mode(dht.ModeServer))
		if err != nil {
			return
		}

		if err = GlobalDHT.Bootstrap(ctx); err != nil {
			return
		}

		logger.Debug().Msg("Kademlia DHT initialized successfully")
	})

	return GlobalDHT, err
}
