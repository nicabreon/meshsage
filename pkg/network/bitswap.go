package network

import (
	"context"

	"github.com/ipfs/boxo/bitswap"
	"github.com/ipfs/boxo/bitswap/network/bsnet"
	"github.com/ipfs/boxo/blockservice"
	"github.com/ipfs/boxo/blockstore"
	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/nicabreon/meshsage/pkg/logger"
)

var (
	GlobalBlockStore   blockstore.Blockstore
	GlobalBlockService blockservice.BlockService
)

func SetupBitswap(ctx context.Context, h host.Host, dhtRouting *dht.IpfsDHT) error {
	ds := datastore.NewMapDatastore()
	GlobalBlockStore = blockstore.NewBlockstore(ds)
	
	networkAdapter := bsnet.NewFromIpfsHost(h)
	
	// Correct order for boxo/bitswap: New(ctx, network, routing, blockstore)
	exchange := bitswap.New(ctx, networkAdapter, dhtRouting, GlobalBlockStore)
	
	GlobalBlockService = blockservice.New(GlobalBlockStore, exchange)
	
	logger.Debug().Msg("Distributed Cluster Storage Engine (Bitswap) initialized")
	return nil
}
