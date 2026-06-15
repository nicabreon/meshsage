package network

import (
	"context"
	"encoding/base32"
	"os"
	"path/filepath"

	"github.com/ipfs/boxo/bitswap"
	"github.com/ipfs/boxo/bitswap/network/bsnet"
	"github.com/ipfs/boxo/blockservice"
	"github.com/ipfs/boxo/blockstore"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/nicabreon/meshsage/pkg/logger"
)

var (
	GlobalBlockStore   blockstore.Blockstore
	GlobalBlockService blockservice.BlockService
)

func SetupBitswap(ctx context.Context, h host.Host, dhtRouting *dht.IpfsDHT, dataDir string) error {
	var ds datastore.Batching
	var err error
	if dataDir != "" {
		blocksDir := filepath.Join(dataDir, "blocks")
		ds, err = NewFileDatastore(blocksDir)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to create FileDatastore, falling back to MapDatastore")
			ds = datastore.NewMapDatastore()
		} else {
			logger.Debug().Str("dir", blocksDir).Msg("Using persistent FileDatastore for Bitswap")
		}
	} else {
		ds = datastore.NewMapDatastore()
	}

	GlobalBlockStore = blockstore.NewBlockstore(ds)

	networkAdapter := bsnet.NewFromIpfsHost(h)

	// Correct order for boxo/bitswap: New(ctx, network, routing, blockstore)
	exchange := bitswap.New(ctx, networkAdapter, dhtRouting, GlobalBlockStore)

	GlobalBlockService = blockservice.New(GlobalBlockStore, exchange)

	logger.Debug().Msg("Distributed Cluster Storage Engine (Bitswap) initialized")
	return nil
}

type FileDatastore struct {
	dir string
}

func NewFileDatastore(dir string) (*FileDatastore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &FileDatastore{dir: dir}, nil
}

func (fs *FileDatastore) Put(ctx context.Context, key datastore.Key, value []byte) error {
	path := filepath.Join(fs.dir, base32.StdEncoding.EncodeToString([]byte(key.String())))
	return os.WriteFile(path, value, 0644)
}

func (fs *FileDatastore) Get(ctx context.Context, key datastore.Key) ([]byte, error) {
	path := filepath.Join(fs.dir, base32.StdEncoding.EncodeToString([]byte(key.String())))
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, datastore.ErrNotFound
	}
	return data, err
}

func (fs *FileDatastore) Has(ctx context.Context, key datastore.Key) (bool, error) {
	path := filepath.Join(fs.dir, base32.StdEncoding.EncodeToString([]byte(key.String())))
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (fs *FileDatastore) GetSize(ctx context.Context, key datastore.Key) (int, error) {
	path := filepath.Join(fs.dir, base32.StdEncoding.EncodeToString([]byte(key.String())))
	info, err := os.Stat(path)
	if err == nil {
		return int(info.Size()), nil
	}
	if os.IsNotExist(err) {
		return -1, datastore.ErrNotFound
	}
	return -1, err
}

func (fs *FileDatastore) Delete(ctx context.Context, key datastore.Key) error {
	path := filepath.Join(fs.dir, base32.StdEncoding.EncodeToString([]byte(key.String())))
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (fs *FileDatastore) Sync(ctx context.Context, prefix datastore.Key) error {
	return nil
}

func (fs *FileDatastore) Close() error {
	return nil
}

func (fs *FileDatastore) Query(ctx context.Context, q query.Query) (query.Results, error) {
	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, err
	}

	var results []query.Entry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		decodedBytes, err := base32.StdEncoding.DecodeString(entry.Name())
		if err != nil {
			continue
		}
		keyStr := string(decodedBytes)
		key := datastore.NewKey(keyStr)

		qEntry := query.Entry{Key: key.String()}
		if !q.KeysOnly {
			val, err := fs.Get(ctx, key)
			if err == nil {
				qEntry.Value = val
			}
		}
		results = append(results, qEntry)
	}

	return query.ResultsWithEntries(q, results), nil
}

type basicBatch struct {
	ds *FileDatastore
}

func (fs *FileDatastore) Batch(ctx context.Context) (datastore.Batch, error) {
	return &basicBatch{ds: fs}, nil
}

func (b *basicBatch) Put(ctx context.Context, key datastore.Key, value []byte) error {
	return b.ds.Put(ctx, key, value)
}

func (b *basicBatch) Delete(ctx context.Context, key datastore.Key) error {
	return b.ds.Delete(ctx, key)
}

func (b *basicBatch) Commit(ctx context.Context) error {
	return nil
}

