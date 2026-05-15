package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ipfs/go-cid"
	blocks "github.com/ipfs/go-block-format"
	"github.com/multiformats/go-multihash"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	corenet "github.com/nicabreon/meshsage/pkg/network"
)

type FileManifest struct {
	Name      string   `json:"name"`
	Size      int      `json:"size"`
	Chunks    []string `json:"chunks"`
	Thumbnail string   `json:"thumbnail,omitempty"` // Base64 encoded small image preview
}

const chunkSize = 256 * 1024 // 256 KB per block for fast P2P swapping

// GenerateRandomKey generates a random 32-byte symmetric key for the file
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// createBlock packages data into an IPFS block and injects it into Bitswap
func createBlock(ctx context.Context, data []byte) (cid.Cid, error) {
	hash, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	
	c := cid.NewCidV1(cid.Raw, hash)
	blk, err := blocks.NewBlockWithCid(data, c)
	if err != nil {
		return cid.Undef, err
	}

	err = corenet.GlobalBlockService.AddBlock(ctx, blk)
	if err != nil {
		return cid.Undef, err
	}

	// Track block for later Garbage Collection
	_ = TrackBlock(c.String())

	// Important: Tell the DHT that we are providing this block
	// so other nodes in different networks can find us via the Relay/DHT.
	_ = corenet.GlobalDHT.Provide(ctx, c, true)
	
	return c, nil
}

// UploadFile encrypts the file, splits into blocks, seeds via Bitswap, returns ManifestCID and Key
func UploadFile(ctx context.Context, data []byte, filename string) (string, string, string, error) {
	// 1. Generate single-use symmetric key
	fileKey, err := GenerateRandomKey()
	if err != nil { return "", "", "", err }

	// 2. Encrypt the entire file content
	encryptedStr, err := corecrypto.EncryptMessage(fileKey, string(data))
	if err != nil { return "", "", "", err }
	
	encBytes := []byte(encryptedStr)
	totalSize := len(encBytes)
	
	// 3. Chunk and seed to Bitswap
	var chunkCIDs []string
	for i := 0; i < totalSize; i += chunkSize {
		end := i + chunkSize
		if end > totalSize { end = totalSize }
		
		c, err := createBlock(ctx, encBytes[i:end])
		if err != nil { return "", "", "", err }
		chunkCIDs = append(chunkCIDs, c.String())
	}

	// 4. Create and seed the Manifest JSON
	manifest := FileManifest{
		Name:      filename,
		Size:      totalSize,
		Chunks:    chunkCIDs,
		Thumbnail: generateMockThumbnail(filename),
	}
	manifestBytes, _ := json.Marshal(manifest)
	manifestCID, err := createBlock(ctx, manifestBytes)
	if err != nil { return "", "", "", err }

	keyB64 := base64.StdEncoding.EncodeToString(fileKey)
	return manifestCID.String(), keyB64, manifest.Thumbnail, nil
}

func generateMockThumbnail(filename string) string {
	// In a real app, we would use the 'image' package to resize the file if it's an image.
	// For now, we return a simple descriptive stub to demonstrate the protocol flow.
	ext := ""
	parts := strings.Split(filename, ".")
	if len(parts) > 1 {
		ext = strings.ToUpper(parts[len(parts)-1])
	}
	
	if ext == "JPG" || ext == "PNG" || ext == "JPEG" {
		return "BASE64_IMAGE_PREVIEW_DATA_STUB"
	}
	return ""
}

// DownloadFile fetches manifest and chunks from Bitswap, decrypts, and returns raw bytes
func DownloadFile(ctx context.Context, manifestCIDStr, keyB64 string) ([]byte, string, error) {
	// 1. Fetch Manifest
	mCID, err := cid.Decode(manifestCIDStr)
	if err != nil { return nil, "", err }

	mBlock, err := corenet.GlobalBlockService.GetBlock(ctx, mCID)
	if err != nil { return nil, "", err }

	var manifest FileManifest
	if err := json.Unmarshal(mBlock.RawData(), &manifest); err != nil {
		return nil, "", err
	}

	// 2. Fetch all chunks in parallel using Bitswap
	var cids []cid.Cid
	for _, cStr := range manifest.Chunks {
		c, _ := cid.Decode(cStr)
		cids = append(cids, c)
	}

	// This triggers Kademlia Provider Search + Bitswap Swarm Downloads automatically!
	blockChan := corenet.GlobalBlockService.GetBlocks(ctx, cids)
	
	blocksMap := make(map[string][]byte)
	for b := range blockChan {
		blocksMap[b.Cid().String()] = b.RawData()
	}

	var assembled []byte
	for _, cStr := range manifest.Chunks {
		data, ok := blocksMap[cStr]
		if !ok {
			return nil, "", fmt.Errorf("failed to download chunk %s", cStr)
		}
		assembled = append(assembled, data...)
	}

	// 3. Decrypt
	fileKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil { return nil, "", err }

	decryptedStr, err := corecrypto.DecryptMessage(fileKey, string(assembled))
	if err != nil { return nil, "", err }

	return []byte(decryptedStr), manifest.Name, nil
}
