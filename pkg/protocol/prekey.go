package protocol

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	"github.com/nicabreon/meshsage/pkg/logger"
)

const PreKeyProtocolID = "/p2p-core/prekey/1.0.0"

var (
	fetchHistory      = make(map[string]int)
	fetchHistoryMutex sync.Mutex
)

type PreKeyBatch struct {
	OwnerID   string        `json:"owner_id"`
	Keys      []OneTimeKey `json:"keys"`
	Signature string        `json:"signature"`
}

type OneTimeKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func SetupPreKeyService(h host.Host) {
	h.SetStreamHandler(PreKeyProtocolID, handlePreKeyStream)

	go func() {
		for {
			time.Sleep(10 * time.Minute)
			fetchHistoryMutex.Lock()
			fetchHistory = make(map[string]int)
			fetchHistoryMutex.Unlock()
			logger.Debug().Msg("Pre-key rate limit history cleared")
		}
	}()
}

func handlePreKeyStream(s network.Stream) {
	peerID := s.Conn().RemotePeer().String()
	logger.Debug().Str("peerID", peerID).Msg("Incoming pre-key stream")
	
	if !corenet.ShouldActAsRelay() {
		logger.Debug().Str("peerID", peerID).Msg("Rejecting pre-key stream: Node is not a relay")
		s.Reset()
		return
	}
	defer s.Close()
	buf := bufio.NewReader(s)
	line, err := buf.ReadString('\n')
	if err != nil { return }

	parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
	if len(parts) < 2 { return }

	switch parts[0] {
	case "UPLOAD_GZIP":
		size := 0
		fmt.Sscanf(parts[1], "%d", &size)
		if size <= 0 { return }
		logger.Debug().Str("peerID", s.Conn().RemotePeer().String()).Msg("Received compressed pre-key UPLOAD")

		compressedData := make([]byte, size)
		_, err = io.ReadFull(buf, compressedData)
		if err != nil {
			logger.Error().Err(err).Msg("Error reading compressed data")
			return
		}

		zr, err := gzip.NewReader(bytes.NewReader(compressedData))
		if err != nil { return }
		defer zr.Close()

		var batch PreKeyBatch
		if err := json.NewDecoder(zr).Decode(&batch); err != nil {
			s.Write([]byte("ERROR: Decompression failed\n"))
			return
		}

		if err := verifyBatchSignature(batch); err != nil {
			s.Write([]byte("ERROR: Unauthorized upload\n"))
			return
		}

		for _, k := range batch.Keys {
			corestore.SavePreKey(batch.OwnerID, k.KeyID, k.PublicKey, "", k.Signature)
		}
		logger.Info().Int("count", len(batch.Keys)).Str("peerID", batch.OwnerID).Msg("Stored compressed pre-keys")
		s.Write([]byte("OK\n"))

	case "UPLOAD":
		logger.Debug().Str("peerID", s.Conn().RemotePeer().String()).Msg("Received uncompressed pre-key UPLOAD")
		var batch PreKeyBatch
		if err := json.Unmarshal([]byte(parts[1]), &batch); err != nil {
			logger.Error().Msg("Invalid JSON upload")
			s.Write([]byte("ERROR: Invalid JSON\n"))
			return
		}
		
		if err := verifyBatchSignature(batch); err != nil {
			s.Write([]byte("ERROR: Unauthorized upload\n"))
			return
		}

		for _, k := range batch.Keys {
			corestore.SavePreKey(batch.OwnerID, k.KeyID, k.PublicKey, "", k.Signature)
		}
		logger.Info().Int("count", len(batch.Keys)).Str("peerID", batch.OwnerID).Msg("Stored uncompressed pre-keys")
		s.Write([]byte(fmt.Sprintf("OK: Stored %d keys\n", len(batch.Keys))))

	case "FETCH":
		targetID := strings.TrimSpace(parts[1])
		requesterID := s.Conn().RemotePeer().String()
		logger.Debug().Str("requester", requesterID).Str("target", targetID).Msg("PREKEY SERVICE: Incoming FETCH request")

		limitKey := requesterID + ":" + targetID
		fetchHistoryMutex.Lock()
		count := fetchHistory[limitKey]
		if count >= 10 {
			fetchHistoryMutex.Unlock()
			logger.Warn().Str("requester", requesterID).Str("target", targetID).Msg("PREKEY SERVICE: Rate limit exceeded")
			s.Write([]byte("ERROR: Rate limit exceeded\n"))
			return
		}
		fetchHistory[limitKey]++
		fetchHistoryMutex.Unlock()

		keyID, pubKey, sig, err := corestore.FetchOnePreKey(targetID, s.Conn().LocalPeer().String())
		if err != nil {
			logger.Debug().Str("peerID", targetID).Msg("PREKEY SERVICE: No keys found in database")
			s.Write([]byte("ERROR: No keys available\n"))
			return
		}
		
		resp, _ := json.Marshal(map[string]string{
			"key_id":     keyID,
			"public_key": pubKey,
			"signature":  sig,
		})
		s.Write([]byte(string(resp) + "\n"))
		logger.Info().Str("keyID", keyID).Str("peerID", targetID).Msg("PREKEY SERVICE: Delivered pre-key to requester")

	case "COUNT":
		ownerID := parts[1]
		count := corestore.GetPreKeyCount(ownerID)
		logger.Debug().Str("peerID", ownerID).Int("count", count).Msg("PREKEY SERVICE: Providing pre-key count")
		s.Write([]byte(fmt.Sprintf("%d\n", count)))
	}
}

func verifyBatchSignature(batch PreKeyBatch) error {
	if batch.Signature == "" { return fmt.Errorf("missing signature") }
	ownerID, err := peer.Decode(batch.OwnerID)
	if err != nil { return err }
	pubKey, err := ownerID.ExtractPublicKey()
	if err != nil { return err }

	var buf bytes.Buffer
	buf.WriteString(batch.OwnerID)
	for _, k := range batch.Keys {
		buf.WriteString(k.KeyID)
		buf.WriteString(k.PublicKey)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(batch.Signature)
	if err != nil { return err }

	valid, err := pubKey.Verify(buf.Bytes(), sigBytes)
	if !valid || err != nil { return fmt.Errorf("invalid signature") }
	return nil
}

func UploadPreKeys(ctx context.Context, h host.Host, relayID peer.ID, batch PreKeyBatch) error {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	s, err := h.NewStream(dialCtx, relayID, PreKeyProtocolID)
	cancel()
	if err != nil { return err }
	defer s.Close()

	_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
	jsonBatch, _ := json.Marshal(batch)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(jsonBatch)
	zw.Close()
	compressedData := buf.Bytes()

	_, err = s.Write([]byte(fmt.Sprintf("UPLOAD_GZIP %d\n", len(compressedData))))
	if err != nil { return err }
	_, err = s.Write(compressedData)
	return err
}

func FetchPreKey(ctx context.Context, h host.Host, relayID peer.ID, targetID string) (string, string, string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	s, err := h.NewStream(dialCtx, relayID, PreKeyProtocolID)
	cancel()
	if err != nil { return "", "", "", err }
	defer s.Close()

	_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = s.Write([]byte(fmt.Sprintf("FETCH %s\n", targetID)))
	if err != nil { return "", "", "", err }

	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := bufio.NewReader(s)
	resp, err := buf.ReadString('\n')
	if err != nil { return "", "", "", err }
	
	logger.Debug().Str("peerID", relayID.String()).Str("resp", strings.TrimSpace(resp)).Msg("Pre-key relay response")

	if strings.HasPrefix(resp, "ERROR") {
		return "", "", "", fmt.Errorf("%s", resp)
	}

	var data map[string]string
	if err := json.Unmarshal([]byte(resp), &data); err != nil {
		return "", "", "", err
	}
	return data["key_id"], data["public_key"], data["signature"], nil
}

func AutoRefillPreKeys(ctx context.Context, h host.Host, relayID peer.ID, privKey crypto.PrivKey) error {
	if relayID == h.ID() { return nil }

	protos, err := h.Peerstore().GetProtocols(relayID)
	if err != nil { return err }
	
	isInfra := false
	for _, p := range protos {
		if string(p) == "/p2p-core/infra/1.1.0" {
			isInfra = true
			break
		}
	}
	if !isInfra { return nil }

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	s, err := h.NewStream(dialCtx, relayID, PreKeyProtocolID)
	cancel()
	if err != nil { return err }
	
	_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = s.Write([]byte(fmt.Sprintf("COUNT %s\n", h.ID().String())))
	if err != nil { s.Reset(); return err }

	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := bufio.NewReader(s)
	resp, err := buf.ReadString('\n')
	s.Close()
	
	if err != nil { return err }
	count := 0
	fmt.Sscanf(strings.TrimSpace(resp), "%d", &count)
	
	if count >= 10 { return nil }
	
	logger.Info().Int("current", count).Str("peerID", relayID.String()).Msg("Pre-keys stock low, refilling")
	
	batch := PreKeyBatch{OwnerID: h.ID().String()}
	var sigBuf bytes.Buffer
	sigBuf.WriteString(batch.OwnerID)

	for i := 0; i < 100; i++ {
		priv, pub, _ := corecrypto.GenerateEphemeralKeypair()
		pubB64 := base64.StdEncoding.EncodeToString(pub)
		privB64 := base64.StdEncoding.EncodeToString(priv)
		
		sig, _ := corecrypto.Sign(privKey, pub)
		sigB64 := base64.StdEncoding.EncodeToString(sig)
		keyID := fmt.Sprintf("%x", sha256.Sum256(pub))[:12]
		
		corestore.SavePreKey(h.ID().String(), keyID, pubB64, privB64, sigB64)
		batch.Keys = append(batch.Keys, OneTimeKey{KeyID: keyID, PublicKey: pubB64, Signature: sigB64})
		sigBuf.WriteString(keyID)
		sigBuf.WriteString(pubB64)
	}
	
	batchSig, _ := privKey.Sign(sigBuf.Bytes())
	batch.Signature = base64.StdEncoding.EncodeToString(batchSig)

	err = UploadPreKeys(ctx, h, relayID, batch)
	if err == nil {
		logger.Info().Str("peerID", relayID.String()).Msg("Refilled 100 pre-keys successfully")
	}
	return err
}
