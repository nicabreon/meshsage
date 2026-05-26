package protocol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	"github.com/nicabreon/meshsage/pkg/logger"
)

const AliasProtocolID = "/p2p-core/alias/1.0.0"

type AliasRecord struct {
	PeerID string
	PubKey crypto.PubKey
}

var (
	aliasStore = make(map[string]AliasRecord) // hash(alias) -> record
	ownerStore = make(map[string]string)      // pubkey_string -> alias_name
	aliasMutex sync.RWMutex
)

// SetupAliasService configures the host to handle alias registration and resolution
func SetupAliasService(h host.Host) {
	h.SetStreamHandler(AliasProtocolID, handleAliasStream)
	// Load persisted aliases from DB into memory on startup
	go loadPersistedAliases()
}

// loadPersistedAliases restores alias records from SQLite into the in-memory store
func loadPersistedAliases() {
	rows, err := corestore.DB.Query(`SELECT alias_hash, alias_name, peer_id, pubkey_bytes FROM alias_store`)
	if err != nil { return }
	defer rows.Close()

	aliasMutex.Lock()
	defer aliasMutex.Unlock()

	count := 0
	for rows.Next() {
		var aliasHash, aliasName, peerID string
		var pubkeyBytes []byte
		if err := rows.Scan(&aliasHash, &aliasName, &peerID, &pubkeyBytes); err != nil { continue }
		pubKey, err := crypto.UnmarshalPublicKey(pubkeyBytes)
		if err != nil { continue }
		aliasStore[aliasHash] = AliasRecord{PeerID: peerID, PubKey: pubKey}
		pubKeyStr := base64.StdEncoding.EncodeToString(pubkeyBytes)
		ownerStore[pubKeyStr] = aliasName
		count++
	}
	if count > 0 {
		logger.Info().Int("count", count).Msg("Loaded persisted aliases from database")
	}
}

func handleAliasStream(s network.Stream) {
	remoteID := s.Conn().RemotePeer().String()
	defer s.Close()
	buf := bufio.NewReader(s)
	cmdLine, err := buf.ReadString('\n')
	if err != nil {
		return
	}
	cmdLine = strings.TrimSpace(cmdLine)
	parts := strings.SplitN(cmdLine, " ", 5)

	if len(parts) > 0 {
		logger.Debug().Str("command", parts[0]).Str("peerID", remoteID).Msg("ALIAS SERVICE: Incoming stream")
		switch parts[0] {
		case "REGISTER":
			// REGISTER <alias_name> <peer_id> <pubkey_b64> <sig_b64>
			if len(parts) == 5 {
				aliasName := parts[1]
				if !strings.HasPrefix(aliasName, "@") { aliasName = "@" + aliasName }
				targetPeerID := parts[2]
				pubKeyB64 := parts[3]
				sigB64 := parts[4]

				// 1. Decode Kriptografi
				pubKeyBytes, _ := base64.StdEncoding.DecodeString(pubKeyB64)
				sigBytes, _ := base64.StdEncoding.DecodeString(sigB64)
				pubKey, err := crypto.UnmarshalPublicKey(pubKeyBytes)
				if err != nil {
					s.Write([]byte("ERROR_INVALID_PUBKEY\n"))
					return
				}

				// 2. Verifikasi: Apakah PeerID sesuai dengan PubKey?
				derivedID, _ := peer.IDFromPublicKey(pubKey)
				if derivedID.String() != targetPeerID {
					logger.Error().Str("expected", targetPeerID).Str("derived", derivedID.String()).Msg("ALIAS SERVICE: ID Mismatch")
					s.Write([]byte("ERROR_ID_MISMATCH\n"))
					return
				}

				// 3. Verifikasi Signature: Apakah pemilik PubKey benar-benar mau mendaftar alias ini?
				dataToVerify := []byte(aliasName + targetPeerID + pubKeyB64)
				valid, err := pubKey.Verify(dataToVerify, sigBytes)
				if !valid || err != nil {
					logger.Error().Err(err).Str("alias", aliasName).Msg("ALIAS SERVICE: Signature Verification Failed")
					s.Write([]byte("ERROR_INVALID_SIGNATURE\n"))
					return
				}

				// 4. Kebijakan: Satu PeerID = Satu Username
				pubKeyStr := base64.StdEncoding.EncodeToString(pubKeyBytes)

				aliasMutex.Lock()


				// Cek apakah nama alias baru ini sudah diambil orang lain?
				aliasHash := GetAliasCoordinate(aliasName)
				existing, exists := aliasStore[aliasHash]
				if exists {
					if !existing.PubKey.Equals(pubKey) {
						aliasMutex.Unlock()
						logger.Warn().Str("alias", aliasName).Msg("REJECTED: Someone tried to steal alias")
						s.Write([]byte("ERROR_ALREADY_OWNED\n"))
						return
					}
				}

				// 5. Simpan ke Database & Memory
				logger.Info().Str("alias", aliasName).Str("hash", aliasHash).Msg("ALIAS SERVICE: Storing new alias registration")
				
				err = corestore.SaveAlias(aliasHash, aliasName, targetPeerID, pubKeyBytes)
				if err != nil {
					aliasMutex.Unlock()
					logger.Error().Err(err).Msg("ALIAS SERVICE: Failed to save alias to database")
					s.Write([]byte("ERROR_DB\n"))
					return
				}

				aliasStore[aliasHash] = AliasRecord{PeerID: targetPeerID, PubKey: pubKey}
				ownerStore[pubKeyStr] = aliasName
				aliasMutex.Unlock()

				logger.Displayf("[Alias DHT] Verified & Registered %s to %s (hash: %s)\n", aliasName, FormatPeerID(targetPeerID), aliasHash)
				s.Write([]byte("OK\n"))
			}
		case "RESOLVE":
			if len(parts) == 2 {
				aliasName := parts[1]
				if !strings.HasPrefix(aliasName, "@") { aliasName = "@" + aliasName }
				aliasHash := fmt.Sprintf("%x", sha256.Sum256([]byte(aliasName)))
				logger.Debug().Str("alias", aliasName).Str("hash", aliasHash).Msg("ALIAS SERVICE: Resolving alias")
				
				aliasMutex.RLock()
				record, exists := aliasStore[aliasHash]
				aliasMutex.RUnlock()
				
				if exists {
					logger.Info().Str("alias", aliasName).Str("peerID", record.PeerID).Msg("ALIAS SERVICE: Alias resolved from memory")
					pubKeyBytes, _ := crypto.MarshalPublicKey(record.PubKey)
					pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)
					response := fmt.Sprintf("FOUND %s %s\n", record.PeerID, pubKeyB64)
					s.Write([]byte(response))
				} else {
					logger.Debug().Str("alias", aliasName).Msg("ALIAS SERVICE: Alias not found in local memory")
					s.Write([]byte("NOT_FOUND\n"))
				}
			}
		case "RESOLVE_GROUP":
			if len(parts) == 2 {
				aliasName := parts[1]
				if !strings.HasPrefix(aliasName, "@") { aliasName = "@" + aliasName }
				
				meta, err := corestore.LoadGroupMetadata(aliasName)
				if err == nil {
					metaBytes, _ := json.Marshal(meta)
					response := fmt.Sprintf("FOUND_GROUP %s\n", base64.StdEncoding.EncodeToString(metaBytes))
					s.Write([]byte(response))
				} else {
					s.Write([]byte("NOT_FOUND\n"))
				}
				return
			}
		}
	}
}

// RegisterAlias sends a signed registration request to the closest DHT nodes
func RegisterAlias(ctx context.Context, h host.Host, alias string, myPeerID string) error {
	coord := GetAliasCoordinate(alias)
	
	// 1. Persiapkan Tanda Tangan Digital (Proof of Ownership)
	privKey := h.Peerstore().PrivKey(h.ID())
	pubKey := h.Peerstore().PubKey(h.ID())
	pubKeyBytes, _ := crypto.MarshalPublicKey(pubKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Format harus sama dengan yang diverifikasi Relay: aliasName + targetPeerID + pubKeyB64
	dataToSign := []byte(alias + myPeerID + pubKeyB64)
	signature, err := privKey.Sign(dataToSign)
	if err != nil {
		return err
	}
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	// 2. Cari node terdekat di DHT dengan timeout 3 detik
	dhtCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	closestPeers, err := corenet.GlobalDHT.GetClosestPeers(dhtCtx, coord)
	cancel()
	if err != nil || len(closestPeers) == 0 {
		closestPeers = h.Network().Peers()
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0

	logger.Debug().Int("peer_count", len(closestPeers)).Str("alias", alias).Msg("CLIENT: Iterating peers for registration")
	for _, p := range closestPeers {
		if p == h.ID() { continue }
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()

			dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			s, err := h.NewStream(dialCtx, peerID, AliasProtocolID)
			if err != nil {
				logger.Debug().Err(err).Str("peerID", peerID.String()).Msg("CLIENT: Failed to dial peer for alias registration")
				return
			}
			defer s.Close()

			// Format: REGISTER <alias_name> <peer_id> <pubkey_b64> <sig_b64>
			cmd := fmt.Sprintf("REGISTER %s %s %s %s\n", alias, myPeerID, pubKeyB64, sigB64)
			_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err = s.Write([]byte(cmd))
			if err != nil { return }

			_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
			respBuf := bufio.NewReader(s)
			resp, err := respBuf.ReadString('\n')
			if err != nil { return }

			if strings.TrimSpace(resp) == "OK" {
				logger.Info().Str("peerID", peerID.String()).Msg("CLIENT: Registration accepted by peer")
				mu.Lock()
				successCount++
				mu.Unlock()
			} else {
				logger.Warn().Str("peerID", peerID.String()).Str("response", strings.TrimSpace(resp)).Msg("CLIENT: Registration rejected by peer")
			}
		}(p)
	}
	wg.Wait()

	if successCount == 0 {
		return fmt.Errorf("failed to register alias (maybe already owned by someone else?)")
	}

	// Save to local database and memory
	aliasHash := GetAliasCoordinate(alias)
	pubKeyStr := base64.StdEncoding.EncodeToString(pubKeyBytes)

	aliasMutex.Lock()


	_ = corestore.SaveAlias(aliasHash, alias, myPeerID, pubKeyBytes)
	aliasStore[aliasHash] = AliasRecord{PeerID: myPeerID, PubKey: pubKey}
	ownerStore[pubKeyStr] = alias
	aliasMutex.Unlock()

	logger.Displayf("[Alias] Successfully registered '%s' on %d nodes with Digital Signature!\n", alias, successCount)
	return nil
}

// ResolveAlias queries local memory first, then the closest DHT nodes to find the PeerID for a given alias
func ResolveAlias(ctx context.Context, h host.Host, alias string) (string, error) {
	if !strings.HasPrefix(alias, "@") {
		alias = "@" + alias
	}
	aliasHash := GetAliasCoordinate(alias)

	// 1. Check local memory first (fastest path - covers aliases registered on this node)
	aliasMutex.RLock()
	record, exists := aliasStore[aliasHash]
	aliasMutex.RUnlock()
	if exists {
		logger.Debug().Str("alias", alias).Str("peerID", record.PeerID).Msg("RESOLVE: Found in local memory")
		return record.PeerID, nil
	}

	// 2. Query the network
	coord := aliasHash
	dhtCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	closestPeers, err := corenet.GlobalDHT.GetClosestPeers(dhtCtx, coord)
	cancel()
	if err != nil || len(closestPeers) == 0 {
		closestPeers = h.Network().Peers()
	}

	// Buffer size = number of peers so goroutines never block on send
	resChan := make(chan string, len(closestPeers)+1)
	var wg sync.WaitGroup

	for _, p := range closestPeers {
		if p == h.ID() { continue }
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()

			dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			s, err := h.NewStream(dialCtx, peerID, AliasProtocolID)
			if err != nil { return }
			defer s.Close()

			cmd := fmt.Sprintf("RESOLVE %s\n", alias)
			_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err = s.Write([]byte(cmd))
			if err != nil { return }

			_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
			respBuf := bufio.NewReader(s)
			resp, err := respBuf.ReadString('\n')
			if err != nil { return }

			resp = strings.TrimSpace(resp)
			if strings.HasPrefix(resp, "FOUND ") {
				parts := strings.SplitN(resp, " ", 3)
				if len(parts) >= 2 && parts[1] != "" {
					peerID := parts[1]
					
					// Cache the resolved alias locally if public key is provided and matches the peer ID
					if len(parts) == 3 && parts[2] != "" {
						pubKeyBytes, err := base64.StdEncoding.DecodeString(parts[2])
						if err == nil {
							pubKey, err := crypto.UnmarshalPublicKey(pubKeyBytes)
							if err == nil {
								derivedID, err := peer.IDFromPublicKey(pubKey)
								if err == nil && derivedID.String() == peerID {
									aliasHash := GetAliasCoordinate(alias)
									aliasMutex.Lock()
									pubKeyStr := base64.StdEncoding.EncodeToString(pubKeyBytes)

									
									_ = corestore.SaveAlias(aliasHash, alias, peerID, pubKeyBytes)
									aliasStore[aliasHash] = AliasRecord{PeerID: peerID, PubKey: pubKey}
									ownerStore[pubKeyStr] = alias
									aliasMutex.Unlock()
									
									logger.Debug().Str("alias", alias).Str("peerID", peerID).Msg("RESOLVE: Cached resolved alias locally")
								}
							}
						}
					}

					// Non-blocking send: channel is buffered so this won't block
					select {
					case resChan <- peerID:
					default:
					}
				}
			}
		}(p)
	}

	// Wait for all goroutines then close channel in background
	go func() {
		wg.Wait()
		close(resChan)
	}()

	// Use a deadline-bounded loop to drain the channel instead of a plain select
	// This avoids the race where close(resChan) fires before a goroutine sends its result
	timeoutCh := time.After(5 * time.Second)
	for {
		select {
		case res, ok := <-resChan:
			if !ok {
				// Channel closed with no result found
				return "", fmt.Errorf("alias '%s' not found in network", alias)
			}
			if res != "" {
				return res, nil
			}
		case <-timeoutCh:
			return "", fmt.Errorf("alias '%s' resolution timed out", alias)
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// ResolveGroupMetadata queries network nodes to find the metadata of a group by its alias or ID
func ResolveGroupMetadata(ctx context.Context, h host.Host, alias string) (corestore.GroupMetadata, error) {
	if !strings.HasPrefix(alias, "@") {
		alias = "@" + alias
	}

	// 1. Check local DB first
	meta, err := corestore.LoadGroupMetadata(alias)
	if err == nil { return meta, nil }

	// 2. Query the creator node directly if we can resolve the alias
	creatorIDStr, err := ResolveAlias(ctx, h, alias)
	if err == nil {
		creatorID, errDec := peer.Decode(creatorIDStr)
		if errDec == nil && creatorID != h.ID() {
			dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			s, errStream := h.NewStream(dialCtx, creatorID, AliasProtocolID)
			cancel()
			if errStream == nil {
				defer s.Close()
				cmd := fmt.Sprintf("RESOLVE_GROUP %s\n", alias)
				_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, errWrite := s.Write([]byte(cmd))
				if errWrite == nil {
					_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
					respBuf := bufio.NewReader(s)
					resp, errRead := respBuf.ReadString('\n')
					if errRead == nil {
						resp = strings.TrimSpace(resp)
						if strings.HasPrefix(resp, "FOUND_GROUP ") {
							parts := strings.SplitN(resp, " ", 2)
							if len(parts) == 2 {
								metaBytes, errDecB64 := base64.StdEncoding.DecodeString(parts[1])
								if errDecB64 == nil {
									var m corestore.GroupMetadata
									if errU := json.Unmarshal(metaBytes, &m); errU == nil {
										return m, nil
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 3. Fallback: Query the closest peers
	aliasHash := GetAliasCoordinate(alias)
	dhtCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	closestPeers, err := corenet.GlobalDHT.GetClosestPeers(dhtCtx, aliasHash)
	cancel()
	if err != nil || len(closestPeers) == 0 {
		closestPeers = h.Network().Peers()
	}

	for _, p := range closestPeers {
		if p == h.ID() { continue }
		
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		s, err := h.NewStream(dialCtx, p, AliasProtocolID)
		cancel()
		if err != nil { continue }
		defer s.Close()

		cmd := fmt.Sprintf("RESOLVE_GROUP %s\n", alias)
		_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err = s.Write([]byte(cmd))
		if err != nil { continue }

		_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
		respBuf := bufio.NewReader(s)
		resp, err := respBuf.ReadString('\n')
		if err != nil { continue }

		resp = strings.TrimSpace(resp)
		if strings.HasPrefix(resp, "FOUND_GROUP ") {
			parts := strings.SplitN(resp, " ", 2)
			if len(parts) == 2 {
				metaBytes, errDec := base64.StdEncoding.DecodeString(parts[1])
				if errDec == nil {
					var m corestore.GroupMetadata
					if errU := json.Unmarshal(metaBytes, &m); errU == nil {
						return m, nil
					}
				}
			}
		}
	}
	return corestore.GroupMetadata{}, fmt.Errorf("group metadata not found in network")
}
