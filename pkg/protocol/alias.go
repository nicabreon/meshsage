package protocol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

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
		count++
	}
	if count > 0 {
		fmt.Printf("[Alias DHT] Loaded %d persisted aliases from database.\n", count)
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
				// Cek apakah Kunci Publik ini sudah punya alias lain?
				oldAlias, hasOld := ownerStore[pubKeyStr]
				if hasOld && oldAlias != aliasName {
					// Hapus alias lama
					oldHash := GetAliasCoordinate(oldAlias)
					delete(aliasStore, oldHash)
					fmt.Printf("[Alias DHT] User updated name: @%s -> @%s\n", oldAlias, aliasName)
				}

				// Cek apakah nama alias baru ini sudah diambil orang lain?
				aliasHash := GetAliasCoordinate(aliasName)
				existing, exists := aliasStore[aliasHash]
				if exists {
					if !existing.PubKey.Equals(pubKey) {
						aliasMutex.Unlock()
						fmt.Printf("[Alias DHT] REJECTED: Someone tried to steal @%s\n", aliasName)
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

				fmt.Printf("[Alias DHT] Verified & Registered %s to %s (hash: %s)\n", aliasName, FormatPeerID(targetPeerID), aliasHash)
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
					response := fmt.Sprintf("FOUND %s\n", record.PeerID)
					s.Write([]byte(response))
				} else {
					logger.Debug().Str("alias", aliasName).Msg("ALIAS SERVICE: Alias not found in local memory")
					s.Write([]byte("NOT_FOUND\n"))
				}
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

	// 2. Cari node terdekat di DHT
	closestPeers, err := corenet.GlobalDHT.GetClosestPeers(ctx, coord)
	if err != nil || len(closestPeers) == 0 {
		closestPeers = h.Network().Peers()
	}

	successCount := 0
	logger.Debug().Int("peer_count", len(closestPeers)).Str("alias", alias).Msg("CLIENT: Iterating peers for registration")
	for _, p := range closestPeers {
		if p == h.ID() { continue }
		logger.Debug().Str("peerID", p.String()).Msg("CLIENT: Sending registration to peer")
		s, err := h.NewStream(ctx, p, AliasProtocolID)
		if err != nil { continue }

		// Format: REGISTER <alias_name> <peer_id> <pubkey_b64> <sig_b64>
		cmd := fmt.Sprintf("REGISTER %s %s %s %s\n", alias, myPeerID, pubKeyB64, sigB64)
		_, err = s.Write([]byte(cmd))
		
		// Baca respon
		respBuf := bufio.NewReader(s)
		resp, _ := respBuf.ReadString('\n')
		s.Close()

		if strings.TrimSpace(resp) == "OK" {
			logger.Info().Str("peerID", p.String()).Msg("CLIENT: Registration accepted by peer")
			successCount++
		} else {
			fmt.Printf("[Alias Error from %s]: %s\n", FormatPeerID(p.String()), strings.TrimSpace(resp))
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to register alias (maybe already owned by someone else?)")
	}
	fmt.Printf("[Alias] Successfully registered '%s' on %d nodes with Digital Signature!\n", alias, successCount)
	return nil
}

// ResolveAlias queries the closest DHT nodes to find the PeerID for a given alias
func ResolveAlias(ctx context.Context, h host.Host, alias string) (string, error) {
	coord := GetAliasCoordinate(alias)
	
	closestPeers, err := corenet.GlobalDHT.GetClosestPeers(ctx, coord)
	if err != nil || len(closestPeers) == 0 {
		closestPeers = h.Network().Peers()
	}

	for _, p := range closestPeers {
		if p == h.ID() { continue }
		s, err := h.NewStream(ctx, p, AliasProtocolID)
		if err != nil { continue }

		_, err = s.Write([]byte(fmt.Sprintf("RESOLVE %s\n", alias)))
		if err != nil {
			s.Close()
			continue
		}

		buf := bufio.NewReader(s)
		line, err := buf.ReadString('\n')
		s.Close()
		
		if err != nil { continue }
		
		line = strings.TrimSpace(line)
		parts := strings.Split(line, " ")
		if len(parts) == 2 && parts[0] == "FOUND" {
			return parts[1], nil
		}
	}

	return "", fmt.Errorf("alias '%s' not found in network", alias)
}
