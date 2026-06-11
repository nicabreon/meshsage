package protocol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/nicabreon/meshsage/pkg/logger"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

func StartChatPrompt(ctx context.Context, h host.Host, priv crypto.PrivKey) {
	// Goroutine 1: Manual Stdin
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			msg, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			msg = strings.TrimSpace(msg)
			if msg != "" {
				ProcessCommand(ctx, h, priv, msg)
			}
		}
	}()

	// Goroutine 2: Automated File Input
	go func() {
		inputPath := os.Getenv("P2P_INPUT_PATH")
		if inputPath == "" {
			inputPath = "/tmp/p2p_input"
		}
		for {
			time.Sleep(1 * time.Second)
			info, err := os.Stat(inputPath)
			if err == nil && info.Mode().IsRegular() {
				content, err := os.ReadFile(inputPath)
				if err == nil && len(content) > 0 {
					// Clear the file immediately before processing to avoid race conditions with subsequent writes
					os.WriteFile(inputPath, []byte(""), 0644)

					lines := strings.Split(string(content), "\n")
					for _, line := range lines {
						cmd := strings.TrimSpace(line)
						if cmd != "" {
							logger.Debug().Str("command", cmd).Msg("Executing automated command from file")
							ProcessCommand(ctx, h, priv, cmd)
						}
					}
				}
			}
		}
	}()
}

func ProcessCommand(ctx context.Context, h host.Host, priv crypto.PrivKey, msgStr string) {
	msgStr = strings.TrimSpace(msgStr)
	if msgStr == "" {
		return
	}

	if strings.HasPrefix(msgStr, "/latency ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			targetID, err := resolveTargetPeerID(ctx, h, parts[1])
			if err == nil {
				pings := ping.Ping(ctx, h, targetID)
				for i := 0; i < 3; i++ {
					res := <-pings
					if res.Error == nil {
						logger.Displayf("[Latency] Ping %d: %v\n", i+1, res.RTT)
					}
				}
			} else {
				logger.Displayf("[Error] Failed to resolve target '%s': %v\n", parts[1], err)
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-create ") {
		parts := strings.SplitN(msgStr, " ", 4)
		if len(parts) >= 3 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}
			gtype := strings.ToUpper(parts[2])
			if gtype != "SECURE" && gtype != "UNSECURE" {
				logger.Displayf("[Error] Invalid group type: %s. Must be SECURE or UNSECURE.\n", parts[2])
				return
			}

			var members []string
			if len(parts) == 4 {
				memberListRaw := strings.Split(parts[3], ",")
				for _, m := range memberListRaw {
					m = strings.TrimSpace(m)
					if m == "" {
						continue
					}
					if strings.HasPrefix(m, "@") {
						resolved, err := ResolveAlias(ctx, h, m)
						if err == nil {
							m = resolved
						} else {
							logger.Displayf("[Error] Failed to resolve member alias %s: %v\n", m, err)
							return
						}
					}
					members = append(members, m)
				}
			}

			// Generate Group ID
			groupID := fmt.Sprintf("group_%x", sha256.Sum256([]byte(h.ID().String()+fmt.Sprintf("%d", time.Now().UnixNano()))))[:32]

			// Sign Metadata
			privKey := h.Peerstore().PrivKey(h.ID())
			createdAt := time.Now().Unix()
			dataToSign := []byte(groupID + alias + h.ID().String() + fmt.Sprintf("%d", createdAt))
			sigBytes, err := privKey.Sign(dataToSign)
			if err != nil {
				logger.Displayf("[Error] Failed to sign metadata: %v\n", err)
				return
			}
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			// Register Group Alias to DHT
			errReg := RegisterAlias(ctx, h, alias, h.ID().String())
			if errReg != nil {
				logger.Displayf("[Error] Failed to register group alias %s: %v\n", alias, errReg)
				return
			}

			// Join Group locally
			errJoin := JoinGroupProper(ctx, h, privKey, groupID, alias, h.ID().String(), gtype, sigB64, createdAt, members)
			if errJoin == nil {
				// Send Invitations to members (GINVITE)
				localKey, _ := corestore.GetGroupLocalKey(groupID)
				invitePayload := struct {
					Meta    corestore.GroupMetadata `json:"meta"`
					Members []string                `json:"members"`
					GKey    string                  `json:"gkey"`
				}{
					Meta: corestore.GroupMetadata{
						GroupID:    groupID,
						GroupAlias: alias,
						CreatorID:  h.ID().String(),
						GroupType:  gtype,
						CreatedAt:  createdAt,
						Signature:  sigB64,
					},
					Members: members,
					GKey:    base64.StdEncoding.EncodeToString(localKey),
				}
				inviteBytes, _ := json.Marshal(invitePayload)
				inviteMsg := "GINVITE:" + string(inviteBytes)

				for _, m := range members {
					if m != h.ID().String() {
						targetID, errDec := peer.Decode(m)
						if errDec == nil {
							go func(t peer.ID) {
								_, _ = SendMessage(ctx, h, privKey, t, inviteMsg)
							}(targetID)
						}
					}
				}
			} else {
				logger.Displayf("[Error] Failed to join group: %v\n", errJoin)
			}
		} else {
			logger.Displayf("[Error] Use: /group-create <alias> <secure/unsecure> [member1,member2,...]\n")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-join ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			// Resolve group metadata from the network
			meta, err := ResolveGroupMetadata(ctx, h, alias)
			if err != nil {
				logger.Displayf("[Error] Failed to resolve group metadata for %s: %v\n", alias, err)
				return
			}

			if meta.GroupType == "SECURE" {
				logger.Displayf("[Error] This group is SECURE (Closed). You must be invited by the Creator (%s).\n", FormatSender(meta.CreatorID))
				return
			}

			privKey := h.Peerstore().PrivKey(h.ID())

			// Join locally
			errJoin := JoinGroupProper(ctx, h, privKey, meta.GroupID, meta.GroupAlias, meta.CreatorID, meta.GroupType, meta.Signature, meta.CreatedAt, []string{})
			if errJoin == nil {
				// Broadcast GCMD:JOIN to the group so online members share GKEYs with us
				payload := fmt.Sprintf("GCMD:JOIN:%s", h.ID().String())
				dataToSign := []byte(payload + h.ID().String())
				sigBytes, _ := privKey.Sign(dataToSign)
				sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

				gMsg := GroupMessage{
					SenderID:  h.ID().String(),
					Payload:   payload,
					Signature: sigB64,
				}
				msgBytes, _ := json.Marshal(gMsg)

				session, exists := activeGroups[meta.GroupID]
				if exists {
					_ = session.Topic.Publish(ctx, msgBytes)
				}
			} else {
				logger.Displayf("[Error] Failed to join group: %v\n", errJoin)
			}
		} else {
			logger.Displayf("[Error] Use: /group-join <group_alias>\n")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-add ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			alias := parts[1]
			member := parts[2]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			if meta.CreatorID != h.ID().String() {
				logger.Displayf("[Error] Only the Creator can add members.\n")
				return
			}
			if meta.GroupType != "SECURE" {
				logger.Displayf("[Error] This group is public/open. Members join themselves using /group-join.\n")
				return
			}

			if strings.HasPrefix(member, "@") {
				resolved, err := ResolveAlias(ctx, h, member)
				if err == nil {
					member = resolved
				} else {
					logger.Displayf("[Error] Failed to resolve member alias %s: %v\n", member, err)
					return
				}
			}

			// Save member locally
			_ = corestore.AddGroupMemberV2(meta.GroupID, member, "MEMBER")

			// Send GINVITE to new member
			privKey := h.Peerstore().PrivKey(h.ID())
			localKey, _ := corestore.GetGroupLocalKey(meta.GroupID)
			existingMembers, _ := corestore.GetGroupMembersV2(meta.GroupID)
			var memberIDs []string
			for _, m := range existingMembers {
				memberIDs = append(memberIDs, m.PeerID)
			}
			// Ensure the new member is also included
			memberIDs = append(memberIDs, member)

			invitePayload := struct {
				Meta    corestore.GroupMetadata `json:"meta"`
				Members []string                `json:"members"`
				GKey    string                  `json:"gkey"`
			}{
				Meta:    meta,
				Members: memberIDs,
				GKey:    base64.StdEncoding.EncodeToString(localKey),
			}
			inviteBytes, _ := json.Marshal(invitePayload)
			inviteMsg := "GINVITE:" + string(inviteBytes)

			targetID, errDec := peer.Decode(member)
			if errDec == nil {
				go func(t peer.ID) {
					_, _ = SendMessage(ctx, h, privKey, t, inviteMsg)
				}(targetID)
			}

			// Broadcast GCMD:ADD to existing members
			payload := fmt.Sprintf("GCMD:ADD:%s", member)
			dataToSign := []byte(payload + h.ID().String())
			sigBytes, _ := privKey.Sign(dataToSign)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			gMsg := GroupMessage{
				SenderID:  h.ID().String(),
				Payload:   payload,
				Signature: sigB64,
			}
			msgBytes, _ := json.Marshal(gMsg)

			session, exists := activeGroups[meta.GroupID]
			if exists {
				_ = session.Topic.Publish(ctx, msgBytes)
			}
			logger.Displayf("[Group] Added member %s successfully.\n", parts[2])
		} else {
			logger.Displayf("[Error] Use: /group-add <group_alias> <member>\n")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-remove ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			alias := parts[1]
			member := parts[2]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			if meta.CreatorID != h.ID().String() {
				logger.Displayf("[Error] Only the Creator can remove members.\n")
				return
			}

			if strings.HasPrefix(member, "@") {
				resolved, err := ResolveAlias(ctx, h, member)
				if err == nil {
					member = resolved
				} else {
					logger.Displayf("[Error] Failed to resolve member alias %s: %v\n", member, err)
					return
				}
			}

			// Broadcast GCMD:REMOVE
			payload := fmt.Sprintf("GCMD:REMOVE:%s", member)
			privKey := h.Peerstore().PrivKey(h.ID())
			dataToSign := []byte(payload + h.ID().String())
			sigBytes, _ := privKey.Sign(dataToSign)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			gMsg := GroupMessage{
				SenderID:  h.ID().String(),
				Payload:   payload,
				Signature: sigB64,
			}
			msgBytes, _ := json.Marshal(gMsg)

			session, exists := activeGroups[meta.GroupID]
			if exists {
				_ = session.Topic.Publish(ctx, msgBytes)
			}

			// Process locally
			ProcessGroupControlMessage(ctx, h, meta.GroupID, gMsg)
		} else {
			logger.Displayf("[Error] Use: /group-remove <group_alias> <member>\n")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-exit ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			if meta.CreatorID == h.ID().String() {
				logger.Displayf("[Warning] You are the Creator. Use /group-disband to dissolve the group.\n")
				return
			}

			// Broadcast GCMD:EXIT
			payload := fmt.Sprintf("GCMD:EXIT:%s", h.ID().String())
			privKey := h.Peerstore().PrivKey(h.ID())
			dataToSign := []byte(payload + h.ID().String())
			sigBytes, _ := privKey.Sign(dataToSign)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			gMsg := GroupMessage{
				SenderID:  h.ID().String(),
				Payload:   payload,
				Signature: sigB64,
			}
			msgBytes, _ := json.Marshal(gMsg)

			session, exists := activeGroups[meta.GroupID]
			if exists {
				_ = session.Topic.Publish(ctx, msgBytes)

				// Exit locally
				session.Sub.Cancel()
				session.Topic.Close()
				groupsMutex.Lock()
				delete(activeGroups, meta.GroupID)
				groupsMutex.Unlock()
			}
			_ = corestore.DeleteGroupMetadata(meta.GroupID)
			logger.Displayf("[Group] You left group %s successfully.\n", meta.GroupAlias)
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-disband ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			if meta.CreatorID != h.ID().String() {
				logger.Displayf("[Error] Only the Creator can disband the group.\n")
				return
			}

			// Broadcast GCMD:DISBAND
			payload := "GCMD:DISBAND:"
			privKey := h.Peerstore().PrivKey(h.ID())
			dataToSign := []byte(payload + h.ID().String())
			sigBytes, _ := privKey.Sign(dataToSign)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

			gMsg := GroupMessage{
				SenderID:  h.ID().String(),
				Payload:   payload,
				Signature: sigB64,
			}
			msgBytes, _ := json.Marshal(gMsg)

			session, exists := activeGroups[meta.GroupID]
			if exists {
				_ = session.Topic.Publish(ctx, msgBytes)
			}

			// Disband locally
			ProcessGroupControlMessage(ctx, h, meta.GroupID, gMsg)
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group-info ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}

			meta, err := corestore.LoadGroupMetadata(alias)
			if err != nil {
				logger.Displayf("[Error] Group metadata not found for %s: %v\n", alias, err)
				return
			}
			members, _ := corestore.GetGroupMembersV2(meta.GroupID)
			logger.Displayln("=========================================")
			logger.Displayf("  Group Info: %s\n", meta.GroupAlias)
			logger.Displayf("  ID:         %s\n", meta.GroupID)
			logger.Displayf("  Type:       %s\n", meta.GroupType)
			logger.Displayf("  Creator:    %s\n", FormatSender(meta.CreatorID))
			logger.Displayf("  Created At: %s\n", time.Unix(meta.CreatedAt, 0).Format("02/01/2006 15:04:05"))
			logger.Displayln("  Members List:")
			for _, m := range members {
				status := "Offline"
				memberID, errDec := peer.Decode(m.PeerID)
				if errDec == nil && h.Network().Connectedness(memberID) == network.Connected {
					status = "Online"
				}
				logger.Displayf("    - %s (%s) [%s]\n", FormatSender(m.PeerID), m.Role, status)
			}
			logger.Displayln("=========================================")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/group ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			targetStr := parts[1]
			if !strings.HasPrefix(targetStr, "@") {
				targetStr = "@" + targetStr
			}

			meta, err := corestore.LoadGroupMetadata(targetStr)
			if err == nil {
				targetStr = meta.GroupID
			}
			errSend := SendGroupMessage(ctx, h, targetStr, parts[2])
			if errSend != nil {
				logger.Displayf("[Error] Failed to send message to group: %v\n", errSend)
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/reset-session ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			targetID, err := resolveTargetPeerID(ctx, h, parts[1])
			if err == nil {
				errReset := SendSessionReset(ctx, h, targetID)
				if errReset == nil {
					logger.Displayf("[Success] E2EE Session with %s has been reset.\n", parts[1])
				} else {
					logger.Displayf("[Error] Failed to send reset signal to %s: %v\n", parts[1], errReset)
				}
			} else {
				logger.Displayf("[Error] Failed to resolve target '%s': %v\n", parts[1], err)
			}
		} else {
			logger.Displayf("[Error] Use: /reset-session <peerID_or_alias>\n")
		}
		return
	}

	if msgStr == "/fetch" {
		for _, p := range h.Network().Peers() {
			protos, _ := h.Peerstore().GetProtocols(p)
			isRelay := false
			for _, proto := range protos {
				if string(proto) == InfrastructureProtocolID {
					isRelay = true
					break
				}
			}
			if isRelay {
				logger.Info().Str("peerID", p.String()).Msg("Triggering manual mailbox fetch")
				FetchMailboxMessages(ctx, h, p, priv)
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/register ") {
		parts := strings.SplitN(msgStr, " ", 2)
		if len(parts) == 2 {
			alias := parts[1]
			if !strings.HasPrefix(alias, "@") {
				alias = "@" + alias
			}
			err := RegisterAlias(ctx, h, alias, h.ID().String())
			if err != nil {
				logger.Error().Err(err).Str("alias", alias).Msg("COMMAND: Failed to register alias")
				logger.Displayf("[Error] Failed to register alias %s: %v\n", alias, err)
			}
		}
		return
	}

	if strings.HasPrefix(msgStr, "/send ") || strings.HasPrefix(msgStr, "/msg ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			targetID, err := resolveTargetPeerID(ctx, h, parts[1])
			if err == nil {
				logger.Debug().Str("peerID", targetID.String()).Msg("COMMAND: Calling SendMessage")
				_, errSend := SendMessage(ctx, h, priv, targetID, parts[2])
				if errSend == nil {
					TrackMsgSent()
					logger.Info().Str("peerID", targetID.String()).Msg("Message sent successfully")
				} else {
					logger.Error().Err(errSend).Str("peerID", targetID.String()).Msg("Failed to send message")
					logger.Displayf("[Error] Failed to send message to %s: %v\n", FormatPeerID(targetID.String()), errSend)
				}
			} else {
				logger.Error().Err(err).Str("target", parts[1]).Msg("COMMAND: Invalid Peer ID or unresolvable alias")
				logger.Displayf("[Error] Invalid Peer ID or unresolvable alias '%s': %v\n", parts[1], err)
			}
		} else {
			logger.Warn().Str("command", msgStr).Msg("COMMAND: Invalid /msg format. Use: /msg @alias message")
		}
		return
	}

	if strings.HasPrefix(msgStr, "/upload ") {
		parts := strings.SplitN(msgStr, " ", 3)
		if len(parts) == 3 {
			filePath := parts[1]
			targetID, err := resolveTargetPeerID(ctx, h, parts[2])
			if err == nil {
				fileData, err := os.ReadFile(filePath)
				if err == nil {
					fileName := filepath.Base(filePath)
					fileMsg := fmt.Sprintf("FILE:%s:%d:%s", fileName, len(fileData), base64.StdEncoding.EncodeToString(fileData))
					_, errSend := SendMessage(ctx, h, priv, targetID, fileMsg)
					if errSend == nil {
						TrackMsgSent()
						logger.Displayf("[Success] Encrypted file %s sent to %s\n", fileName, FormatPeerID(targetID.String()))
					} else {
						logger.Error().Err(errSend).Str("peerID", targetID.String()).Msg("Failed to send file")
						logger.Displayf("[Error] Failed to send file %s to %s: %v\n", fileName, FormatPeerID(targetID.String()), errSend)
					}
				} else {
					logger.Displayf("[Error] Failed to read file %s: %v\n", filePath, err)
				}
			} else {
				logger.Displayf("[Error] Failed to resolve target '%s': %v\n", parts[2], err)
			}
		}
		return
	}

	logger.Displayf("[Error] Unknown command: '%s'\n", msgStr)
	logger.Displayf("Available commands: /msg, /group, /join, /fetch, /register, /upload, /latency, /reset-session\n")
}
