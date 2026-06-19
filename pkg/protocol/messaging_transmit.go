package protocol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	"github.com/nicabreon/meshsage/pkg/logger"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

type timeTrackedDuration struct {
	duration  time.Duration
	updatedAt time.Time
}

var (
	customDialTimeouts   sync.Map // map[string]timeTrackedDuration
	customDialRTTs       sync.Map // map[string]timeTrackedDuration
	x3dhInitiateCooldown sync.Map // map[string]time.Time
)

// pendingDirectQueue holds envelopes that failed direct delivery due to
// a stale or transitioning connection (e.g. WiFi → mobile data switch).
// They are retried via DrainPendingDirectQueue when the peer reconnects.
type pendingDirectEntry struct {
	envelope  string    // finalWireEnvelope ready to transmit
	enqueuedAt time.Time
}

const (
	pendingDirectTTL     = 5 * time.Minute // max age before dropping
	pendingDirectMaxPeer = 20              // max queued entries per peer
)

var (
	pendingDirectMu    sync.Mutex
	pendingDirectQueue = make(map[string][]pendingDirectEntry) // peerID → []entry
)

// enqueuePendingDirect adds an envelope to the per-peer retry queue.
func enqueuePendingDirect(peerID string, envelope string) {
	pendingDirectMu.Lock()
	defer pendingDirectMu.Unlock()
	list := pendingDirectQueue[peerID]
	now := time.Now()
	// Prune expired entries
	filtered := list[:0]
	for _, e := range list {
		if now.Sub(e.enqueuedAt) < pendingDirectTTL {
			filtered = append(filtered, e)
		}
	}
	// Cap the queue size
	if len(filtered) >= pendingDirectMaxPeer {
		filtered = filtered[1:]
	}
	filtered = append(filtered, pendingDirectEntry{envelope: envelope, enqueuedAt: now})
	pendingDirectQueue[peerID] = filtered
}

// DrainPendingDirectQueue is called when a peer reconnects.
// It attempts to re-deliver all envelopes that previously failed for that peer.
func DrainPendingDirectQueue(ctx context.Context, h host.Host, targetID peer.ID) {
	peerID := targetID.String()
	pendingDirectMu.Lock()
	list, ok := pendingDirectQueue[peerID]
	if !ok || len(list) == 0 {
		pendingDirectMu.Unlock()
		return
	}
	now := time.Now()
	toSend := make([]string, 0, len(list))
	for _, e := range list {
		if now.Sub(e.enqueuedAt) < pendingDirectTTL {
			toSend = append(toSend, e.envelope)
		}
	}
	delete(pendingDirectQueue, peerID)
	pendingDirectMu.Unlock()

	if len(toSend) == 0 {
		return
	}

	logger.Info().
		Str("peerID", FormatPeerID(peerID)).
		Int("count", len(toSend)).
		Msg("DrainPendingDirectQueue: retrying failed direct-send envelopes after reconnect")

	for _, env := range toSend {
		// Small delay between retries to let the new connection stabilise
		time.Sleep(100 * time.Millisecond)
		if err := transmitEnvelope(ctx, h, targetID, env); err != nil {
			logger.Warn().
				Err(err).
				Str("peerID", FormatPeerID(peerID)).
				Msg("DrainPendingDirectQueue: retry failed, envelope dropped")
		} else {
			logger.Info().
				Str("peerID", FormatPeerID(peerID)).
				Msg("DrainPendingDirectQueue: envelope re-delivered successfully")
		}
	}
}

func init() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()

			// Clean up x3dhInitiateCooldown (older than 10 seconds, since cooldown limit is 5 seconds)
			x3dhInitiateCooldown.Range(func(key, val interface{}) bool {
				if lastTime, ok := val.(time.Time); ok {
					if now.Sub(lastTime) > 10*time.Second {
						x3dhInitiateCooldown.Delete(key)
					}
				} else {
					x3dhInitiateCooldown.Delete(key)
				}
				return true
			})

			// Clean up customDialTimeouts (older than 1 hour)
			customDialTimeouts.Range(func(key, val interface{}) bool {
				if tracked, ok := val.(timeTrackedDuration); ok {
					if now.Sub(tracked.updatedAt) > 1*time.Hour {
						customDialTimeouts.Delete(key)
					}
				} else {
					customDialTimeouts.Delete(key)
				}
				return true
			})

			// Clean up customDialRTTs (older than 1 hour)
			customDialRTTs.Range(func(key, val interface{}) bool {
				if tracked, ok := val.(timeTrackedDuration); ok {
					if now.Sub(tracked.updatedAt) > 1*time.Hour {
						customDialRTTs.Delete(key)
					}
				} else {
					customDialRTTs.Delete(key)
				}
				return true
			})
		}
	}()
}

func SendMessage(ctx context.Context, h host.Host, priv crypto.PrivKey, target peer.ID, msg string) (string, error) {
	msg = strings.TrimSuffix(msg, "\n")
	virtualTime := GetVirtualTime()
	msgID := fmt.Sprintf("%x", sha256.Sum256([]byte(msg+virtualTime.String())))[:8]
	dataToSign := []byte(msg + msgID)
	sigBytes, _ := priv.Sign(dataToSign)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	senderAlias, _ := corestore.FindAliasByPeerID(h.ID().String())

	env := MessageEnvelope{
		ID:        msgID,
		Type:      MsgTypeText,
		Content:   msg,
		Timestamp: virtualTime.UnixNano(),
		Sender:    senderAlias,
		Signature: sigB64,
	}

	// Mine PoW difficulty 16 for spam prevention
	env.MinePoW(16)

	// Simpan pesan ke sent-message buffer per-peer.
	// Jika receiver mengalami masalah sesi dan mengirim REQUEST_X3DH,
	// pesan ini akan di-kirim ulang setelah X3DH baru selesai.
	trackSentMessage(target.String(), env)

	return msgID, sendSecureEnvelope(ctx, h, priv, target, env)
}

func PrepareSecureEnvelope(ctx context.Context, h host.Host, priv crypto.PrivKey, targetID peer.ID, jsonPayload []byte) (string, error) {
	startPrep := time.Now()
	defer func() {
		logger.Info().Str("target", targetID.String()).Dur("elapsed", time.Since(startPrep)).Msg("LOG_STEP: PrepareSecureEnvelope completed")
	}()

	// BUG-03: Lock per-peer agar tidak ada race condition pada session state
	sessionMu := getSessionLock(targetID.String())
	sessionMu.Lock()
	defer sessionMu.Unlock()

	// 1. Cek apakah sudah punya sesi aktif (Session Cache)
	remoteIdentityB64, rootB64, sendB64, recvB64, remoteRatchetB64, localRatchetPrivB64, localRatchetPubB64, n, m, pn, outboundMsgsSinceRatchet, err := corestore.LoadSession(targetID.String())
	if err == nil && rootB64 != "" {
		// Sesi Aktif Ditemukan!
		rootKey, _ := base64.StdEncoding.DecodeString(rootB64)
		sendChain, _ := base64.StdEncoding.DecodeString(sendB64)
		recvChain, _ := base64.StdEncoding.DecodeString(recvB64)
		remoteRatchetPub, _ := base64.StdEncoding.DecodeString(remoteRatchetB64)
		localRatchetPriv, _ := base64.StdEncoding.DecodeString(localRatchetPrivB64)
		localRatchetPub, _ := base64.StdEncoding.DecodeString(localRatchetPubB64)

		if len(sendChain) == 0 {
			sendChain = rootKey
		}

		session := &corecrypto.SessionState{
			PeerID:                       targetID.String(),
			RemoteIdentityKey:            []byte(remoteIdentityB64),
			RootKey:                      rootKey,
			SendChainKey:                 sendChain,
			RecvChainKey:                 recvChain,
			RemoteRatchetPubkey:          remoteRatchetPub,
			LocalRatchetPrivkey:          localRatchetPriv,
			LocalRatchetPubkey:           localRatchetPub,
			N:                            n,
			M:                            m,
			PN:                           pn,
			OutboundMessagesSinceRatchet: outboundMsgsSinceRatchet,
		}

		ciphertext, err := session.EncryptWithRatchet(string(jsonPayload))
		if err == nil {
			// Save updated state
			corestore.SaveSession(targetID.String(), remoteIdentityB64,
				base64.StdEncoding.EncodeToString(session.RootKey),
				base64.StdEncoding.EncodeToString(session.SendChainKey),
				base64.StdEncoding.EncodeToString(session.RecvChainKey),
				base64.StdEncoding.EncodeToString(session.RemoteRatchetPubkey),
				base64.StdEncoding.EncodeToString(session.LocalRatchetPrivkey),
				base64.StdEncoding.EncodeToString(session.LocalRatchetPubkey),
				session.N, session.M, session.PN, session.OutboundMessagesSinceRatchet)

			finalWireEnvelope := fmt.Sprintf("DR:%s", base64.StdEncoding.EncodeToString([]byte(ciphertext)))
			return finalWireEnvelope, nil
		}
	}

	// 2. Jika tidak ada sesi, lakukan alur X3DH
	now := time.Now()
	if lastVal, ok := x3dhInitiateCooldown.Load(targetID.String()); ok {
		if lastTime, ok := lastVal.(time.Time); ok && now.Sub(lastTime) < 5*time.Second {
			logger.Debug().Str("target", targetID.String()).Msg("X3DH handshake skipped (cooldown active to prevent spam)")
			return "", fmt.Errorf("X3DH handshake cooldown active")
		}
	}
	x3dhInitiateCooldown.Store(targetID.String(), now)

	var keyID, pubKeyB64 string
	preKeyFound := false
	connectedPeers := h.Network().Peers()
	logger.Info().
		Str("target", targetID.String()).
		Int("peers", len(connectedPeers)).
		Msg("No session found. Initiating X3DH Handshake flow")

	for _, relayPeer := range connectedPeers {
		// Optimization: Check if peer supports the pre-key protocol before attempting to dial
		protos, err := h.Peerstore().GetProtocols(relayPeer)
		if err != nil {
			continue
		}
		supportsPreKey := false
		for _, proto := range protos {
			if string(proto) == PreKeyProtocolID {
				supportsPreKey = true
				break
			}
		}
		if !supportsPreKey {
			continue
		}

		logger.Info().Str("target", targetID.String()).Str("relay", relayPeer.String()).Msg("LOG_STEP: X3DH HANDSHAKE: Fetching Pre-Key starting...")
		startFetch := time.Now()
		id, pub, _, err := FetchPreKey(ctx, h, relayPeer, targetID.String())
		logger.Info().Str("target", targetID.String()).Str("relay", relayPeer.String()).Dur("elapsed", time.Since(startFetch)).Err(err).Msg("LOG_STEP: X3DH HANDSHAKE: FetchPreKey finished")
		if err == nil && pub != "" {
			keyID = id
			pubKeyB64 = pub
			preKeyFound = true
			logger.Info().Str("target", targetID.String()).Str("relay", relayPeer.String()).Msg("X3DH SUCCESS: Pre-Key found")
			break
		}
		logger.Debug().
			Err(err).
			Str("target", targetID.String()).
			Str("relay", relayPeer.String()).
			Msg("X3DH: FetchPreKey failed from this peer (not a relay, or no key available)")
	}
	if !preKeyFound {
		logger.Warn().
			Str("target", targetID.String()).
			Int("peers_tried", len(connectedPeers)).
			Msg("X3DH FAILED: no pre-key found for target on any connected peer")
		return "", fmt.Errorf("no pre-key found")
	}

	logger.Debug().Msg("X3DH HANDSHAKE: Generating Ephemeral Keypair & Deriving Shared Secret")
	ePriv, ePub, err := corecrypto.GenerateEphemeralKeypair()
	if err != nil {
		return "", err
	}

	peerPubKeyBytes, _ := base64.StdEncoding.DecodeString(pubKeyB64)
	aesKey, err := corecrypto.DeriveSharedSecret(ePriv, peerPubKeyBytes)
	if err != nil {
		return "", err
	}

	// Inisialisasi Double Ratchet: Generate ratchet keypair lokal
	localRatchetPriv, localRatchetPub, err := corecrypto.GenerateEphemeralKeypair()
	if err != nil {
		return "", err
	}

	// Lakukan DH Send Step awal menggunakan localRatchetPriv dan pubKeyB64 (Pre-key Bob)
	sharedSecret, err := corecrypto.DeriveSharedSecret(localRatchetPriv, peerPubKeyBytes)
	if err != nil {
		return "", err
	}
	res, err := corecrypto.HKDFExpand(sharedSecret, "p2p-core-dh-ratchet", 64)
	if err != nil {
		return "", err
	}

	initRootKey := res[:32]
	initSendChainKey := res[32:]

	senderRootKeyB64 := base64.StdEncoding.EncodeToString(initRootKey)
	senderSendChainB64 := base64.StdEncoding.EncodeToString(initSendChainKey)
	senderRatchetPrivB64 := base64.StdEncoding.EncodeToString(localRatchetPriv)
	senderRatchetPubB64Out := base64.StdEncoding.EncodeToString(localRatchetPub)

	logger.Info().Str("peerID", FormatPeerID(targetID.String())).Str("rootKey", senderRootKeyB64[:6]).Msg("X3DH HANDSHAKE: Saving Initial Session with Ratchet Keys")
	TrackHandshake() // Track X3DH handshake
	// BUG-1 FIX: Sender side — clear stale skipped keys before establishing new session.
	if clearErr := corestore.ClearSkippedKeys(targetID.String()); clearErr != nil {
		logger.Warn().Err(clearErr).Str("targetID", targetID.String()).Msg("X3DH SEND: Failed to clear stale skipped keys")
	} else {
		logger.Debug().Str("targetID", targetID.String()).Msg("X3DH SEND: Cleared stale skipped keys for new session")
	}
	// Simpan session dengan SendChainKey terisi, RecvChainKey kosong, dan RemoteRatchetPubkey = pubKeyB64
	corestore.SaveSession(targetID.String(), pubKeyB64, senderRootKeyB64, senderSendChainB64, "", pubKeyB64, senderRatchetPrivB64, senderRatchetPubB64Out, 0, 0, 0, 0)

	// Sertakan localRatchetPub di dalam payload agar receiver bisa init RecvChainKey
	ePubB64 := base64.StdEncoding.EncodeToString(ePub)
	encryptedBytes, err := corecrypto.EncryptMessageRaw(aesKey, jsonPayload)
	if err != nil {
		return "", err
	}

	// Format: X3DH:keyID:ePub:senderRatchetPub:encryptedPayload
	finalWireEnvelope := fmt.Sprintf("X3DH:%s:%s:%s:%s", keyID, ePubB64, senderRatchetPubB64Out, base64.StdEncoding.EncodeToString(encryptedBytes))
	return finalWireEnvelope, nil
}

func sendSecureEnvelope(ctx context.Context, h host.Host, priv crypto.PrivKey, targetID peer.ID, env MessageEnvelope) error {
	jsonPayload, _ := json.Marshal(env)
	finalWireEnvelope, err := PrepareSecureEnvelope(ctx, h, priv, targetID, jsonPayload)
	if err != nil {
		return err
	}
	return transmitEnvelope(ctx, h, targetID, finalWireEnvelope)
}

// getRelayRTT returns the minimum stream dial RTT to any currently connected dedicated relay.
// If no dedicated relay is connected or measured, it returns 0.
func getRelayRTT(h host.Host) time.Duration {
	if h == nil {
		return 0
	}
	var bestRTT time.Duration = 0
	for _, p := range h.Network().Peers() {
		// Verify if peer is a dedicated relay
		protos, err := h.Peerstore().GetProtocols(p)
		if err != nil {
			continue
		}
		isDedicated := false
		for _, proto := range protos {
			if string(proto) == "/p2p-core/infra/dedicated/1.1.0" {
				isDedicated = true
				break
			}
		}
		if isDedicated {
			if val, ok := customDialRTTs.Load(p.String()); ok {
				if tracked, ok := val.(timeTrackedDuration); ok {
					rtt := tracked.duration
					if bestRTT == 0 || rtt < bestRTT {
						bestRTT = rtt
					}
				}
			}
		}
	}
	return bestRTT
}

// MeasureAndRecordDialTimeout measures stream creation latency to a newly connected peer
// and saves a custom adaptive dial timeout for it.
func MeasureAndRecordDialTimeout(ctx context.Context, h host.Host, target peer.ID) {
	go func() {
		// Wait a moment for connection handshakes (QUIC/TCP, security, muxer) to settle down.
		time.Sleep(1 * time.Second)

		logger.Info().Str("target", target.String()).Msg("LOG_STEP: MeasureAndRecordDialTimeout: Initiating test stream to measure latency...")
		start := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		s, err := h.NewStream(dialCtx, target, "/ipfs/ping/1.0.0")
		cancel()

		if err == nil {
			elapsed := time.Since(start)
			s.Close()

			now := time.Now()
			customDialRTTs.Store(target.String(), timeTrackedDuration{duration: elapsed, updatedAt: now})

			// Calculate adaptive timeout: 3 * elapsed + 1 second buffer (longer buffer to handle spikes or relay routes)
			timeout := 3*elapsed + 1*time.Second
			if timeout < 500*time.Millisecond {
				timeout = 500 * time.Millisecond
			}
			maxAllowedTimeout := 5 * time.Second
			isTargetRelayed := false
			for _, addr := range h.Peerstore().Addrs(target) {
				if strings.Contains(addr.String(), "/p2p-circuit") {
					isTargetRelayed = true
					break
				}
			}
			if isTargetRelayed {
				maxAllowedTimeout = 15 * time.Second
			}
			if timeout > maxAllowedTimeout {
				timeout = maxAllowedTimeout
			}

			customDialTimeouts.Store(target.String(), timeTrackedDuration{duration: timeout, updatedAt: now})
			logger.Info().
				Str("target", target.String()).
				Dur("stream_dial_rtt", elapsed).
				Dur("dial_timeout", timeout).
				Msg("LOG_STEP: MeasureAndRecordDialTimeout: Successfully measured stream creation time and saved custom dial timeout")
		} else {
			logger.Warn().
				Str("target", target.String()).
				Err(err).
				Msg("LOG_STEP: MeasureAndRecordDialTimeout: Failed to open test stream to measure latency")
		}
	}()
}

func getPeerDialTimeout(ctx context.Context, h host.Host, target peer.ID) time.Duration {
	// Establish maximum timeout limit. Hard cap is 5 seconds for direct, 15 seconds for relayed.
	maxLimit := 5 * time.Second

	// Check if target is connected/configured via relay
	isRelayed := false
	conns := h.Network().ConnsToPeer(target)
	for _, conn := range conns {
		if strings.Contains(conn.RemoteMultiaddr().String(), "/p2p-circuit") {
			isRelayed = true
			break
		}
	}
	if !isRelayed {
		for _, addr := range h.Peerstore().Addrs(target) {
			if strings.Contains(addr.String(), "/p2p-circuit") {
				isRelayed = true
				break
			}
		}
	}

	if isRelayed {
		maxLimit = 15 * time.Second
	} else {
		// If we are connected to a dedicated relay, scale maxLimit dynamically based on the relay's RTT.
		// Since relay routing takes at least 1 relay RTT (plus stream negotiation/handshakes),
		// we scale the limit to 3 * relayRTT + 1 second.
		if relayRTT := getRelayRTT(h); relayRTT > 0 {
			adaptiveLimit := 3*relayRTT + 1*time.Second
			if adaptiveLimit > maxLimit {
				maxLimit = adaptiveLimit
			}
		}
	}

	// First, check if we have a measured custom dial timeout
	if val, ok := customDialTimeouts.Load(target.String()); ok {
		if tracked, ok := val.(timeTrackedDuration); ok {
			timeout := tracked.duration
			if timeout > maxLimit {
				timeout = maxLimit
			}
			logger.Debug().
				Str("target", target.String()).
				Dur("dial_timeout", timeout).
				Dur("max_limit", maxLimit).
				Msg("LOG_STEP: getPeerDialTimeout: Using custom recorded dial timeout (capped by limit)")
			return timeout
		}
	}

	// Retrieve EWMA latency from Peerstore
	ewma := h.Peerstore().LatencyEWMA(target)
	if ewma > 0 {
		// Calculate adaptive timeout: 4x RTT + 500ms safety buffer
		timeout := 4*ewma + 500*time.Millisecond
		// Bound it between 300ms and maxLimit
		if timeout < 300*time.Millisecond {
			timeout = 300 * time.Millisecond
		}
		if timeout > maxLimit {
			timeout = maxLimit
		}
		logger.Debug().
			Str("target", target.String()).
			Dur("ewma_rtt", ewma).
			Dur("calculated_timeout", timeout).
			Dur("max_limit", maxLimit).
			Msg("LOG_STEP: getPeerDialTimeout: Calculated timeout using stored EWMA latency")
		return timeout
	}

	// Fallback to active ping measurement if no EWMA latency is stored
	logger.Debug().Str("target", target.String()).Msg("LOG_STEP: getPeerDialTimeout: No EWMA latency stored, performing active ping...")
	pingCtx, pingCancel := context.WithTimeout(ctx, 1*time.Second)
	defer pingCancel()
	pings := ping.Ping(pingCtx, h, target)
	select {
	case res, ok := <-pings:
		if ok && res.Error == nil && res.RTT > 0 {
			timeout := 4*res.RTT + 500*time.Millisecond
			if timeout < 300*time.Millisecond {
				timeout = 300 * time.Millisecond
			}
			if timeout > maxLimit {
				timeout = maxLimit
			}
			logger.Debug().
				Str("target", target.String()).
				Dur("ping_rtt", res.RTT).
				Dur("calculated_timeout", timeout).
				Dur("max_limit", maxLimit).
				Msg("LOG_STEP: getPeerDialTimeout: Calculated timeout using active ping")
			return timeout
		}
	case <-pingCtx.Done():
	}

	// Default fallback timeout
	fallback := 3 * time.Second
	if fallback > maxLimit {
		fallback = maxLimit
	}
	logger.Debug().Str("target", target.String()).Dur("fallback", fallback).Msg("LOG_STEP: getPeerDialTimeout: Active ping failed or timed out, falling back to default")
	return fallback
}

func transmitEnvelope(ctx context.Context, h host.Host, target peer.ID, finalWireEnvelope string) error {
	startTransmit := time.Now()
	defer func() {
		logger.Info().Str("target", target.String()).Dur("elapsed", time.Since(startTransmit)).Msg("LOG_STEP: transmitEnvelope completed")
	}()

	if target == h.ID() {
		logger.Info().Msg("transmitEnvelope: Self-message detected, processing locally without network dial")
		go ProcessSecureEnvelope(ctx, h, h.ID(), finalWireEnvelope, "")
		return nil
	}

	// Cek apakah ada koneksi aktif ke peer tersebut (direct maupun via relay)
	isConnected := len(h.Network().ConnsToPeer(target)) > 0

	// FIX: Network switch — save the original (pre-signature-wrap) envelope
	// so we can retry direct delivery if the send fails on a stale connection.
	originalEnvelope := finalWireEnvelope
	directSendFailed := false

	var s network.Stream
	var err error

	if isConnected {
		logger.Info().Str("target", target.String()).Msg("LOG_STEP: transmitEnvelope: Active connection found, attempting direct stream dial...")
		dialTimeout := getPeerDialTimeout(ctx, h, target)
		logger.Info().Str("target", target.String()).Dur("timeout", dialTimeout).Msg("LOG_STEP: transmitEnvelope: Using calculated dial timeout")

		startDial := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		s, err = h.NewStream(dialCtx, target, MessagingProtocolID)
		cancel()
		logger.Info().Str("target", target.String()).Dur("elapsed", time.Since(startDial)).Err(err).Msg("LOG_STEP: transmitEnvelope: NewStream dial finished")

		if err == nil {
			logger.Debug().Str("target", target.String()).Msg("transmitEnvelope: Direct stream succeeded, writing envelope")
			s.SetWriteDeadline(time.Now().Add(1 * time.Second))
			startWrite := time.Now()
			errWrite := binary.Write(s, binary.LittleEndian, uint32(len(finalWireEnvelope)))
			if errWrite == nil {
				_, errWrite = s.Write([]byte(finalWireEnvelope))
			}
			logger.Info().Str("target", target.String()).Dur("elapsed", time.Since(startWrite)).Err(errWrite).Msg("LOG_STEP: transmitEnvelope: stream Write finished")

			if errWrite == nil {
				// Read ACK
				respReader := bufio.NewReader(s)
				s.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				startAck := time.Now()
				resp, errRead := respReader.ReadString('\n')
				logger.Info().Str("target", target.String()).Dur("elapsed", time.Since(startAck)).Err(errRead).Msg("LOG_STEP: transmitEnvelope: stream Read ACK finished")
				if errRead != nil || strings.TrimSpace(resp) != "OK" {
					errWrite = fmt.Errorf("did not receive ACK from target: %v", errRead)
				}
			}
			s.Close()
			if errWrite == nil {
				// Track outgoing bytes (4-byte length prefix + envelope payload)
				AddBytesSent(4 + len(finalWireEnvelope))

				// Determine connection type for routing logs
				routeType := "DIRECT (QUIC/UDP)"
				connType := "direct_quic"
				relayVia := ""
				conns := h.Network().ConnsToPeer(target)
				if len(conns) > 0 {
					addrStr := conns[0].RemoteMultiaddr().String()
					if strings.Contains(addrStr, "p2p-circuit") {
						routeType = "RELAYED (Circuit)"
						connType = "relay"
						parts := strings.Split(addrStr, "/")
						for i, part := range parts {
							if part == "p2p-circuit" && i >= 2 {
								for j := i - 1; j >= 0; j-- {
									if parts[j] == "p2p" && j+1 < i {
										relayVia = parts[j+1]
										break
									}
								}
								break
							}
						}
					} else if strings.Contains(addrStr, "webrtc-direct") {
						routeType = "DIRECT (WebRTC)"
						connType = "direct_webrtc"
					}
				}
				UpdatePeerActivity(target.String(), connType, relayVia)

				logger.Info().
					Str("peerID", target.String()).
					Str("route", routeType).
					Msg(">>> MESSAGE DELIVERED ONLINE")

				return nil
			}
			logger.Warn().Err(errWrite).Str("target", target.String()).Msg("transmitEnvelope: Direct write failed, falling back to mailbox")
			err = errWrite
			directSendFailed = true
		} else {
			logger.Warn().Err(err).Str("target", target.String()).Msg("transmitEnvelope: Dial stream failed, falling back to mailbox")
			directSendFailed = true
		}
	} else {
		logger.Info().Str("target", target.String()).Msg("transmitEnvelope: No active connection found, skipping dial and sending via offline mailbox")
	}

	// FIX: Network switch — if a connected peer's direct send failed (stale QUIC
	// connection during WiFi→mobile transition), store the original envelope in
	// the pending queue so it can be retried when the peer reconnects, instead
	// of being permanently lost if the mailbox also fails (e.g. no relay reachable).
	if isConnected && directSendFailed {
		enqueuePendingDirect(target.String(), originalEnvelope)
		logger.Info().
			Str("peerID", FormatPeerID(target.String())).
			Msg("transmitEnvelope: Stale-connection failure — envelope queued for reconnect retry")
	}

	// Wrap envelope with standard signature for spam-proof mailbox storage
	sigWrapped, errSig := WrapEnvelopeWithSignature(h.Peerstore().PrivKey(h.ID()), finalWireEnvelope)
	if errSig == nil {
		finalWireEnvelope = sigWrapped
	} else {
		logger.Warn().Err(errSig).Msg("Failed to wrap envelope with standard signature, sending unwrapped")
	}

	encodedEnvelope := base64.StdEncoding.EncodeToString([]byte(finalWireEnvelope))
	// Pass the actual marshalled public key (not the peer ID string) so the
	// receiver can correctly reconstruct the sender peer ID when fetching from mailbox.
	pubKeyBytes, errMarshal := crypto.MarshalPublicKey(h.Peerstore().PubKey(h.ID()))
	if errMarshal != nil {
		pubKeyBytes, _ = h.ID().MarshalBinary() // fallback: use raw peer ID bytes
	}
	senderPubkeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	logger.Info().
		Str("peerID", target.String()).
		Msg(">>> TARGET OFFLINE/UNREACHABLE: Storing message in offline mailbox")

	// Run mailbox storage in the background to avoid blocking the FFI / UI thread
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := StoreOfflineMessage(bgCtx, h, target, senderPubkeyB64, encodedEnvelope)
		if err != nil {
			logger.Warn().Err(err).Str("target", target.String()).Msg("Background StoreOfflineMessage failed")
		} else {
			logger.Info().
				Str("peerID", target.String()).
				Msg(">>> OFFLINE MAILBOX UPLOAD SUCCESSFUL")
		}
	}()
	return nil
}

func resolveTargetPeerID(ctx context.Context, h host.Host, targetStr string) (peer.ID, error) {
	// First, if it doesn't look like an alias (doesn't start with @), try to decode it directly
	if !strings.HasPrefix(targetStr, "@") {
		if targetID, err := peer.Decode(targetStr); err == nil {
			return targetID, nil
		}
	}

	// Otherwise, treat it as an alias (prepend @ if missing)
	aliasToResolve := targetStr
	if !strings.HasPrefix(aliasToResolve, "@") {
		aliasToResolve = "@" + aliasToResolve
	}

	// Exclude group aliases
	if _, errMeta := corestore.LoadGroupMetadata(aliasToResolve); errMeta == nil {
		return "", fmt.Errorf("'%s' is a group alias, cannot send private messages to it", aliasToResolve)
	}
	if meta, errGroup := ResolveGroupMetadata(ctx, h, aliasToResolve); errGroup == nil && meta.GroupID != "" {
		return "", fmt.Errorf("'%s' is a group alias, cannot send private messages to it", aliasToResolve)
	}

	resolved, err := ResolveAlias(ctx, h, aliasToResolve)
	if err != nil {
		return "", fmt.Errorf("failed to resolve alias %s: %w", aliasToResolve, err)
	}

	return peer.Decode(resolved)
}
