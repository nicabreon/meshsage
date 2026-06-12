package protocol

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/nicabreon/meshsage/pkg/logger"
)

const MessagingProtocolID = "/p2p-core/msg/1.0.0"

// sessionLocks menyimpan mutex per-peer untuk mencegah race condition
// saat concurrent goroutine mengakses Double Ratchet session state.
var (
	sessionLocks        sync.Map // map[peerID string]*sync.Mutex
	x3dhRequestCooldown sync.Map // map[peerID string]time.Time
)

type PeerActivityInfo struct {
	LastSeen time.Time
	Type     string
	RelayVia string
}

var (
	PeerActivityMap = make(map[string]PeerActivityInfo)
	PeerActivityMu  sync.RWMutex
)

func UpdatePeerActivity(peerID string, connType string, relayVia string) {
	PeerActivityMu.Lock()
	defer PeerActivityMu.Unlock()
	PeerActivityMap[peerID] = PeerActivityInfo{
		LastSeen: time.Now(),
		Type:     connType,
		RelayVia: relayVia,
	}
}

func GetPeerActivity(peerID string) (PeerActivityInfo, bool) {
	PeerActivityMu.RLock()
	defer PeerActivityMu.RUnlock()
	act, found := PeerActivityMap[peerID]
	return act, found
}

// sentMsg adalah pesan yang sudah dikirim oleh node ini, disimpan untuk kemungkinan retry
// jika receiver mengalami masalah sesi dan meminta X3DH ulang.
type sentMsg struct {
	env    MessageEnvelope
	sentAt time.Time
}

const (
	maxSentPerPeer = 20               // max pesan tersimpan per peer
	sentMsgTTL     = 10 * time.Minute // pesan lebih lama dari ini tidak di-retry
)

var (
	sentMsgMu  sync.Mutex
	sentMsgBuf = make(map[string][]sentMsg) // peerID → []sentMsg
)

// trackSentMessage menyimpan pesan yang baru dikirim ke buffer per-peer.
// Dipanggil oleh SendMessage setelah berhasil mengirim.
func trackSentMessage(peerID string, env MessageEnvelope) {
	sentMsgMu.Lock()
	defer sentMsgMu.Unlock()

	list := sentMsgBuf[peerID]
	now := time.Now()
	// Buang yang sudah kadaluarsa
	filtered := list[:0]
	for _, m := range list {
		if now.Sub(m.sentAt) < sentMsgTTL {
			filtered = append(filtered, m)
		}
	}
	// Jaga batas ukuran: hapus yang terlama
	if len(filtered) >= maxSentPerPeer {
		filtered = filtered[1:]
	}
	filtered = append(filtered, sentMsg{env: env, sentAt: now})
	sentMsgBuf[peerID] = filtered
}

// retrySentMessages dipanggil saat REQUEST_X3DH diterima dari peer.
// Setelah X3DH baru berhasil dibentuk, kirim ulang semua pesan yang
// sebelumnya sudah dikirim ke peer tersebut dalam TTL window.
func retrySentMessages(ctx context.Context, h host.Host, priv crypto.PrivKey, targetID peer.ID) {
	peerID := targetID.String()
	sentMsgMu.Lock()
	list, ok := sentMsgBuf[peerID]
	if !ok || len(list) == 0 {
		sentMsgMu.Unlock()
		return
	}
	now := time.Now()
	toResend := make([]MessageEnvelope, 0, len(list))
	for _, m := range list {
		if now.Sub(m.sentAt) < sentMsgTTL {
			toResend = append(toResend, m.env)
		}
	}
	// Hapus buffer setelah diambil
	delete(sentMsgBuf, peerID)
	sentMsgMu.Unlock()

	if len(toResend) == 0 {
		return
	}
	logger.Info().Str("peerID", peerID[:8]).Int("count", len(toResend)).Msg("Retrying sent messages after X3DH re-handshake")
	for _, env := range toResend {
		// Jeda kecil agar session state sudah tersimpan ke DB
		time.Sleep(80 * time.Millisecond)
		if err := sendSecureEnvelope(ctx, h, priv, targetID, env); err != nil {
			logger.Warn().Err(err).Str("peerID", peerID[:8]).Str("msgID", env.ID).Msg("Retry sent message failed")
		} else {
			logger.Info().Str("peerID", peerID[:8]).Str("msgID", env.ID).Msg("Sent message retried successfully after X3DH")
		}
	}
}

// getSessionLock mengembalikan mutex khusus untuk peerID tertentu.
func getSessionLock(peerID string) *sync.Mutex {
	val, _ := sessionLocks.LoadOrStore(peerID, &sync.Mutex{})
	return val.(*sync.Mutex)
}

func SetupMessaging(h host.Host) {
	h.SetStreamHandler(MessagingProtocolID, func(s network.Stream) {
		handleStream(h, s)
	})
}

func handleStream(h host.Host, s network.Stream) {
	defer s.Close()
	senderID := s.Conn().RemotePeer()

	buf := bufio.NewReader(s)
	var length uint32
	if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
		logger.Warn().Err(err).Msg("handleStream: failed to read length prefix")
		return
	}

	envelopeBytes := make([]byte, length)
	if _, err := io.ReadFull(buf, envelopeBytes); err != nil {
		logger.Warn().Err(err).Msg("handleStream: failed to read envelope payload")
		return
	}

	// Track incoming bytes (4-byte length prefix + envelope payload)
	AddBytesRecv(4 + len(envelopeBytes))

	ProcessSecureEnvelope(context.Background(), h, senderID, string(envelopeBytes), "")

	// Kirim balik "OK\n" sebagai tanda terima (ACK)
	_, _ = s.Write([]byte("OK\n"))
}
