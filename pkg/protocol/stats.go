package protocol

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/nicabreon/meshsage/pkg/logger"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
)

// ----- Session-level atomic counters (reset to 0 on each StartNode) -----
var (
	statsBytesSent  int64 // atomic
	statsBytesRecv  int64 // atomic
	statsMsgSent    int64 // atomic
	statsMsgRecv    int64 // atomic
	statsHandshakes int64 // atomic
	statsFileSent   int64 // atomic
	statsFileRecv   int64 // atomic

	// Base values loaded from DB (cumulative from previous sessions)
	statsBaseSent       int64
	statsBaseRecv       int64
	statsBaseMsgSent    int64
	statsBaseMsgRecv    int64
	statsBaseHandshakes int64
	statsBaseFileSent   int64
	statsBaseFileRecv   int64

	statsSessionStart time.Time
)

// NetworkStatsJSON is the JSON payload returned via FFI to Flutter.
type NetworkStatsJSON struct {
	TotalSentBytes   int64 `json:"total_sent_bytes"`
	TotalRecvBytes   int64 `json:"total_recv_bytes"`
	SessionSentBytes int64 `json:"session_sent_bytes"`
	SessionRecvBytes int64 `json:"session_recv_bytes"`
	MsgSent          int64 `json:"msg_sent"`
	MsgRecv          int64 `json:"msg_recv"`
	Handshakes       int64 `json:"handshakes"`
	FileSentBytes    int64 `json:"file_sent_bytes"`
	FileRecvBytes    int64 `json:"file_recv_bytes"`
	UptimeSeconds    int64 `json:"uptime_seconds"`
}

// InitStats loads base counters from DB and starts the 30-second auto-save goroutine.
// Must be called once during StartNode, after the DB is initialized.
func InitStats() {
	statsSessionStart = time.Now()

	// Reset session counters
	atomic.StoreInt64(&statsBytesSent, 0)
	atomic.StoreInt64(&statsBytesRecv, 0)
	atomic.StoreInt64(&statsMsgSent, 0)
	atomic.StoreInt64(&statsMsgRecv, 0)
	atomic.StoreInt64(&statsHandshakes, 0)
	atomic.StoreInt64(&statsFileSent, 0)
	atomic.StoreInt64(&statsFileRecv, 0)

	// Load cumulative base from DB
	base, err := corestore.LoadNetworkStats()
	if err == nil {
		statsBaseSent = base[0]
		statsBaseRecv = base[1]
		statsBaseMsgSent = base[2]
		statsBaseMsgRecv = base[3]
		statsBaseHandshakes = base[4]
		statsBaseFileSent = base[5]
		statsBaseFileRecv = base[6]
		logger.Info().
			Int64("total_sent_mb", (statsBaseSent+base[0])/(1024*1024)).
			Msg("Network stats loaded from DB")
	}

	// Auto-save every 30 seconds to survive force close (max loss = 30s of data)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			SaveStatsNow()
		}
	}()
	logger.Info().Msg("Network stats tracking initialized (auto-save every 30s)")
}

// SaveStatsNow writes current totals (base + session delta) to DB immediately.
// Called by auto-save goroutine and by StopNode for a clean final flush.
func SaveStatsNow() {
	_ = corestore.SaveNetworkStats(
		statsBaseSent+atomic.LoadInt64(&statsBytesSent),
		statsBaseRecv+atomic.LoadInt64(&statsBytesRecv),
		statsBaseMsgSent+atomic.LoadInt64(&statsMsgSent),
		statsBaseMsgRecv+atomic.LoadInt64(&statsMsgRecv),
		statsBaseHandshakes+atomic.LoadInt64(&statsHandshakes),
		statsBaseFileSent+atomic.LoadInt64(&statsFileSent),
		statsBaseFileRecv+atomic.LoadInt64(&statsFileRecv),
	)
}

// ----- Tracking helpers called from messaging/file transfer code -----

// AddBytesSent records n bytes of outgoing network traffic.
func AddBytesSent(n int) { atomic.AddInt64(&statsBytesSent, int64(n)) }

// AddBytesRecv records n bytes of incoming network traffic.
func AddBytesRecv(n int) { atomic.AddInt64(&statsBytesRecv, int64(n)) }

// TrackMsgSent increments the outgoing message counter.
func TrackMsgSent() { atomic.AddInt64(&statsMsgSent, 1) }

// TrackMsgRecv increments the incoming message counter.
func TrackMsgRecv() { atomic.AddInt64(&statsMsgRecv, 1) }

// TrackHandshake increments the X3DH handshake counter.
func TrackHandshake() { atomic.AddInt64(&statsHandshakes, 1) }

// AddFileSent records n bytes of outgoing file transfer traffic.
func AddFileSent(n int64) { atomic.AddInt64(&statsFileSent, n) }

// AddFileRecv records n bytes of incoming file transfer traffic.
func AddFileRecv(n int64) { atomic.AddInt64(&statsFileRecv, n) }

// GetNetworkStatsJSON returns a JSON string of current cumulative stats for FFI.
func GetNetworkStatsJSON() string {
	sessionSent := atomic.LoadInt64(&statsBytesSent)
	sessionRecv := atomic.LoadInt64(&statsBytesRecv)

	s := NetworkStatsJSON{
		TotalSentBytes:   statsBaseSent + sessionSent,
		TotalRecvBytes:   statsBaseRecv + sessionRecv,
		SessionSentBytes: sessionSent,
		SessionRecvBytes: sessionRecv,
		MsgSent:          statsBaseMsgSent + atomic.LoadInt64(&statsMsgSent),
		MsgRecv:          statsBaseMsgRecv + atomic.LoadInt64(&statsMsgRecv),
		Handshakes:       statsBaseHandshakes + atomic.LoadInt64(&statsHandshakes),
		FileSentBytes:    statsBaseFileSent + atomic.LoadInt64(&statsFileSent),
		FileRecvBytes:    statsBaseFileRecv + atomic.LoadInt64(&statsFileRecv),
		UptimeSeconds:    int64(time.Since(statsSessionStart).Seconds()),
	}
	b, _ := json.Marshal(s)
	return string(b)
}
