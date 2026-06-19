package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/nicabreon/meshsage/pkg/logger"
)

const TimeProtocolID = "/meshsage/time/1.0.0"

var (
	timeOffset      time.Duration
	timeOffsetMutex sync.RWMutex
)

// GetVirtualTime returns the current local system time adjusted by the calculated offset
func GetVirtualTime() time.Time {
	timeOffsetMutex.RLock()
	offset := timeOffset
	timeOffsetMutex.RUnlock()
	return time.Now().Add(offset)
}

// SetVirtualTimeOffset sets the clock offset to adjust the local system clock
func SetVirtualTimeOffset(offset time.Duration) {
	timeOffsetMutex.Lock()
	timeOffset = offset
	timeOffsetMutex.Unlock()
}

type TimeRequest struct {
	Version      string `json:"version"`
	ClientTimeMs int64  `json:"client_time_ms"`
}

type TimeResponse struct {
	Version     string `json:"version"`
	RelayTimeMs int64  `json:"relay_time_ms"`
}

// SetupTimeService registers the /meshsage/time/1.0.0 protocol handler on the host
func SetupTimeService(h host.Host, isDedicated bool) {
	if isDedicated {
		// Start periodic NTP synchronization
		StartNTPPeriodicSync(context.Background())
	}

	h.SetStreamHandler(TimeProtocolID, func(s network.Stream) {
		defer s.Close()
		buf := bufio.NewReader(s)
		reqLine, err := buf.ReadString('\n')
		if err != nil {
			return
		}
		reqLine = strings.TrimSpace(reqLine)

		var req TimeRequest
		if err := json.Unmarshal([]byte(reqLine), &req); err != nil {
			return
		}

		resp := TimeResponse{
			Version:     "1.0.0",
			RelayTimeMs: GetVirtualTime().UnixNano() / int64(time.Millisecond),
		}

		respBytes, err := json.Marshal(resp)
		if err != nil {
			return
		}

		_, _ = s.Write(append(respBytes, '\n'))
	})
}

// QueryNTP queries an NTP server and returns the absolute network time
func QueryNTP(server string) (time.Time, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	req := make([]byte, 48)
	req[0] = 0x1B // client mode, version 3

	if _, err := conn.Write(req); err != nil {
		return time.Time{}, err
	}

	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return time.Time{}, err
	}

	sec := uint64(resp[40])<<24 | uint64(resp[41])<<16 | uint64(resp[42])<<8 | uint64(resp[43])
	frac := uint64(resp[44])<<24 | uint64(resp[45])<<16 | uint64(resp[46])<<8 | uint64(resp[47])

	const ntpEpochOffset = 2208988800
	unixSec := int64(sec - ntpEpochOffset)
	nanosec := int64(frac * 1e9 >> 32)

	return time.Unix(unixSec, nanosec), nil
}

// StartNTPPeriodicSync periodically syncs the relay's offset using public NTP servers
func StartNTPPeriodicSync(ctx context.Context) {
	go func() {
		for {
			t, err := QueryNTP("pool.ntp.org:123")
			if err != nil {
				t, err = QueryNTP("time.google.com:123")
			}

			if err == nil {
				offset := t.Sub(time.Now())
				SetVirtualTimeOffset(offset)
				logger.Info().Str("offset", offset.String()).Msg("NTP SYNC: Successfully synced with NTP server")
			} else {
				logger.Error().Err(err).Msg("NTP SYNC: Failed to sync with public NTP servers")
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Hour):
			}
		}
	}()
}

// SyncTimeWithRelays queries all seed peers, calculates estimated times and updates the local virtual clock offset using the median
func SyncTimeWithRelays(ctx context.Context, h host.Host, seedIDs []peer.ID) {
	if len(seedIDs) == 0 {
		return
	}

	var offsets []time.Duration
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range seedIDs {
		if p == h.ID() {
			continue
		}
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()

			dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			s, err := h.NewStream(dialCtx, peerID, TimeProtocolID)
			if err != nil {
				return
			}
			defer s.Close()

			t1 := time.Now()
			req := TimeRequest{
				Version:      "1.0.0",
				ClientTimeMs: t1.UnixNano() / int64(time.Millisecond),
			}
			reqBytes, _ := json.Marshal(req)
			_, _ = s.Write(append(reqBytes, '\n'))

			buf := bufio.NewReader(s)
			respLine, err := buf.ReadString('\n')
			if err != nil {
				return
			}
			t2 := time.Now()

			var resp TimeResponse
			if err := json.Unmarshal([]byte(strings.TrimSpace(respLine)), &resp); err != nil {
				return
			}

			rtt := t2.Sub(t1)
			relayTime := time.Unix(0, resp.RelayTimeMs*int64(time.Millisecond))
			estimatedRelayTime := relayTime.Add(rtt / 2)
			offset := estimatedRelayTime.Sub(t2)

			mu.Lock()
			offsets = append(offsets, offset)
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	if len(offsets) == 0 {
		logger.Warn().Msg("TIME SYNC: Failed to sync time with any seed peer")
		return
	}

	sortOffsets(offsets)
	medianOffset := offsets[len(offsets)/2]

	SetVirtualTimeOffset(medianOffset)
	logger.Info().Str("offset", medianOffset.String()).Msg("TIME SYNC: Successfully synchronized virtual clock with seeds")
}

func sortOffsets(offsets []time.Duration) {
	for i := 0; i < len(offsets); i++ {
		for j := i + 1; j < len(offsets); j++ {
			if offsets[i] > offsets[j] {
				offsets[i], offsets[j] = offsets[j], offsets[i]
			}
		}
	}
}
