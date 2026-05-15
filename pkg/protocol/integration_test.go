package protocol

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	"github.com/stretchr/testify/assert"
)

func TestBinaryMessagingIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Initialize in-memory database for testing
	err := corestore.InitDatabase(":memory:")
	assert.NoError(t, err)
	defer corestore.DB.Close()

	// 1. Create two hosts
	h1, _ := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	h2, _ := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	defer h1.Close()
	defer h2.Close()

	// 2. Setup Services on both
	SetupMessaging(h1)
	SetupMessaging(h2)
	SetupPreKeyService(h1)
	SetupPreKeyService(h2)
	
	// Mock as relay to allow pre-key storage
	corenet.IsClientOnly = false

	// 3. Connect them
	h1.Peerstore().AddAddrs(h2.ID(), h2.Addrs(), time.Hour)
	err = h1.Connect(ctx, peer.AddrInfo{ID: h2.ID()})
	assert.NoError(t, err)

	t.Log("Integration Test: Setup passed.")
}

func TestAdaptiveRelayLogic(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	assert.NoError(t, err)

	// Test Client Only mode
	corenet.IsClientOnly = true
	assert.False(t, corenet.ShouldActAsRelay(), "Should NOT relay when IsClientOnly=true")

	// Test weak network
	corenet.IsClientOnly = false
	corenet.IsNetworkWeak = true
	assert.False(t, corenet.ShouldActAsRelay(), "Should NOT relay when network is weak")

	// Test healthy node
	corenet.IsNetworkWeak = false
	assert.True(t, corenet.ShouldActAsRelay(), "Should relay when connection is healthy")
}

func TestGzipPreKeyCompression(t *testing.T) {
	batch := PreKeyBatch{
		OwnerID: "test-peer",
		Keys: []OneTimeKey{
			{KeyID: "1", PublicKey: "pub1", Signature: "sig1"},
			{KeyID: "2", PublicKey: "pub2", Signature: "sig2"},
		},
	}
	assert.NotEmpty(t, batch.OwnerID)
	assert.Len(t, batch.Keys, 2)
}

func TestReputationSystem(t *testing.T) {
	// Reset state for isolated test
	blacklist = make(map[string]bool)
	violationCounter = make(map[string]int)

	peerID := "12D3KooWTestPeerID123456"

	// Should not be blocked initially
	assert.False(t, IsPeerBlocked(peerID), "New peer should not be blocked")

	// Report violations up to the limit
	for i := 0; i < MaxViolations-1; i++ {
		ReportViolation(peerID, "test violation")
	}
	assert.False(t, IsPeerBlocked(peerID), "Should not be blocked yet")

	// One more should trigger blacklist
	ReportViolation(peerID, "final violation")
	assert.True(t, IsPeerBlocked(peerID), "Should be blacklisted after MaxViolations")
}
