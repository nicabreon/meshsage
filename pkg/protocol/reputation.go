package protocol

import (
	"fmt"
	"sync"
)

var (
	// Blacklist stores PeerIDs that are blocked
	blacklist = make(map[string]bool)
	// ViolationCounter tracks how many bad requests a peer has sent
	violationCounter = make(map[string]int)
	reputationMu     sync.RWMutex
)

const MaxViolations = 5

// IsPeerBlocked checks if a peer is in the blacklist
func IsPeerBlocked(peerID string) bool {
	reputationMu.RLock()
	defer reputationMu.RUnlock()
	return blacklist[peerID]
}

// ReportViolation increments the violation count for a peer
func ReportViolation(peerID string, reason string) {
	reputationMu.Lock()
	defer reputationMu.Unlock()

	violationCounter[peerID]++
	fmt.Printf("[Reputation] Violation reported for %s: %s (Count: %d)\n", peerID, reason, violationCounter[peerID])

	if violationCounter[peerID] >= MaxViolations {
		blacklist[peerID] = true
		fmt.Printf("[Reputation] Peer %s has been BLACKLISTED due to excessive violations.\n", peerID)
	}
}

// ResetReputationSystem clears all violations and blocks (mainly for testing).
func ResetReputationSystem() {
	reputationMu.Lock()
	blacklist = make(map[string]bool)
	violationCounter = make(map[string]int)
	reputationMu.Unlock()
}
