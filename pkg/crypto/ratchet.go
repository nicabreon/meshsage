package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// SessionState represents the current state of a Double Ratchet session with a peer.
type SessionState struct {
	PeerID               string
	RemoteIdentityKey    []byte
	RootKey              []byte
	SendChainKey         []byte
	RecvChainKey         []byte
	RemoteRatchetPubkey  []byte
	LocalRatchetPrivkey  []byte
	LocalRatchetPubkey   []byte
	N                    uint32 // Message counter for current send chain
	M                    uint32 // Message counter for current receive chain
	PN                   uint32 // Number of messages in previous send chain
}

// EncryptWithRatchet advances the send chain and returns an encrypted message.
// In a full implementation, this would also include the current Ratchet Public Key in the header.
func (s *SessionState) EncryptWithRatchet(plaintext string) (string, error) {
	msgKey, nextChainKey, err := RatchetStep(s.SendChainKey)
	if err != nil { return "", err }
	
	s.SendChainKey = nextChainKey
	headerN := s.N
	headerPN := s.PN
	s.N++
	
	// Encrypt using the derived message key
	ciphertext, err := EncryptMessage(msgKey, plaintext)
	if err != nil { return "", err }
	
	// Header: RatchetPub|PN|N
	header := fmt.Sprintf("%s|%d|%d", base64.StdEncoding.EncodeToString(s.LocalRatchetPubkey), headerPN, headerN)
	return fmt.Sprintf("%s|%s", header, ciphertext), nil
}

// DecryptWithRatchet advances the receive chain and returns the decrypted plaintext.
// It returns (plaintext, skippedKeys, error). skippedKeys is a map of counter -> key for messages skipped.
func (s *SessionState) DecryptWithRatchet(payload string) (string, map[uint32][]byte, error) {
	parts := strings.SplitN(payload, "|", 4)
	if len(parts) != 4 {
		return "", nil, fmt.Errorf("invalid ratchet message format (expected 4 parts)")
	}
	
	remoteRatchetPub, _ := base64.StdEncoding.DecodeString(parts[0])
	pn, _ := strconv.ParseUint(parts[1], 10, 32)
	n, _ := strconv.ParseUint(parts[2], 10, 32)
	ciphertext := parts[3]
	
	skippedKeys := make(map[uint32][]byte)

	// 1. Handle DH Ratchet
	if !bytes.Equal(remoteRatchetPub, s.RemoteRatchetPubkey) {
		// 1.1 Skip remaining keys in current receive chain
		for s.M < uint32(pn) {
			msgKey, nextChainKey, _ := RatchetStep(s.RecvChainKey)
			skippedKeys[s.M] = msgKey
			s.RecvChainKey = nextChainKey
			s.M++
		}

		// 1.2 Advance DH Ratchet
		s.RemoteRatchetPubkey = remoteRatchetPub
		s.PN = s.N
		s.N = 0
		s.M = 0
		
		sharedSecret, _ := DeriveSharedSecret(s.LocalRatchetPrivkey, s.RemoteRatchetPubkey)
		res, _ := HKDFExpand(sharedSecret, "p2p-core-dh-ratchet", 64)
		s.RootKey = res[:32]
		s.RecvChainKey = res[32:]
		
		newPriv, newPub, _ := GenerateEphemeralKeypair()
		s.LocalRatchetPrivkey = newPriv
		s.LocalRatchetPubkey = newPub
	}
	
	// 2. Skip keys in current symmetric ratchet if n > s.M
	for s.M < uint32(n) {
		msgKey, nextChainKey, _ := RatchetStep(s.RecvChainKey)
		skippedKeys[s.M] = msgKey
		s.RecvChainKey = nextChainKey
		s.M++
	}

	// 3. Current message key
	msgKey, nextChainKey, err := RatchetStep(s.RecvChainKey)
	if err != nil { return "", nil, err }
	s.RecvChainKey = nextChainKey
	s.M++
	
	plaintext, err := DecryptMessage(msgKey, ciphertext)
	return plaintext, skippedKeys, err
}
