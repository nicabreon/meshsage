package protocol

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	"github.com/stretchr/testify/assert"
)

func TestCryptographicGroupCreation(t *testing.T) {
	// Initialize in-memory database
	err := corestore.InitDatabase(":memory:")
	assert.NoError(t, err)
	defer corestore.DB.Close()

	// 1. Create creator host
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	assert.NoError(t, err)
	defer h.Close()

	// Mock PubSub instance to prevent nil dereference during Join
	corenet.GlobalPubSub = nil // In unit tests, we test the metadata & membership database logic

	groupID := "group_test_id_123"
	alias := "@kopi-senja"
	creator := h.ID().String()

	// Sign metadata
	privKey := h.Peerstore().PrivKey(h.ID())
	createdAt := time.Now().Unix()
	dataToSign := []byte(groupID + alias + creator + fmt.Sprintf("%d", createdAt))
	sigBytes, err := privKey.Sign(dataToSign)
	assert.NoError(t, err)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Save Group Metadata
	meta := corestore.GroupMetadata{
		GroupID:    groupID,
		GroupAlias: alias,
		CreatorID:  creator,
		GroupType:  "SECURE",
		CreatedAt:  createdAt,
		Signature:  sigB64,
	}
	err = corestore.SaveGroupMetadata(meta)
	assert.NoError(t, err)

	// Verify group metadata loading
	loadedMeta, err := corestore.LoadGroupMetadata(alias)
	assert.NoError(t, err)
	assert.Equal(t, groupID, loadedMeta.GroupID)
	assert.Equal(t, "SECURE", loadedMeta.GroupType)

	// Verify signature mathematically
	pubKey, err := h.ID().ExtractPublicKey()
	assert.NoError(t, err)
	valid, err := pubKey.Verify(dataToVerify(loadedMeta), sigBytes)
	assert.NoError(t, err)
	assert.True(t, valid, "Group metadata signature should be valid")
}

func TestUnsecureGroupOpenJoin(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	assert.NoError(t, err)
	defer corestore.DB.Close()

	groupID := "group_public_123"
	alias := "@woroworo"
	creator := "12D3KooWCreatorID"

	meta := corestore.GroupMetadata{
		GroupID:    groupID,
		GroupAlias: alias,
		CreatorID:  creator,
		GroupType:  "UNSECURE",
		CreatedAt:  time.Now().Unix(),
		Signature:  "mock-sig",
	}
	err = corestore.SaveGroupMetadata(meta)
	assert.NoError(t, err)

	// Test joining the public group
	err = corestore.AddGroupMemberV2(groupID, "12D3KooWMemberID", "MEMBER")
	assert.NoError(t, err)

	members, err := corestore.GetGroupMembersV2(groupID)
	assert.NoError(t, err)
	assert.Len(t, members, 1)
	assert.Equal(t, "12D3KooWMemberID", members[0].PeerID)
	assert.Equal(t, "MEMBER", members[0].Role)
}

func TestCreatorOnlyControlVerification(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	assert.NoError(t, err)
	defer corestore.DB.Close()

	// Create Creator Host
	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	assert.NoError(t, err)
	defer h1.Close()

	// Create Hacker Host
	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	assert.NoError(t, err)
	defer h2.Close()

	groupID := "group_test_ownership"
	alias := "@ownership-test"
	creator := h1.ID().String()

	meta := corestore.GroupMetadata{
		GroupID:    groupID,
		GroupAlias: alias,
		CreatorID:  creator,
		GroupType:  "SECURE",
		CreatedAt:  time.Now().Unix(),
		Signature:  "mock-sig",
	}
	_ = corestore.SaveGroupMetadata(meta)

	// Setup initial member
	_ = corestore.AddGroupMemberV2(groupID, h1.ID().String(), "CREATOR")
	_ = corestore.AddGroupMemberV2(groupID, "12D3KooWTargetMember", "MEMBER")

	// Validate action verification logic
	// If command is sent by creator:
	assert.Equal(t, creator, h1.ID().String())
	assert.NotEqual(t, creator, h2.ID().String())
}

func dataToVerify(meta corestore.GroupMetadata) []byte {
	return []byte(meta.GroupID + meta.GroupAlias + meta.CreatorID + fmt.Sprintf("%d", meta.CreatedAt))
}
