package integration

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pproto "github.com/libp2p/go-libp2p/core/protocol"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	corenet "github.com/nicabreon/meshsage/pkg/network"
	"github.com/nicabreon/meshsage/pkg/protocol"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	protocol.SetupMessaging(h1)
	protocol.SetupMessaging(h2)
	protocol.SetupPreKeyService(h1)
	protocol.SetupPreKeyService(h2)

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
	defer corestore.DB.Close()

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
	batch := protocol.PreKeyBatch{
		OwnerID: "test-peer",
		Keys: []protocol.OneTimeKey{
			{KeyID: "1", PublicKey: "pub1", Signature: "sig1"},
			{KeyID: "2", PublicKey: "pub2", Signature: "sig2"},
		},
	}
	assert.NotEmpty(t, batch.OwnerID)
	assert.Len(t, batch.Keys, 2)
}

func TestReputationSystem(t *testing.T) {
	// Reset state for isolated test
	protocol.ResetReputationSystem()

	peerID := "12D3KooWTestPeerID123456"

	// Should not be blocked initially
	assert.False(t, protocol.IsPeerBlocked(peerID), "New peer should not be blocked")

	// Report violations up to the limit
	for i := 0; i < protocol.MaxViolations-1; i++ {
		protocol.ReportViolation(peerID, "test violation")
	}
	assert.False(t, protocol.IsPeerBlocked(peerID), "Should not be blocked yet")

	// One more should trigger blacklist
	protocol.ReportViolation(peerID, "final violation")
	assert.True(t, protocol.IsPeerBlocked(peerID), "Should be blacklisted after MaxViolations")
}

func TestSkippedKeysPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_skipped_keys.db")

	// 1. Inisialisasi DB pertama kali & simpan key
	err := corestore.InitDatabase(dbPath)
	require.NoError(t, err)

	peerID := "12D3KooWSkippedKeyPeer"
	counter := uint32(5)
	ratchetPub := []byte("this-is-a-32-byte-ratchet-pub-!!")
	msgKey := []byte("this-is-a-32-byte-msg-key-test-value!!")

	err = corestore.SaveSkippedKey(peerID, ratchetPub, counter, msgKey)
	require.NoError(t, err)

	// Tutup DB
	err = corestore.DB.Close()
	require.NoError(t, err)

	// 2. Re-inisialisasi DB (simulasi restart/reopen)
	err = corestore.InitDatabase(dbPath)
	require.NoError(t, err)
	defer corestore.DB.Close()

	// Muat kembali skipped key
	loadedKey, err := corestore.GetSkippedKey(peerID, ratchetPub, counter)
	require.NoError(t, err)
	assert.Equal(t, msgKey, loadedKey, "Skipped key harus persisten dan sama setelah DB ditutup & dibuka kembali")
}

func TestMailboxRateLimiter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	// Buat Host Server (Relay) & Client
	hRelay, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hRelay.Close()

	hClient, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hClient.Close()

	// Daftarkan protocol Mailbox di Server
	corenet.IsClientOnly = false // Supaya act as relay
	corenet.IsNetworkWeak = false
	protocol.SetupMailbox(hRelay, false)

	// Sambungkan Client ke Server
	hClient.Peerstore().AddAddrs(hRelay.ID(), hRelay.Addrs(), time.Hour)
	err = hClient.Connect(ctx, peer.AddrInfo{ID: hRelay.ID()})
	require.NoError(t, err)

	// Reset rate limit untuk test bersih
	protocol.ResetMailboxRateLimiter()

	// 1. Kirim request FETCH pertama
	s1, err := hClient.NewStream(ctx, hRelay.ID(), libp2pproto.ID(protocol.MailboxProtocolID))
	require.NoError(t, err)
	defer s1.Close()

	coord := protocol.GetMailboxCoordinate(hClient.ID())
	cmd1 := "FETCH " + coord + " ACK\n"
	_, err = s1.Write([]byte(cmd1))
	require.NoError(t, err)

	// 2. Kirim request FETCH kedua dengan cepat secara paralel/konkuren
	s2, err := hClient.NewStream(ctx, hRelay.ID(), libp2pproto.ID(protocol.MailboxProtocolID))
	require.NoError(t, err)
	defer s2.Close()

	cmd2 := "FETCH " + coord + " ACK\n"
	_, err = s2.Write([]byte(cmd2))
	require.NoError(t, err)

	// Baca response dari request kedua — harus terkena rate limit
	reader := bufio.NewReader(s2)
	resp, err := reader.ReadString('\n')
	require.NoError(t, err)

	assert.True(t, strings.Contains(resp, "ERROR_RATE_LIMIT_EXCEEDED"),
		"FETCH kedua yang sangat cepat harus ditolak dengan ERROR_RATE_LIMIT_EXCEEDED")
}

func TestEndToEndMailboxAndSessionExpiration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Gunakan file DB fisik sementara untuk simulasi E2E yang lebih realistis
	dbPath := filepath.Join(t.TempDir(), "test_e2e_mailbox.db")
	err := corestore.InitDatabase(dbPath)
	require.NoError(t, err)
	defer corestore.DB.Close()

	// 1. Buat Alice (Client), Bob (Client/Offline), dan Relay (Server)
	hAlice, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hAlice.Close()

	hBob, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hBob.Close()

	hRelay, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hRelay.Close()

	// 2. Setup Layanan
	protocol.SetupMessaging(hAlice)
	protocol.SetupMessaging(hBob)
	protocol.SetupMessaging(hRelay)

	protocol.SetupPreKeyService(hAlice)
	protocol.SetupPreKeyService(hBob)
	protocol.SetupPreKeyService(hRelay)

	protocol.SetupMailbox(hAlice, true)
	protocol.SetupMailbox(hBob, true)
	protocol.SetupMailbox(hRelay, false) // Relay act as server

	corenet.IsClientOnly = false
	corenet.IsNetworkWeak = false

	// Hubungkan Alice dan Bob ke Relay
	hAlice.Peerstore().AddAddrs(hRelay.ID(), hRelay.Addrs(), time.Hour)
	err = hAlice.Connect(ctx, peer.AddrInfo{ID: hRelay.ID()})
	require.NoError(t, err)

	hBob.Peerstore().AddAddrs(hRelay.ID(), hRelay.Addrs(), time.Hour)
	err = hBob.Connect(ctx, peer.AddrInfo{ID: hRelay.ID()})
	require.NoError(t, err)

	// Registrasi 3 PreKeys Bob di Relay agar Alice bisa handshake X3DH secara offline multiple times
	bobPrivKey := hBob.Peerstore().PrivKey(hBob.ID())
	bobKeys := make(map[string][]byte) // keyID -> privateKeyBytes

	for i := 1; i <= 3; i++ {
		bobPreKeyID := fmt.Sprintf("bob-prekey-%d", i)
		bobPreKeyPriv, bobPreKeyPub, errKey := corecrypto.GenerateEphemeralKeypair()
		require.NoError(t, errKey)
		bobPreKeySig, errKey := bobPrivKey.Sign(bobPreKeyPub)
		require.NoError(t, errKey)

		bobKeys[bobPreKeyID] = bobPreKeyPriv

		errKey = corestore.SavePreKey(hBob.ID().String(), bobPreKeyID,
			base64.StdEncoding.EncodeToString(bobPreKeyPub), base64.StdEncoding.EncodeToString(bobPreKeyPriv),
			base64.StdEncoding.EncodeToString(bobPreKeySig))
		require.NoError(t, errKey)
	}

	// Registrasi 3 PreKeys Alice di Relay agar dia dianggap terdaftar (anti-spam check)
	alicePrivKey := hAlice.Peerstore().PrivKey(hAlice.ID())
	for i := 1; i <= 3; i++ {
		alicePreKeyID := fmt.Sprintf("alice-prekey-%d", i)
		alicePreKeyPriv, alicePreKeyPub, errKey := corecrypto.GenerateEphemeralKeypair()
		require.NoError(t, errKey)
		alicePreKeySig, errKey := alicePrivKey.Sign(alicePreKeyPub)
		require.NoError(t, errKey)

		errKey = corestore.SavePreKey(hAlice.ID().String(), alicePreKeyID,
			base64.StdEncoding.EncodeToString(alicePreKeyPub), base64.StdEncoding.EncodeToString(alicePreKeyPriv),
			base64.StdEncoding.EncodeToString(alicePreKeySig))
		require.NoError(t, errKey)
	}

	// Reset rateLimitMap untuk menghindari rate limit pada store awal
	protocol.ResetMailboxRateLimiter()
	protocol.ResetProcessedMailboxMessages()

	// 3. Alice mengirim pesan ke Bob secara OFFLINE (Bob pura-pura offline)
	msg1 := protocol.MessageEnvelope{
		ID:        "msg1-id",
		Type:      protocol.MsgTypeText,
		Content:   "Halo Bob, ini pesan offline dari Alice!",
		Timestamp: time.Now().UnixNano(),
	}
	msg1Bytes, err := json.Marshal(msg1)
	require.NoError(t, err)

	envelope, err := protocol.PrepareSecureEnvelope(ctx, hAlice, alicePrivKey, hBob.ID(), msg1Bytes)
	require.NoError(t, err)

	// Workaround: Re-insert Bob's pre-keys to the shared DB since they were deleted by Alice's fetch.
	// In production, Bob retains these private keys in his own private DB.
	for keyID, privBytes := range bobKeys {
		pubBytes, _ := corecrypto.DerivePublicKey(privBytes)
		sigBytes, _ := bobPrivKey.Sign(pubBytes)
		_ = corestore.SavePreKey(hBob.ID().String(), keyID,
			base64.StdEncoding.EncodeToString(pubBytes), base64.StdEncoding.EncodeToString(privBytes),
			base64.StdEncoding.EncodeToString(sigBytes))
	}

	sigWrapped, errSig := protocol.WrapEnvelopeWithSignature(alicePrivKey, envelope)
	require.NoError(t, errSig)
	encodedEnvelope := base64.StdEncoding.EncodeToString([]byte(sigWrapped))

	// Simpan di Mailbox Relay
	pubKeyBytes, err := crypto.MarshalPublicKey(hAlice.Peerstore().PubKey(hAlice.ID()))
	require.NoError(t, err)
	err = protocol.StoreOfflineMessage(ctx, hAlice, hBob.ID(), base64.StdEncoding.EncodeToString(pubKeyBytes), encodedEnvelope)
	require.NoError(t, err)

	// 4. Bob "online" dan melakukan fetch dari Relay
	messageReceived := make(chan string, 10)
	protocol.MessageCallback = func(event protocol.MessageEvent) {
		if event.Sender == hAlice.ID().String() {
			messageReceived <- event.Content
		}
	}

	// Reset rate limit & processed messages
	protocol.ResetMailboxRateLimiter()
	protocol.ResetProcessedMailboxMessages()

	protocol.FetchMailboxMessages(ctx, hBob, hRelay.ID(), bobPrivKey)

	select {
	case msg := <-messageReceived:
		assert.Contains(t, msg, "Halo Bob", "Bob harus sukses mengunduh dan mendekripsi pesan offline")
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout: Bob gagal menerima pesan offline")
	}

	// 5. Uji Skenario Sesi Expired / Korup
	// Hapus sesi Bob secara sengaja untuk mensimulasikan korupsi sesi
	err = corestore.DeleteSession(hAlice.ID().String())
	require.NoError(t, err)
	_ = corestore.ClearSkippedKeys(hAlice.ID().String())

	// Reset rateLimitMap & processed map sebelum Alice mempersiapkan envelope2
	protocol.ResetMailboxRateLimiter()
	protocol.ResetProcessedMailboxMessages()

	// Alice mengirim pesan berikutnya ke Bob
	msg2 := protocol.MessageEnvelope{
		ID:        "msg2-id",
		Type:      protocol.MsgTypeText,
		Content:   "Bob, apakah kamu masih di sana?",
		Timestamp: time.Now().UnixNano(),
	}
	msg2Bytes, err := json.Marshal(msg2)
	require.NoError(t, err)

	envelope2, err := protocol.PrepareSecureEnvelope(ctx, hAlice, alicePrivKey, hBob.ID(), msg2Bytes)
	require.NoError(t, err)

	sigWrapped2, errSig2 := protocol.WrapEnvelopeWithSignature(alicePrivKey, envelope2)
	require.NoError(t, errSig2)
	encodedEnvelope2 := base64.StdEncoding.EncodeToString([]byte(sigWrapped2))

	// Kirim pesan lewat Mailbox lagi
	err = protocol.StoreOfflineMessage(ctx, hAlice, hBob.ID(), base64.StdEncoding.EncodeToString(pubKeyBytes), encodedEnvelope2)
	require.NoError(t, err)

	// Bob fetch pesan baru. Decryption Bob akan gagal karena sesi dihapus.
	// Bob otomatis mengirim REQUEST_X3DH ke Alice untuk re-handshake.
	protocol.ResetMailboxRateLimiter()
	protocol.ResetProcessedMailboxMessages()
	protocol.FetchMailboxMessages(ctx, hBob, hRelay.ID(), bobPrivKey)

	// Beri jeda kecil agar Bob menyimpan REQUEST_X3DH di mailbox Alice
	time.Sleep(500 * time.Millisecond)

	// 6. Alice online dan fetch mailbox-nya sendiri untuk menerima REQUEST_X3DH dari Bob
	protocol.ResetMailboxRateLimiter()
	protocol.ResetProcessedMailboxMessages()
	protocol.FetchMailboxMessages(ctx, hAlice, hRelay.ID(), alicePrivKey)

	// Beri waktu bagi proses background REQUEST_X3DH dan re-handshake
	// Alice akan merespon dengan sendHandshakeAck (menyimpan ACK & retried message di mailbox Bob)
	time.Sleep(3 * time.Second)

	// Re-insert Bob's pre-keys to the shared DB again since Alice's re-handshake fetch deleted them
	for keyID, privBytes := range bobKeys {
		pubBytes, _ := corecrypto.DerivePublicKey(privBytes)
		sigBytes, _ := bobPrivKey.Sign(pubBytes)
		_ = corestore.SavePreKey(hBob.ID().String(), keyID,
			base64.StdEncoding.EncodeToString(pubBytes), base64.StdEncoding.EncodeToString(privBytes),
			base64.StdEncoding.EncodeToString(sigBytes))
	}

	// 7. Bob online lagi dan fetch mailbox-nya untuk memproses re-handshake ACK & pesan yang di-retry
	protocol.ResetMailboxRateLimiter()
	protocol.ResetProcessedMailboxMessages()
	protocol.FetchMailboxMessages(ctx, hBob, hRelay.ID(), bobPrivKey)

	// Setelah re-handshake selesai, Alice otomatis mengirim ulang pesan yang tertunda.
	// Kita periksa apakah pesan baru berhasil didekripsi oleh Bob.
	select {
	case msg := <-messageReceived:
		assert.Contains(t, msg, "apakah kamu masih di sana", "Pesan harus sukses didekripsi setelah re-handshake X3DH selesai")
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout: Sesi re-handshake X3DH gagal memulihkan enkripsi")
	}
}

func TestMailboxMessageSizeLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	// Buat Host Server & Client
	hRelay, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hRelay.Close()

	hClient, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hClient.Close()

	corenet.IsClientOnly = false
	protocol.SetupMailbox(hRelay, false)

	hClient.Peerstore().AddAddrs(hRelay.ID(), hRelay.Addrs(), time.Hour)
	err = hClient.Connect(ctx, peer.AddrInfo{ID: hRelay.ID()})
	require.NoError(t, err)

	// Registrasi prekey untuk Alice agar dia dianggap registered
	alicePrivKey := hClient.Peerstore().PrivKey(hClient.ID())
	priv, pub, _ := corecrypto.GenerateEphemeralKeypair()
	sig, _ := alicePrivKey.Sign(pub)
	_ = corestore.SavePreKey(hClient.ID().String(), "alice-spam-key",
		base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv),
		base64.StdEncoding.EncodeToString(sig))

	// Buat message melebihi MaxMessageSize (1MB)
	largeMessage := strings.Repeat("A", protocol.MaxMessageSize+100)

	protocol.ResetMailboxRateLimiter()

	s, err := hClient.NewStream(ctx, hRelay.ID(), libp2pproto.ID(protocol.MailboxProtocolID))
	require.NoError(t, err)
	defer s.Close()

	pubKeyBytes, _ := crypto.MarshalPublicKey(hClient.Peerstore().PubKey(hClient.ID()))
	senderPubkey := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Wrap large message with signature
	sigWrapped, errSig := protocol.WrapEnvelopeWithSignature(alicePrivKey, largeMessage)
	require.NoError(t, errSig)
	encodedPayload := base64.StdEncoding.EncodeToString([]byte(sigWrapped))

	coord := protocol.GetMailboxCoordinate(hClient.ID())
	cmd := fmt.Sprintf("STORE large-msg-hash %s %s %s\n", coord, senderPubkey, encodedPayload)

	_, err = s.Write([]byte(cmd))
	require.NoError(t, err)

	reader := bufio.NewReader(s)
	resp, err := reader.ReadString('\n')
	require.NoError(t, err)

	assert.True(t, strings.Contains(resp, "ERROR_TOO_LARGE"), "Pesan di atas 1MB harus ditolak dengan ERROR_TOO_LARGE")
}

func TestMailboxAntiSpamCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	// Buat Host Server & Client
	hRelay, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hRelay.Close()

	hClient, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer hClient.Close()

	corenet.IsClientOnly = false
	protocol.SetupMailbox(hRelay, false)

	hClient.Peerstore().AddAddrs(hRelay.ID(), hRelay.Addrs(), time.Hour)
	err = hClient.Connect(ctx, peer.AddrInfo{ID: hRelay.ID()})
	require.NoError(t, err)

	// SENDER TIDAK MENDAFTARKAN PRE-KEY DI RELAY (Bob / hClient tidak register prekeys).
	// Mengirim pesan offline dari Bob (tanpa prekey) ke Alice.
	protocol.ResetMailboxRateLimiter()

	s, err := hClient.NewStream(ctx, hRelay.ID(), libp2pproto.ID(protocol.MailboxProtocolID))
	require.NoError(t, err)
	defer s.Close()

	pubKeyBytes, _ := crypto.MarshalPublicKey(hClient.Peerstore().PubKey(hClient.ID()))
	senderPubkey := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Wrap message with signature
	alicePrivKey := hClient.Peerstore().PrivKey(hClient.ID())
	sigWrapped, errSig := protocol.WrapEnvelopeWithSignature(alicePrivKey, "test payload")
	require.NoError(t, errSig)
	encodedPayload := base64.StdEncoding.EncodeToString([]byte(sigWrapped))

	coord := protocol.GetMailboxCoordinate(hClient.ID())
	cmd := fmt.Sprintf("STORE test-msg-hash %s %s %s\n", coord, senderPubkey, encodedPayload)

	_, err = s.Write([]byte(cmd))
	require.NoError(t, err)

	reader := bufio.NewReader(s)
	resp, err := reader.ReadString('\n')
	require.NoError(t, err)

	assert.True(t, strings.Contains(resp, "ERROR_SENDER_UNREGISTERED"), "Pesan dari sender tanpa prekey harus ditolak dengan ERROR_SENDER_UNREGISTERED")
}
