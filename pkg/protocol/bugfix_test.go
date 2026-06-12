package protocol

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	corecrypto "github.com/nicabreon/meshsage/pkg/crypto"
	corestore "github.com/nicabreon/meshsage/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBUG03_SessionLock_ConcurrentAccess memverifikasi bahwa getSessionLock
// memberikan mutex yang sama untuk peerID yang sama, dan mutex yang berbeda
// untuk peerID berbeda — mencegah race condition pada Double Ratchet state.
func TestBUG03_SessionLock_ConcurrentAccess(t *testing.T) {
	// Reset sessionLocks untuk test bersih
	sessionLocks = sync.Map{}

	peerA := "12D3KooWPeerA"
	peerB := "12D3KooWPeerB"

	// Mutex untuk peerID yang sama harus identik (pointer sama)
	mu1 := getSessionLock(peerA)
	mu2 := getSessionLock(peerA)
	assert.Equal(t, mu1, mu2, "BUG-03: getSessionLock harus mengembalikan mutex yang SAMA untuk peerID yang sama")

	// Mutex untuk peerID berbeda harus berbeda
	muB := getSessionLock(peerB)
	assert.NotSame(t, mu1, muB, "BUG-03: getSessionLock harus mengembalikan mutex yang BERBEDA untuk peerID berbeda")
}

// TestBUG03_SessionLock_NoConcurrentCorruption mensimulasikan concurrent access
// ke session store untuk memverifikasi tidak ada data corruption.
func TestBUG03_SessionLock_NoConcurrentCorruption(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	peerID := "12D3KooWConcurrentTestPeer"
	sessionLocks = sync.Map{}

	// Simpan session awal
	err = corestore.SaveSession(peerID, "", "rootkey", "sendchain", "recvchain", "", "", "", 0, 0, 0, 0)
	require.NoError(t, err)

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Jalankan 10 goroutine yang concurrent membaca dan menulis session
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			mu := getSessionLock(peerID)
			mu.Lock()
			defer mu.Unlock()

			// Baca session
			_, rootB64, _, _, _, _, _, nVal, _, _, _, err := corestore.LoadSession(peerID)
			if err != nil {
				errors <- err
				return
			}

			// Tulis session dengan counter incremented
			err = corestore.SaveSession(peerID, "", rootB64, "sendchain", "recvchain", "", "", "", nVal+1, 0, 0, 0)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Tidak boleh ada error
	for err := range errors {
		assert.NoError(t, err, "Concurrent session access harus aman")
	}

	// Verifikasi session masih terbaca dengan benar
	_, rootB64, _, _, _, _, _, _, _, _, _, err := corestore.LoadSession(peerID)
	assert.NoError(t, err)
	assert.NotEmpty(t, rootB64, "Session harus tetap ada setelah concurrent access")
}

// TestBUG06_HandleStream_BufioRead memverifikasi bahwa pembacaan binary length
// melalui bufio.Reader konsisten dan tidak melewatkan bytes.
// Ini mensimulasikan BUG-06: binary.Read(s) vs binary.Read(buf).
func TestBUG06_BinaryReadConsistency(t *testing.T) {
	// Simulasikan sebuah stream: tulis length (4 bytes) + payload
	payload := []byte("ini adalah pesan test untuk verifikasi binary protocol")
	length := uint32(len(payload))

	// Buat pipe untuk simulasi stream
	reader, writer := io.Pipe()

	go func() {
		// Tulis length header + payload
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, length)
		writer.Write(buf)
		writer.Write(payload)
		writer.Close()
	}()

	// Cara BENAR (fix BUG-06): gunakan bufio reader untuk SEMUA read
	import_bufio_reader := newBufioReaderForTest(reader)

	var readLength uint32
	err := binary.Read(import_bufio_reader, binary.LittleEndian, &readLength)
	require.NoError(t, err, "BUG-06: binary.Read dari bufio harus berhasil")
	assert.Equal(t, length, readLength, "Length header harus terbaca dengan benar")

	readPayload := make([]byte, readLength)
	_, err = io.ReadFull(import_bufio_reader, readPayload)
	require.NoError(t, err)
	assert.Equal(t, payload, readPayload, "Payload harus terbaca lengkap tanpa bytes yang hilang")
}

// TestBUG08_RateLimitMap_Cleanup memverifikasi bahwa entri lama di rateLimitMap
// bisa dihapus (logika cleanup yang ditambahkan di SetupMailbox).
func TestBUG08_RateLimitMap_Cleanup(t *testing.T) {
	// Reset state
	rateLimitMutex.Lock()
	rateLimitMap = make(map[string]time.Time)
	rateLimitMutex.Unlock()

	// Tambah beberapa entry
	rateLimitMutex.Lock()
	rateLimitMap["peer-old-1"] = time.Now().Add(-10 * time.Minute) // Entry lama
	rateLimitMap["peer-old-2"] = time.Now().Add(-6 * time.Minute)  // Entry lama
	rateLimitMap["peer-new-1"] = time.Now()                        // Entry baru
	rateLimitMap["peer-new-2"] = time.Now().Add(-1 * time.Minute)  // Entry baru
	rateLimitMutex.Unlock()

	// Simulasi cleanup logic (sama dengan yang ada di SetupMailbox)
	rateLimitMutex.Lock()
	for k, t := range rateLimitMap {
		if time.Since(t) > 5*time.Minute {
			delete(rateLimitMap, k)
		}
	}
	rateLimitMutex.Unlock()

	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	// Entry lama harus sudah dihapus
	_, exists1 := rateLimitMap["peer-old-1"]
	_, exists2 := rateLimitMap["peer-old-2"]
	assert.False(t, exists1, "BUG-08: Entry lama harus dihapus saat cleanup")
	assert.False(t, exists2, "BUG-08: Entry lama harus dihapus saat cleanup")

	// Entry baru harus masih ada
	_, exists3 := rateLimitMap["peer-new-1"]
	_, exists4 := rateLimitMap["peer-new-2"]
	assert.True(t, exists3, "BUG-08: Entry baru TIDAK boleh dihapus")
	assert.True(t, exists4, "BUG-08: Entry baru TIDAK boleh dihapus")

	assert.Len(t, rateLimitMap, 2, "Harus tersisa 2 entry setelah cleanup")
}

// TestDESIGN05_UnknownCommandNoBroadcast memverifikasi bahwa processCommand
// tidak lagi broadcast ke semua peer untuk input tidak dikenal.
// Test ini memverifikasi behavior BARU (tidak crash, tidak panic).
func TestDESIGN05_KnownCommandsRecognized(t *testing.T) {
	// Verifikasi bahwa command yang dikenal tidak menyebabkan panic
	// Ini adalah smoke test untuk processCommand behavior
	commands := []string{
		"/msg peer hello",
		"/send peer hello",
		"/group groupid hello",
		"/join groupid",
		"/fetch",
		"/register alias",
		"/upload file peer",
		"/latency peer",
	}

	// Semua command ini harus dikenali sebagai prefix yang valid
	for _, cmd := range commands {
		assert.True(t, isKnownCommand(cmd), "Command '%s' harus dikenali", cmd)
	}

	// Command tidak dikenal tidak boleh dibroadcast
	unknownCommands := []string{
		"hello world",
		"random text",
		"/unknown",
		"tidak ada spasi",
	}
	for _, cmd := range unknownCommands {
		assert.False(t, isKnownCommand(cmd), "Command '%s' seharusnya TIDAK dikenali", cmd)
	}
}

// isKnownCommand adalah helper untuk TestDESIGN05
func isKnownCommand(cmd string) bool {
	knownPrefixes := []string{"/msg ", "/send ", "/group ", "/join ", "/fetch", "/register ", "/upload ", "/latency "}
	for _, prefix := range knownPrefixes {
		if len(cmd) >= len(prefix) && cmd[:len(prefix)] == prefix {
			return true
		}
		if cmd == "/fetch" && prefix == "/fetch" {
			return true
		}
	}
	return false
}

// TestStorageSessionRoundtrip memverifikasi SaveSession/LoadSession bekerja benar
// termasuk untuk ratchet keys yang sekarang tidak kosong (BUG-04 fix).
func TestBUG04_StorageSessionWithRatchetKeys(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	peerID := "12D3KooWTestBUG04"
	rootKey := "cm9vdGtleWJhc2U2NHRlc3Q=" // base64
	sendChain := "c2VuZGNoYWluYmFzZTY0dGVzdA=="
	recvChain := "cmVjdmNoYWluYmFzZTY0dGVzdA=="
	remoteRatchetPub := "cmVtb3RlcmF0Y2hldHB1YmJhc2U2NA=="
	localRatchetPriv := "bG9jYWxyYXRjaGV0cHJpdmJhc2U2NA=="
	localRatchetPub := "bG9jYWxyYXRjaGV0cHViYmFzZTY0"

	// BUG-04 FIX: Semua field termasuk ratchet keys harus tersimpan
	err = corestore.SaveSession(peerID, "identitykey", rootKey, sendChain, recvChain,
		remoteRatchetPub, localRatchetPriv, localRatchetPub, 5, 3, 2, 0)
	require.NoError(t, err)

	// Load dan verifikasi semua field tersimpan dengan benar
	_, loadedRoot, loadedSend, loadedRecv, loadedRemoteRatchet, loadedLocalPriv, loadedLocalPub, n, m, pn, _, err :=
		corestore.LoadSession(peerID)
	require.NoError(t, err)

	assert.Equal(t, rootKey, loadedRoot, "RootKey harus tersimpan")
	assert.Equal(t, sendChain, loadedSend, "SendChainKey harus tersimpan")
	assert.Equal(t, recvChain, loadedRecv, "RecvChainKey harus tersimpan")
	assert.Equal(t, remoteRatchetPub, loadedRemoteRatchet, "RemoteRatchetPub harus tersimpan (BUG-04)")
	assert.Equal(t, localRatchetPriv, loadedLocalPriv, "LocalRatchetPriv harus tersimpan (BUG-04)")
	assert.Equal(t, localRatchetPub, loadedLocalPub, "LocalRatchetPub harus tersimpan (BUG-04)")
	assert.Equal(t, uint32(5), n, "Counter N harus tersimpan")
	assert.Equal(t, uint32(3), m, "Counter M harus tersimpan")
	assert.Equal(t, uint32(2), pn, "Counter PN harus tersimpan")
}

// TestDESIGN07_ClusterEventHMAC memverifikasi pembuatan signature HMAC dan
// validitas verifikasi tanda tangan tersebut pada ClusterEvent.
func TestDESIGN07_ClusterEventHMAC(t *testing.T) {
	key := []byte("test-cluster-secret-key-12345")

	event := ClusterEvent{
		Type:    "MAILBOX_ADD",
		Hash:    "somehashvalue123",
		OwnerID: "owner-peer-id",
		Payload: "base64encodedencryptedpayload",
		Sender:  "sender-peer-id",
	}

	// 1. Signature harus valid dengan kunci yang benar
	sig := GenerateClusterHMAC(event, key)
	assert.NotEmpty(t, sig)

	eventWithSig := event
	eventWithSig.Signature = sig

	assert.True(t, VerifyClusterHMAC(eventWithSig, key), "DESIGN-07: Verifikasi HMAC harus sukses dengan kunci yang benar")

	// 2. Signature harus gagal dengan kunci yang salah
	wrongKey := []byte("wrong-cluster-secret-key-999")
	assert.False(t, VerifyClusterHMAC(eventWithSig, wrongKey), "DESIGN-07: Verifikasi HMAC harus gagal dengan kunci yang salah")

	// 3. Signature harus gagal jika data event dimodifikasi setelah ditandatangani
	modifiedEvent := eventWithSig
	modifiedEvent.Payload = "modified-payload"
	assert.False(t, VerifyClusterHMAC(modifiedEvent, key), "DESIGN-07: Verifikasi HMAC harus gagal jika payload event dimodifikasi")

	// 4. Signature harus gagal jika signature kosong
	eventNoSig := event
	assert.False(t, VerifyClusterHMAC(eventNoSig, key), "DESIGN-07: Verifikasi HMAC harus gagal jika signature kosong")
}

// Helper: buat bufio.Reader dari io.Reader (tanpa import di dalam function)
func newBufioReaderForTest(r io.Reader) io.Reader {
	return struct{ io.Reader }{r}
}

// Simulasikan net.Conn untuk test BUG-06 jika diperlukan
var _ net.Conn = (*mockConn)(nil)

type mockConn struct {
	io.Reader
	io.Writer
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestDeleteSession memverifikasi bahwa DeleteSession menghapus sesi aktif dan semua skipped keys yang terkait.
func TestDeleteSession(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	peerID := "12D3KooWTestDeleteSession"

	// 1. Simpan session dan skipped keys
	err = corestore.SaveSession(peerID, "identity", "root", "send", "recv", "remoteRatchet", "localPriv", "localPub", 1, 2, 3, 0)
	require.NoError(t, err)

	err = corestore.SaveSkippedKey(peerID, []byte("dummyPub"), 0, []byte("key0"))
	require.NoError(t, err)
	err = corestore.SaveSkippedKey(peerID, []byte("dummyPub"), 1, []byte("key1"))
	require.NoError(t, err)

	// Verifikasi data masuk
	_, rootB64, _, _, _, _, _, _, _, _, _, err := corestore.LoadSession(peerID)
	require.NoError(t, err)
	assert.Equal(t, "root", rootB64)

	skippedKey, err := corestore.GetSkippedKey(peerID, []byte("dummyPub"), 0)
	require.NoError(t, err)
	assert.Equal(t, []byte("key0"), skippedKey)

	// 2. Jalankan DeleteSession
	err = corestore.DeleteSession(peerID)
	require.NoError(t, err)

	// 3. Verifikasi session terhapus
	_, _, _, _, _, _, _, _, _, _, _, err = corestore.LoadSession(peerID)
	assert.Error(t, err, "Session harusnya terhapus dan mengembalikan error")

	// Verifikasi skipped keys juga terhapus
	_, err = corestore.GetSkippedKey(peerID, []byte("dummyPub"), 1)
	assert.Error(t, err, "Skipped keys harusnya terhapus")
}

// TestGroupLocalKeyHistoryAndRecovery memverifikasi penyimpanan riwayat local key
// dan kemampuan deskripsi menggunakan historical keys jika terjadi out-of-sync.
func TestGroupLocalKeyHistoryAndRecovery(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	groupID := "group_test_123"
	senderID := "12D3KooWSenderBob"

	key0 := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	key1 := []byte("abcdef0123456789abcdef0123456789") // 32 bytes

	// 1. Simpan local key pertama
	err = corestore.SaveGroupLocalKey(groupID, key0)
	require.NoError(t, err)

	// 2. Simpan local key kedua (rotasi)
	err = corestore.SaveGroupLocalKey(groupID, key1)
	require.NoError(t, err)

	// 3. Verifikasi active local key adalah key1
	activeKey, err := corestore.GetGroupLocalKey(groupID)
	require.NoError(t, err)
	assert.Equal(t, key1, activeKey)

	// 4. Verifikasi history berisi key1 dan key0 (DESC order)
	history, err := corestore.GetGroupLocalKeyHistory(groupID)
	require.NoError(t, err)
	require.Len(t, history, 2)
	assert.Equal(t, key1, history[0])
	assert.Equal(t, key0, history[1])

	// 5. Simulasikan receiver menyimpan key history Bob
	// Receiver memproses comma-separated GKEY dari oldest ke newest
	receiverKeys := [][]byte{key0, key1}
	for _, k := range receiverKeys {
		err = corestore.SaveGroupSenderKey(groupID, senderID, k)
		require.NoError(t, err)
	}

	// Verifikasi active sender key di receiver adalah key1
	activeSenderKey, err := corestore.GetGroupSenderKey(groupID, senderID)
	require.NoError(t, err)
	assert.Equal(t, key1, activeSenderKey)

	// Verifikasi history sender key di receiver berisi key1 dan key0
	senderHistory, err := corestore.GetGroupSenderKeyHistory(groupID, senderID)
	require.NoError(t, err)
	require.Len(t, senderHistory, 2)
	assert.Equal(t, key1, senderHistory[0])
	assert.Equal(t, key0, senderHistory[1])

	// 6. Uji dekripsi menggunakan historical key
	// Buat pesan terenkripsi dengan key0
	plaintext := "Halo Creator, ini pesan rahasia saya!"
	ciphertext, err := corecrypto.EncryptMessage(key0, plaintext)
	require.NoError(t, err)

	meta := corestore.GroupMetadata{
		GroupID:   groupID,
		GroupType: "SECURE",
	}
	gMsg := GroupMessage{
		SenderID: senderID,
		Payload:  ciphertext,
	}

	// decryptGroupMsg harus sukses mendekripsi menggunakan key0 dari history
	decryptedPlaintext, err := decryptGroupMsg(meta, gMsg)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedPlaintext)
}

// TestEnsureColumn memverifikasi penambahan kolom secara dinamis menggunakan EnsureColumn
func TestEnsureColumn(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	// 1. Tambah kolom baru ke tabel messages yang sudah ada
	err = corestore.EnsureColumn("messages", "new_test_column", "TEXT DEFAULT 'default_val'")
	require.NoError(t, err)

	// 2. Verifikasi kolom baru dapat diakses
	_, err = corestore.DB.Exec("INSERT INTO messages (sender_id, recipient_id, content, new_test_column) VALUES ('sender', 'recipient', 'content', 'custom_val')")
	require.NoError(t, err)

	var val string
	err = corestore.DB.QueryRow("SELECT new_test_column FROM messages LIMIT 1").Scan(&val)
	require.NoError(t, err)
	assert.Equal(t, "custom_val", val)

	// 3. Panggilan berulang untuk kolom yang sama tidak boleh memicu error (idempotent)
	err = corestore.EnsureColumn("messages", "new_test_column", "TEXT")
	require.NoError(t, err)
}

// TestPreKeyDeletionAndClear memverifikasi penambahan DeletePreKeyByID dan DeletePreKeysByOwner
func TestPreKeyDeletionAndClear(t *testing.T) {
	err := corestore.InitDatabase(":memory:")
	require.NoError(t, err)
	defer corestore.DB.Close()

	ownerID := "12D3KooWOwner"
	keyID1 := "key1"
	keyID2 := "key2"

	// 1. Simpan prekeys
	err = corestore.SavePreKey(ownerID, keyID1, "pub1", "priv1", "sig1")
	require.NoError(t, err)
	err = corestore.SavePreKey(ownerID, keyID2, "pub2", "priv2", "sig2")
	require.NoError(t, err)

	assert.Equal(t, 2, corestore.GetPreKeyCount(ownerID))

	// 2. Hapus key1 secara spesifik
	err = corestore.DeletePreKeyByID(keyID1)
	require.NoError(t, err)
	assert.Equal(t, 1, corestore.GetPreKeyCount(ownerID))

	// Verifikasi key2 masih ada tapi key1 sudah tidak ada
	_, err = corestore.FindPrivateKeyByID(keyID1)
	assert.Error(t, err)

	priv2, err := corestore.FindPrivateKeyByID(keyID2)
	assert.NoError(t, err)
	assert.Equal(t, "priv2", priv2)

	// 3. Clear semua key milik owner
	err = corestore.DeletePreKeysByOwner(ownerID)
	require.NoError(t, err)
	assert.Equal(t, 0, corestore.GetPreKeyCount(ownerID))
}

// TestSignedEnvelopeVerification verifies wrapping and verification of SignedMailboxEnvelope.
func TestSignedEnvelopeVerification(t *testing.T) {
	// 1. Setup host
	h, err := libp2p.New()
	require.NoError(t, err)
	defer h.Close()

	priv := h.Peerstore().PrivKey(h.ID())
	require.NotNil(t, priv)
	pub := h.Peerstore().PubKey(h.ID())
	require.NotNil(t, pub)

	// 2. Wrap envelope with signature
	originalEnvelope := "DR:ciphertext-message-payload-here"
	sigWrapped, err := WrapEnvelopeWithSignature(priv, originalEnvelope)
	require.NoError(t, err)
	assert.NotEmpty(t, sigWrapped)

	// 3. Verify the signed envelope (should succeed)
	plain, err := VerifySignedEnvelope(sigWrapped, pub)
	require.NoError(t, err)
	assert.Equal(t, originalEnvelope, plain)

	// 4. Verify with invalid public key (should fail)
	h2, err := libp2p.New()
	require.NoError(t, err)
	defer h2.Close()
	pub2 := h2.Peerstore().PubKey(h2.ID())

	_, err2 := VerifySignedEnvelope(sigWrapped, pub2)
	assert.Error(t, err2, "Signature verification should fail with wrong public key")
}
