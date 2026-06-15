package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBUG02_EncryptDecryptMessage_Symmetry memverifikasi bahwa EncryptMessage dan
// DecryptMessage adalah pasangan yang benar (ada gzip di dalamnya).
// BUG-02 lama: skipped key path pakai DecryptMessageRaw → GAGAL karena gzip.
func TestBUG02_EncryptDecryptMessage_Symmetry(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := "hello meshsage, ini pesan rahasia!"

	// Step 1: Enkripsi dengan EncryptMessage (ada gzip di dalamnya)
	ciphertext, err := EncryptMessage(key, plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	// Step 2: DecryptMessage harus berhasil (pasangan yang benar)
	result, err := DecryptMessage(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, result, "DecryptMessage harus berhasil mendekripsi output EncryptMessage")

	// Step 3: Verifikasi bahwa output EncryptMessage adalah base64
	rawBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	require.NoError(t, err, "Output EncryptMessage harus berupa base64 yang valid")
	assert.NotEmpty(t, rawBytes)
}

// TestBUG02_SkippedKeyMustUseDecryptMessage memverifikasi bahwa skipped key path
// HARUS menggunakan DecryptMessage, bukan DecryptMessageRaw.
// Ini adalah reproduksi langsung dari bug yang diperbaiki.
func TestBUG02_SkippedKeyMustUseDecryptMessage(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 0xAB
	key[31] = 0xCD

	// Pesan dienkripsi oleh EncryptWithRatchet → memanggil EncryptMessage
	plaintext := `{"id":"abc123","type":"text","content":"pesan out-of-order"}`
	ciphertext, err := EncryptMessage(key, plaintext)
	require.NoError(t, err)

	// Fix BUG-02: skipped key path harus pakai DecryptMessage
	result, err := DecryptMessage(key, ciphertext)
	require.NoError(t, err, "Skipped key HARUS bisa dekripsi dengan DecryptMessage")
	assert.Equal(t, plaintext, result, "Plaintext harus identik setelah roundtrip")

	// Verifikasi bahwa DecryptMessageRaw TIDAK bisa mendekripsi output EncryptMessage
	rawCipher, _ := base64.StdEncoding.DecodeString(ciphertext)
	resultRaw, errRaw := DecryptMessageRaw(key, rawCipher)
	if errRaw == nil {
		// Jika tidak error, hasil pasti bukan plaintext asli (karena gzip masih ada)
		assert.NotEqual(t, plaintext, string(resultRaw),
			"DecryptMessageRaw tidak boleh menghasilkan plaintext yang benar dari output EncryptMessage")
	}
	// Jika error → ini yang diharapkan (BUG-02 lama selalu error di sini)
}

// TestBUG02_RatchetEncryptDecryptRoundtrip memverifikasi full roundtrip
// EncryptWithRatchet → DecryptWithRatchet dengan session yang simetris.
func TestBUG02_RatchetEncryptDecryptRoundtrip(t *testing.T) {
	alicePriv, alicePub, err := GenerateEphemeralKeypair()
	require.NoError(t, err)
	bobPriv, bobPub, err := GenerateEphemeralKeypair()
	require.NoError(t, err)

	aliceSecret, err := DeriveSharedSecret(alicePriv, bobPub)
	require.NoError(t, err)
	bobSecret, err := DeriveSharedSecret(bobPriv, alicePub)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(aliceSecret, bobSecret), "Shared secret harus identik")

	aliceSession := &SessionState{
		PeerID:              "bob",
		RootKey:             aliceSecret,
		SendChainKey:        aliceSecret,
		RecvChainKey:        bobSecret,
		LocalRatchetPrivkey: alicePriv,
		LocalRatchetPubkey:  alicePub,
		RemoteRatchetPubkey: bobPub,
	}
	bobSession := &SessionState{
		PeerID:              "alice",
		RootKey:             bobSecret,
		SendChainKey:        bobSecret,
		RecvChainKey:        aliceSecret,
		LocalRatchetPrivkey: bobPriv,
		LocalRatchetPubkey:  bobPub,
		RemoteRatchetPubkey: alicePub,
	}

	messages := []string{
		`{"id":"1","type":"text","content":"Halo Bob!"}`,
		`{"id":"2","type":"text","content":"Pesan kedua"}`,
		`{"id":"3","type":"text","content":"Pesan ketiga dengan konten lebih panjang untuk test gzip"}`,
	}

	for i, msg := range messages {
		ciphertext, err := aliceSession.EncryptWithRatchet(msg)
		require.NoError(t, err, "Encrypt pesan %d harus berhasil", i+1)

		plaintext, _, err := bobSession.DecryptWithRatchet(ciphertext)
		require.NoError(t, err, "Decrypt pesan %d harus berhasil", i+1)
		assert.Equal(t, msg, plaintext, "Pesan %d harus identik setelah roundtrip", i+1)
	}
}

// TestBUG04_X3DH_SharedSecretSymmetry memverifikasi bahwa DH key exchange menghasilkan
// shared secret yang sama dari kedua arah — fondasi dari BUG-04 fix.
func TestBUG04_X3DH_SharedSecretSymmetry(t *testing.T) {
	senderPriv, senderPub, err := GenerateEphemeralKeypair()
	require.NoError(t, err)
	receiverPriv, receiverPub, err := GenerateEphemeralKeypair()
	require.NoError(t, err)

	senderShared, err := DeriveSharedSecret(senderPriv, receiverPub)
	require.NoError(t, err)
	receiverShared, err := DeriveSharedSecret(receiverPriv, senderPub)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(senderShared, receiverShared),
		"BUG-04: Sender dan receiver HARUS derive shared secret yang sama (DH property)")
	assert.Len(t, senderShared, 32, "Shared secret harus 32 bytes (AES-256 ready)")
}

// TestBUG04_RatchetKeyPairNotEmpty memverifikasi bahwa ratchet keypair yang di-generate
// tidak pernah empty — mencegah BUG-04 dimana session disimpan dengan keys kosong.
func TestBUG04_RatchetKeyPairNotEmpty(t *testing.T) {
	priv, pub, err := GenerateEphemeralKeypair()
	require.NoError(t, err)

	assert.NotEmpty(t, priv, "BUG-04: Ratchet private key tidak boleh kosong")
	assert.NotEmpty(t, pub, "BUG-04: Ratchet public key tidak boleh kosong")
	assert.Len(t, priv, 32, "Ratchet private key harus 32 bytes")
	assert.Len(t, pub, 32, "Ratchet public key harus 32 bytes")
	assert.NotEqual(t, priv, pub, "Private dan public key harus berbeda")
}

// TestRatchetStep_ForwardSecrecy memverifikasi bahwa setiap RatchetStep menghasilkan
// message key yang berbeda (forward secrecy).
func TestRatchetStep_ForwardSecrecy(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i * 7)
	}

	// Derive 5 message keys secara berurutan
	keys := make([][]byte, 5)
	current := chainKey
	for i := 0; i < 5; i++ {
		msgKey, nextChain, err := RatchetStep(current)
		require.NoError(t, err)
		keys[i] = msgKey
		current = nextChain
	}

	// Verifikasi semua keys unik (forward secrecy)
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			assert.False(t, bytes.Equal(keys[i], keys[j]),
				"Forward secrecy: message key %d dan %d harus berbeda", i, j)
		}
	}
}

// TestEncryptDecryptRaw_Symmetry memverifikasi EncryptMessageRaw / DecryptMessageRaw
func TestEncryptDecryptRaw_Symmetry(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("raw bytes test untuk X3DH initial message")

	ciphertext, err := EncryptMessageRaw(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	result, err := DecryptMessageRaw(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, result, "EncryptMessageRaw/DecryptMessageRaw harus symmetric")
}

// TestHKDFExpand_Deterministic memverifikasi HKDF menghasilkan output deterministic
func TestHKDFExpand_Deterministic(t *testing.T) {
	secret := []byte("test-secret-32-bytes-for-hkdf-ok")
	out1, err := HKDFExpand(secret, "test-info", 32)
	require.NoError(t, err)
	out2, err := HKDFExpand(secret, "test-info", 32)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(out1, out2), "HKDF harus deterministic")

	// Info yang berbeda harus menghasilkan output berbeda
	out3, err := HKDFExpand(secret, "different-info", 32)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(out1, out3), "HKDF dengan info berbeda harus menghasilkan output berbeda")
}

// TestDoubleRatchetAlternatingRotation memverifikasi bahwa rotasi kunci DH tidak terjadi secara proaktif
// (hanya dengan mengirim pesan), melainkan secara reaktif saat menerima balasan dengan kunci DH baru.
func TestDoubleRatchetAlternatingRotation(t *testing.T) {
	alicePriv, alicePub, err := GenerateEphemeralKeypair()
	require.NoError(t, err)
	bobPriv, bobPub, err := GenerateEphemeralKeypair()
	require.NoError(t, err)

	aliceSecret, err := DeriveSharedSecret(alicePriv, bobPub)
	require.NoError(t, err)
	bobSecret, err := DeriveSharedSecret(bobPriv, alicePub)
	require.NoError(t, err)

	aliceSession := &SessionState{
		PeerID:              "bob",
		RootKey:             aliceSecret,
		SendChainKey:        aliceSecret,
		RecvChainKey:        bobSecret,
		LocalRatchetPrivkey: alicePriv,
		LocalRatchetPubkey:  alicePub,
		RemoteRatchetPubkey: bobPub,
	}

	bobSession := &SessionState{
		PeerID:              "alice",
		RootKey:             bobSecret,
		SendChainKey:        bobSecret,
		RecvChainKey:        aliceSecret,
		LocalRatchetPrivkey: bobPriv,
		LocalRatchetPubkey:  bobPub,
		RemoteRatchetPubkey: alicePub,
	}

	initialAlicePubkey := aliceSession.LocalRatchetPubkey
	initialBobPubkey := bobSession.LocalRatchetPubkey

	// 1. Alice mengirim 10 pesan beruntun tanpa balasan
	// Kunci publik Alice tidak boleh berubah (tidak ada rotasi proaktif)
	for i := 0; i < 10; i++ {
		msg := fmt.Sprintf("Alice Msg %d", i+1)
		cipher, err := aliceSession.EncryptWithRatchet(msg)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(initialAlicePubkey, aliceSession.LocalRatchetPubkey), "Kunci publik tidak boleh berputar secara proaktif")

		// Bob menerima dan mendekripsi
		plain, _, err := bobSession.DecryptWithRatchet(cipher)
		require.NoError(t, err)
		assert.Equal(t, msg, plain)
	}

	// 2. Bob sekarang membalas. Karena Bob menerima pesan dengan AlicePubkey (yang sama dengan initialAlicePubkey),
	// Bob tidak mendeteksi perubahan kunci pada dekripsi, sehingga Bob membalas menggunakan initialBobPubkey.
	bobCipher, err := bobSession.EncryptWithRatchet("Bob Msg 1")
	require.NoError(t, err)
	assert.True(t, bytes.Equal(initialBobPubkey, bobSession.LocalRatchetPubkey))

	// 3. Alice mendekripsi balasan Bob
	plain, _, err := aliceSession.DecryptWithRatchet(bobCipher)
	require.NoError(t, err)
	assert.Equal(t, "Bob Msg 1", plain)

	// Sekarang kita simulasikan rotasi reaktif:
	// A. Alice secara manual memutar kunci ratchet lokalnya (seperti saat menerima kunci baru)
	// Kita buat key pair baru untuk Alice dan kirim ke Bob.
	aliceNewPriv, aliceNewPub, err := GenerateEphemeralKeypair()
	require.NoError(t, err)
	
	// Kita buat session state baru secara manual di mana Alice menggunakan key pair baru
	aliceSession.LocalRatchetPrivkey = aliceNewPriv
	aliceSession.LocalRatchetPubkey = aliceNewPub
	sharedSecretSend, err := DeriveSharedSecret(aliceNewPriv, aliceSession.RemoteRatchetPubkey)
	require.NoError(t, err)
	resSend, err := HKDFExpand(sharedSecretSend, "p2p-core-dh-ratchet", 64)
	require.NoError(t, err)
	aliceSession.RootKey = resSend[:32]
	aliceSession.SendChainKey = resSend[32:]
	aliceSession.PN = aliceSession.N
	aliceSession.N = 0

	// Alice mengirim pesan baru dengan kunci baru
	aliceCipherNew, err := aliceSession.EncryptWithRatchet("Alice Msg New Key")
	require.NoError(t, err)
	assert.True(t, bytes.Equal(aliceNewPub, aliceSession.LocalRatchetPubkey))

	// Bob menerima pesan ini. Karena aliceNewPub != initialAlicePubkey, Bob mendeteksi perubahan kunci!
	// Ini memicu rotasi DH reaktif di BobSession.
	plainNew, _, err := bobSession.DecryptWithRatchet(aliceCipherNew)
	require.NoError(t, err)
	assert.Equal(t, "Alice Msg New Key", plainNew)

	// Verifikasi Bob telah memutar kunci lokalnya secara reaktif
	assert.False(t, bytes.Equal(initialBobPubkey, bobSession.LocalRatchetPubkey), "Bob harus memutar kunci lokalnya secara reaktif setelah menerima kunci baru dari Alice")
}
