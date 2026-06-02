# Meshsage Bug Fix Tasks

> Dibuat berdasarkan hasil evaluasi kode tanggal 2026-05-22.
> Status terakhir: Semua bug kritis & penting (termasuk DESIGN-07) SELESAI ✅

---

## 🔴 Bug Kritis

- [x] **BUG-06**: `handleStream` — mix read dari `s` langsung dan dari `buf`
  - **File**: `pkg/protocol/messaging.go` (L41-48)
  - **Fix**: Ganti `binary.Read(s, ...)` → `binary.Read(buf, ...)`
  - **Status**: ✅ Fixed

- [x] **BUG-03**: Race condition — session state tanpa locking
  - **File**: `pkg/protocol/messaging.go` (`sendSecureEnvelope` & `ProcessSecureEnvelope`)
  - **Fix**: Tambah `sync.Map` dengan `*sync.Mutex` per peerID via `getSessionLock()`. Lock di kedua jalur send & receive.
  - **Status**: ✅ Fixed

- [x] **BUG-02**: Skipped Key — path decryption salah
  - **File**: `pkg/protocol/messaging.go` (L72-148)
  - **Fix**: Gunakan `corecrypto.DecryptMessage()` (bukan `DecryptMessageRaw`) langsung ke `processDecryptedPayload()`.
  - **Status**: ✅ Fixed

- [x] **BUG-04**: X3DH tidak inisialisasi ratchet keys
  - **File**: `pkg/protocol/messaging.go` (sender L369-428, receiver L159-215)
  - **Fix (sender)**: Generate ratchet keypair, simpan SendChainKey=rootKey, sertakan `senderRatchetPub` di wire format baru: `X3DH:keyID:ePub:ratchetPub:payload`.
  - **Fix (receiver)**: Parse `senderRatchetPub` dari format baru, generate ratchet keypair lokal, derive `RecvChainKey` dari DH(localRatchetPriv, senderRatchetPub). Session tersimpan lengkap.
  - **Status**: ✅ Fixed

---

## 🟡 Masalah Penting

- [x] **BUG-08**: Memory leak `rateLimitMap`
  - **File**: `pkg/protocol/mailbox.go` (`SetupMailbox`)
  - **Fix**: Tambah goroutine periodic cleanup setiap 5 menit, hapus entry yang sudah > 5 menit.
  - **Status**: ✅ Fixed

- [x] **DESIGN-05**: Default broadcast ke semua peer untuk input tidak dikenal
  - **File**: `pkg/protocol/messaging.go` (akhir fungsi `processCommand`)
  - **Fix**: Ganti broadcast dengan pesan error informatif + daftar command tersedia.
  - **Status**: ✅ Fixed

- [x] **DESIGN-07**: Cluster sync events tidak diverifikasi
  - **File**: `pkg/protocol/replication.go` (L116-130)
  - **Fix**: Tambah HMAC signature pada `ClusterEvent` dan verifikasi di penerima.
  - **Status**: ✅ Fixed

---

## 🟢 Opsional

- [ ] **DESIGN-01**: Ganti `DeriveKeyFromPassword` dengan Argon2id — `pkg/crypto/e2ee.go` L130
- [ ] **DESIGN-02**: Gunakan random salt pada HKDF — `pkg/crypto/e2ee.go` L40
- [ ] **DESIGN-06**: Jadikan seed nodes dapat dikonfigurasi via flag — `cmd/node/main.go` L26

---

## 📱 Bug Fix Mobile & E2EE Stability (Juni 2026)

- [x] **BUG-09**: Key Rotation Race Condition & Missing Self-Healing
  - **File**: `pkg/protocol/group.go`
  - **Fix**: Added local key history (pruned to 20 keys), shared key history in `GKEY` payloads, and rate-limited `sendGroupKeyRequest` (30s) on group decryption errors to auto-heal desynchronized sessions.
  - **Status**: ✅ Fixed

- [x] **BUG-10**: Context Propagation & Background resource leak
  - **File**: `pkg/network/discovery.go` & `cmd/`
  - **Fix**: Propagated cancellation context to DHT advertiser/discovery loops to release port and DB resources instantly on app restart or force-close.
  - **Status**: ✅ Fixed

- [x] **BUG-11**: Database Integrity & Schema Migration Framework
  - **File**: `pkg/storage/database.go`
  - **Fix**: Integrated startup schema versioning using SQLite `PRAGMA user_version` and added dynamic column checks (`EnsureColumn`) to update existing databases on app upgrade.
  - **Status**: ✅ Fixed

- [x] **BUG-12**: E2EE Mailbox Pre-Key Sync Deletion
  - **File**: `pkg/storage/database.go` & `pkg/protocol/replication.go` & `messaging.go`
  - **Fix**: Refactored `PREKEY_DELETE` event to only remove public pre-keys from relay caches while keeping the private key on the owner node until successful handshake decryption.
  - **Status**: ✅ Fixed

- [x] **BUG-13**: Startup Clean Refresh & Pre-Key limit
  - **File**: `pkg/protocol/prekey.go`
  - **Fix**: Reduced default pre-key refill batch size to 10 and forced a clean update on startup to resolve ZKP sync issues after reinstall.
  - **Status**: ✅ Fixed

- [x] **BUG-14**: Mailbox Sync Polling & standard signature
  - **File**: `pkg/protocol/mailbox.go`
  - **Fix**: Deleted ZKP ring signatures. Implemented standard libp2p cryptographic signing on mailbox envelopes and introduced 2-second fast polling and 30-second background prekey check loops.
  - **Status**: ✅ Fixed

- [x] **BUG-15**: Timestamp Drift on Group Invite
  - **File**: `pkg/protocol/group.go` & `main.go`
  - **Fix**: Propagated the exact signed metadata timestamp when creating/joining groups to avoid GINVITE signature drift failures.
  - **Status**: ✅ Fixed

- [x] **BUG-16**: Mailbox Sync Race Condition (X3DH vs DR Message Order)
  - **File**: `pkg/protocol/mailbox.go`
  - **Fix**: Sorted fetched mailbox envelopes so X3DH handshakes are processed before Double Ratchet messages.
  - **Status**: ✅ Fixed

- [x] **BUG-17**: Private Messages to Group Aliases
  - **File**: `pkg/protocol/messaging.go` & `cmd/libmeshsage/main.go`
  - **Fix**: Blocked direct messaging to group aliases at resolve and FFI levels.
  - **Status**: ✅ Fixed

- [x] **UI-01**: Dart Null List Type Cast Crash
  - **File**: `cmd/libmeshsage/main.go`
  - **Fix**: Initialized FFI output slices as empty arrays `[]` instead of `nil` to prevent Dart JSON decode crashes.
  - **Status**: ✅ Fixed

- [x] **UI-02**: UI Alignments & Sorting
  - **File**: `meshsage_flutter` UI files
  - **Fix**: Configured dynamic activity-based chat room sorting, pull-to-fetch drag gesture, consistent local timezone rendering, and corrected wrapping buttons in Identity Card.
  - **Status**: ✅ Fixed

---

## 🔴 Future / Pending Features

- [ ] **FEAT-01**: Restricted Connection Rules for Client Nodes
  - **Goal**: Restrict outgoing/incoming client connections to dedicated relays and direct chat peers by default, preventing open peer-to-peer scanning unless all relays are offline.
  - **Implementation**:
    - Build a custom `RestrictedConnectionGater` implementing `connmgr.ConnectionGater` in the Go networking layer.
    - Check and allow connection ONLY to static seeds, discovered dedicated relays (`/p2p-core/infra/dedicated/1.1.0`), and peers with active direct chat sessions in SQLite.
    - Implement a dynamic fallback: if zero dedicated relays are reachable, allow standard connections to standard/hybrid peers.
    - Register the gater in `pkg/network/host.go` during `libp2p.New`.

---

## Build Status

```
go build ./pkg/...  ✅ SUCCESS
go build -o meshsage ./cmd/node  ✅ SUCCESS
./build_android.sh  ✅ SUCCESS (native FFI libraries packaged)
```
