# Final Walkthrough: Meshsage E2EE Stabilization & Mobile Rollout

## 1. Overview Sistem
Meshsage sekarang adalah platform P2P yang sepenuhnya aman dengan standar enkripsi industri. Pekerjaan terakhir berfokus pada transisi dari "MVP" ke "Production-Ready" dengan mengintegrasikan core library ke mobile app Flutter via Dart FFI dan memperbaiki mekanisme sinkronisasi pada kondisi jaringan yang tidak stabil.

## 2. Perubahan Utama & Lokasi Kode
- **Double Ratchet (OOO Handling)**:
  - `pkg/crypto/ratchet.go`: Logika inti penyimpanan dan penggunaan `skipped_keys`.
  - `pkg/protocol/messaging.go`: Integrasi pengambilan kunci yang terlewat sebelum dekripsi standar.
- **Group Messaging & Key History**:
  - `pkg/protocol/group.go`: Penambahan rotasi kunci (`GROUP_RATCHET`) dan rolling key history (20 kunci) untuk mencegah kegagalan dekripsi saat offline invitation.
- **Database Resilience & Schema Migrations**:
  - `pkg/storage/database.go`: Optimalisasi SQLite dengan mode `WAL` dan framework migrasi skema dinamis (`EnsureColumn` & `PRAGMA user_version`).
- **Mailbox Sync Manager & Standard Signatures**:
  - `pkg/protocol/mailbox.go`: Penghapusan ZKP ring signature yang berat dan tidak stabil. Diganti dengan tanda tangan standar libp2p (`SignedMailboxEnvelope`) serta scheduler sync otomatis (fast polling 2s, notification 5s, prekey refill 30s).
- **Offline Invite Sorting**:
  - `pkg/protocol/mailbox.go`: Mengurutkan incoming envelopes (X3DH handshakes didahulukan) saat mengambil offline mailbox guna mencegah session erasure loop.
- **Group Alias PM Block**:
  - `pkg/protocol/messaging.go` & `cmd/libmeshsage/main.go`: Memblokir pengiriman pesan pribadi ke alias grup.
- **Flutter FFI Integration**:
  - `cmd/libmeshsage/main.go`: Export API FFI untuk startup node, pengiriman direct/group messages, dynamic group join/create/exit, dan manual mailbox fetch.
- **Leak Cleanups**:
  - `pkg/network/discovery.go`: Penambahan context cancellation pada background routine discovery agar resource port/DB langsung dilepas saat app di-restart.

## 3. Cara Menjalankan Tes Integrasi
Jika Anda ingin mengulangi pengujian otomatis di masa depan:
1. Jalankan `go test ./pkg/protocol/...` untuk unit tests.
2. Jalankan `bash test_groups_e2e.sh` untuk group chat E2E swarm test.
3. Jalankan `./build_android.sh` untuk mengompilasi shared library Android.
4. Jalankan `flutter build apk` dari direktori `meshsage_flutter`.

## 4. Panduan Pengembangan Selanjutnya
- **Multi-Device Support**: Eksplorasi penggunaan *Device ID* dalam kunci Double Ratchet.
- **Auto-Discovery Members**: Implementasi *Auto-Discovery* anggota grup melalui GossipSub tanpa harus input manual.

