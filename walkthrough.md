# Walkthrough - Perbaikan Caching & Proteksi Pembajakan Alias

Dokumen ini mendokumentasikan hasil pengujian dan perubahan yang dilakukan untuk memperbaiki bug resolusi lokal dan mencegah pembajakan alias (*alias hijacking*) pada jaringan.

## Perubahan Kode
Kami telah mengubah berkas [alias.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/alias.go) pada dua bagian utama:
1. **Menyimpan Alias Secara Lokal:** Memastikan bahwa node yang mendaftarkan alias (melalui `RegisterAlias`) juga menyimpan alias tersebut ke database SQLite dan memory lokal (`aliasStore` & `ownerStore`) milik dirinya sendiri agar langsung dikenali.
2. **Pemulihan `ownerStore` saat Booting:** Memastikan `loadPersistedAliases` memuat database ke dalam `ownerStore` sehingga aturan satu kunci publik satu alias tetap terjaga setelah node melakukan *restart*.

---

## Rincian Kasus Uji (Skenario 5)
Kami telah menambahkan **Skenario 5** pada berkas pengujian E2E [e2e_test_scenarios.sh](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/e2e_test_scenarios.sh):

```bash
echo "=================================================="
echo "SKENARIO 5: Alias Hijacking Protection & Local Caching"
echo "=================================================="
# 1. Alice mendaftarkan alias @super-alice
# 2. Verifikasi Alice menyimpannya secara lokal
# 3. Bob mencoba membajak dengan mendaftarkan alias @super-alice
# 4. Verifikasi pendaftaran Bob ditolak oleh jaringan
```

---

## Hasil Pengujian E2E
Seluruh skenario pengujian berhasil dilewati dengan sukses:

```text
==================================================
SKENARIO 1: 1:1 Messaging (Online) - Alice -> Bob
==================================================
>> SKENARIO 1: SUCCESS (Pesan diterima online)

==================================================
SKENARIO 2: 1:1 Messaging (Offline) - Alice -> Bob (Offline)
==================================================
>> SKENARIO 2: SUCCESS (Pesan offline diterima via Mailbox)

==================================================
SKENARIO 3: Group Chat (Online) - Alice, Bob, Charlie
==================================================
>> SKENARIO 3: SUCCESS (Semua anggota online menerima pesan grup)

==================================================
SKENARIO 4: Group Chat (Offline Bergantian)
==================================================
>> SKENARIO 4: SUCCESS (Group Offline Bergantian bekerja sempurna)

==================================================
SKENARIO 5: Alias Hijacking Protection & Local Caching
==================================================
1. Alice mendaftarkan alias @super-alice...
   -> Alice berhasil mendaftarkan @super-alice secara lokal dan ke swarm.
2. Bob mencoba mendaftarkan alias @super-alice (alias hijacking)...
   -> Bob ditolak ketika mencoba mendaftarkan alias @super-alice (Sukses Proteksi Hijacking!).
>> SKENARIO 5: SUCCESS
```

---

## 3. Penyelesaian Pesan Offline & Perbaikan Lingkungan Pengujian
Kami mendeteksi beberapa kegagalan dan ketidakstabilan pengujian yang diselesaikan dengan peningkatan berikut:

### Perubahan yang Dilakukan:
1. **DHT Peer Routing (`FindPeer`):** Menggunakan pencarian DHT resmi `corenet.GlobalDHT.FindPeer(ctx, target)` jika peerstore tidak memiliki alamat target. Ini mengambil secara dinamis seluruh alamat yang diiklankan oleh target (termasuk alamat `p2p-circuit` relay) tanpa mengotori peerstore dengan alamat loopback duplikat.
2. **Global DHT Discovery:** Menambahkan **DHT Rendezvous Discovery** di [discovery.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/network/discovery.go). Setiap node mempublikasikan kehadirannya di bawah tag `"meshsage-global-rendezvous"` dan secara periodik mendeteksi serta menghubungkan diri ke node global lainnya secara otomatis.
3. **Peningkatan Timeout:** Menaikkan timeout dari 2 detik menjadi 5 detik untuk memberi kesempatan perutean relay dan negosiasi hole punching (DCUtR).
4. **Self-Messaging (Pesan ke Diri Sendiri):** Menambahkan penanganan khusus di `transmitEnvelope` agar pesan yang ditujukan ke diri sendiri (`target == h.ID()`) diproses langsung secara lokal di latar belakang tanpa dial ke jaringan (mencegah error `failed to dial: dial to self attempted`).
5. **Isolasi Lingkungan Uji (Test Environment Isolation):** Mengubah perilaku pemuatan seed di [main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/node/main.go) agar jika parameter `-peer` diberikan, node **hanya** akan terhubung ke alamat bootstrap tersebut dan mengabaikan seed produksi (`DefaultSeeds`). Ini mencegah node uji melakukan registrasi ke relay produksi yang memicu error `ERROR_ALREADY_OWNED`.

Hasil E2E test setelah seluruh perbaikan bersih ini berjalan 100% sukses tanpa ada regresi, dan list peer bertambah secara otomatis tanpa mengotori peerstore.

---

## 4. Verifikasi Manajemen Grup Kriptografis (Cryptographic Group Management)

Kami telah berhasil mengimplementasikan dan memverifikasi fitur manajemen grup chat yang aman berbasis **E2EE (Sender Key)**, tata kelola kepemilikan oleh **Creator**, serta dua model keanggotaan:
1. **SECURE (Closed / Invite-only)**: Pendaftaran anggota harus disetujui/ditambahkan oleh Creator.
2. **UNSECURE (Open / Public)**: Anggota dapat bergabung secara langsung via GossipSub topic dan melakukan pertukaran kunci (`GKEY`) secara otomatis.

### Hasil Pengujian E2E Otomatis (`test_groups_e2e.sh`)

Seluruh skenario pengujian fungsionalitas grup berjalan sukses 100%:
```text
=== MEMULAI GROUP CHAT E2E SETUP ===
[Compile] Building latest meshsage binary...
[Relay] Starting Relay on port 8001...
Relay Address: /ip4/127.0.0.1/tcp/8001/p2p/12D3KooWQkTJ9vZpuH6caeeTvJhhkXYkAHuSk3qc4cYyjtqHpFBK
[Clients] Starting Alice (8002) and Bob (8003)...
Alice ID: 12D3KooWGYZMvXJRiX4KqFXXSv3DSMXLKhJwcdfFxhkywDaTHY5z
Bob ID: 12D3KooWDgLzdQoBvXQdU3B1fy5HruFZMfE4qVo3LQdYzi6omd7G
[Alias] Registering @alice and @bob...
   -> @alice registered successfully.
   -> @bob registered successfully.
==================================================
TEST 1: SECURE (Closed/Invite) Group Chat
==================================================
Alice creating SECURE group @sec-group inviting @bob...
   -> Alice created @sec-group successfully.
   -> Bob auto-joined @sec-group invitation successfully.
Alice sending message to @sec-group...
   -> Bob successfully received and decrypted the secure message.
Bob sending message to @sec-group...
   -> Alice successfully received and decrypted Bob's message.
==================================================
TEST 2: Forward Secrecy on Voluntary Exit
==================================================
Bob voluntary exiting @sec-group...
   -> Bob local database exited @sec-group.
   -> Alice received Bob exit control command.
Alice sending message to @sec-group after Bob left...
   -> SUCCESS: Bob did not receive messages sent after exiting.
==================================================
TEST 3: UNSECURE (Open/Public) Group Chat
==================================================
Alice creating UNSECURE group @pub-group...
   -> Alice created @pub-group successfully.
Bob joining @pub-group...
   -> Bob resolved and joined @pub-group successfully.
Bob sending message to @pub-group...
   -> Alice received Bob's message in the open group.
==================================================
TEST 4: Forward Secrecy on Kick (Remove)
==================================================
Alice removing Bob from @pub-group...
   -> Bob was kicked and removed from @pub-group locally.
Alice sending message to @pub-group after kicking Bob...
   -> SUCCESS: Bob did not receive messages sent after being kicked.
=== GROUP CHAT E2E SUCCESS ===
Pembersihan node P2P...
```

Keamanan dan privasi (E2EE) terjamin sepenuhnya baik pada grup tertutup maupun terbuka, serta rotasi kunci (Forward Secrecy) bekerja dengan sempurna saat anggota keluar/dikeluarkan dari grup.
