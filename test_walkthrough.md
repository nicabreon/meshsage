# Walkthrough: Pengujian E2E Otomatis & Bukti Enkripsi/Dekripsi Pesan

Pengujian end-to-end (E2E) otomatis berhasil diselesaikan menggunakan skrip [e2e_test_scenarios.sh](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/e2e_test_scenarios.sh). Seluruh skenario (Scenario 1, 2, 3, dan 4) selesai dengan status **SUCCESS** dan terbukti melakukan enkripsi serta dekripsi E2EE dengan benar baik dalam kondisi online maupun offline.

---

## Ringkasan Identitas Node pada Pengujian

* **Dedicated Relay Port 6001**: `12D3KooWMuRGHZZG6ZRDJ4dy4aegKkdv1zwof3xtrzegPjuc77KA`
* **Alice Port 6002**: `12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9` (@alice)
* **Bob Port 6003**: `12D3KooWJKdw7ZqVnoG1x2uH2ohJEAWhyviXuHwk2mVNAXk8pmjs` (@bob)
* **Charlie Port 6004**: `12D3KooWQ5ey8EUFVd1YsazgwnxkqHk4n5nS39ym4WtkSCAvL7nM` (@charlie)

---

## Skenario & Bukti Log Hasil Pengujian

### SKENARIO 1: 1:1 Messaging (Online) - Alice -> Bob

* **Tindakan**: Alice mengirim pesan secara online ke Bob yang juga aktif secara online.
* **Pesan Asli**: `Halo Bob! Ini pesan online pertama dari Alice.`
* **Bukti Penerimaan pada Log Bob**:
  ```text
  [HANDSHAKE] Receiving new X3DH Handshake from 12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9
  [HANDSHAKE] Deriving shared secret from receiver's Pre-Key...
  [HANDSHAKE] Initial session established. RootKey: mGbJ3n...
  [Message from 12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9]: Halo Bob! Ini pesan online pertama dari Alice.
  ```

---

### SKENARIO 2: 1:1 Messaging (Offline) - Alice -> Bob (Offline)

* **Tindakan**: Bob dimatikan, kemudian Alice mengirim pesan langsung ke Bob. Pesan tersebut secara otomatis dialihkan ke Mailbox Relay. Setelah Bob dinyalakan kembali, Bob melakukan `/fetch`.
* **Pesan Asli**: `Halo Bob! Ini pesan offline saat kamu sedang tidak aktif.`
* **Bukti Penerimaan pada Log Bob setelah /fetch**:
  ```text
  [Message from 12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9]: Halo Bob! Ini pesan offline saat kamu sedang tidak aktif.
  ```

---

### SKENARIO 3: Group Chat (Online) - Alice, Bob, Charlie

* **Tindakan**: Seluruh anggota bergabung ke grup `GRP_TEST`. Alice mengirim pesan grup secara online saat semua anggota aktif.
* **Pesan Asli**: `Halo teman-teman! Kita semua online di grup.`
* **Bukti Enkripsi pada Log Alice**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP ENCRYPTION ---
  [GROUP E2EE] Original Text: Halo teman-teman! Kita semua online di grup.
  [GROUP E2EE] Encrypted Result (B64): XX8ExfU3/zxDEfRMAjrWGbhBO2Rc2mhD3v36RXMbTWw/lVbBuLJ34rSYZVJY73e1IpJcjzIG5uNI1xHtmVl3RLFxHffXEevGI0SB5ExCZ+2Ab6SMUrAuJDArTHun
  [Group Ratchet] Rotated our local key for group GRP_TEST
  ```
* **Bukti Dekripsi pada Log Bob**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---
  [GROUP E2EE] Decrypted Result: Halo teman-teman! Kita semua online di grup.
  [Group Security] Message from @12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9 verified with Digital Signature.
  [Group GRP_TEST] @12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9: Halo teman-teman! Kita semua online di grup.
  ```
* **Bukti Dekripsi pada Log Charlie**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---
  [GROUP E2EE] Decrypted Result: Halo teman-teman! Kita semua online di grup.
  [Group GRP_TEST] @12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9: Halo teman-teman! Kita semua online di grup.
  ```

---

### SKENARIO 4: Group Chat (Offline Bergantian)

Skenario ini memverifikasi fungsionalitas pesan grup saat anggota offline bergantian serta pemulihan otomatis group membership pada startup node.

#### 1. Charlie Offline, Alice mengirim pesan grup:
* **Pesan Asli**: `Halo grup! Charlie sedang offline saat ini.`
* **Bukti Enkripsi pada Log Alice**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP ENCRYPTION ---
  [GROUP E2EE] Original Text: Halo grup! Charlie sedang offline saat ini.
  [GROUP E2EE] Encrypted Result (B64): 4YF4S+UHH9XTGjAkwghjW/2R2EoaWK6oLEyIsbW8NjUC/Dw4GsBjnvarupHqQ2VxCg3wnRnN8s7pgS3Zdkec0fF8HEKZuD1D0TOaSsetiCsfLl6yOqePIAaEiLDuQXA=
  ```
* **Bukti Penerimaan Online pada Log Bob**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---
  [GROUP E2EE] Decrypted Result: Halo grup! Charlie sedang offline saat ini.
  [Group GRP_TEST] @12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9: Halo grup! Charlie sedang offline saat ini.
  ```

#### 2. Bob Offline, Charlie dinyalakan kembali:
* **Bukti Pemulihan Group pada Startup Charlie**:
  ```text
  [Alias DHT] Loaded 2 persisted aliases from database.
  [GROUP HANDSHAKE] Sharing our local key for group GRP_TEST with member 12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9 via Double Ratchet...
  [Group] Successfully joined room: GRP_TEST with 3 members
  [90m2026-05-22T09:32:47+07:00 [0m [32mINF [0m [1mAuto-restored group membership on startup [0m [36mgroupID= [0mGRP_TEST
  ```
* **Charlie melakukan `/fetch` untuk pesan offline**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION (OFFLINE) ---
  [GROUP E2EE] Decrypted Result: Halo grup! Charlie sedang offline saat ini.
  ```

#### 3. Charlie mengirim pesan grup baru saat Bob offline:
* **Pesan Asli**: `Halo Alice! Saya sudah online kembali. Bob kemana?`
* **Bukti Enkripsi pada Log Charlie**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP ENCRYPTION ---
  [GROUP E2EE] Original Text: Halo Alice! Saya sudah online kembali. Bob kemana?
  ```
* **Bukti Penerimaan Online pada Log Alice**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---
  [GROUP E2EE] Decrypted Result: Halo Alice! Saya sudah online kembali. Bob kemana?
  [Group GRP_TEST] @12D3KooWQ5ey8EUFVd1YsazgwnxkqHk4n5nS39ym4WtkSCAvL7nM (Offline): Halo Alice! Saya sudah online kembali. Bob kemana?
  ```

#### 4. Bob Dinyalakan Kembali & Mengambil Pesan Offline:
* **Bob melakukan `/fetch`**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION (OFFLINE) ---
  [GROUP E2EE] Decrypted Result: Halo Alice! Saya sudah online kembali. Bob kemana?
  ```

---

## Verifikasi Akhir

Seluruh fungsionalitas platform pesan terdistribusi (Meshsage) telah diverifikasi bekerja dengan stabil:
1. **Double Ratchet & X3DH**: Pengiriman pesan 1:1 online dan offline aman dan tidak mengalami error decryption.
2. **GossipSub Group Messaging**: Distribusi pesan grup online bekerja secara real-time.
3. **Offline Group Mailbox**: Pesan grup saat anggota offline disimpan di mailbox relay server dan dapat diambil kembali secara utuh.
4. **Group State Restoration**: Saat node restart, keanggotaan grup dipulihkan secara otomatis dari SQLite database sehingga node dapat langsung bertukar pesan tanpa harus bergabung kembali secara manual.
