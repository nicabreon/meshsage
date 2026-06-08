# Laporan Teknis: Stabilisasi E2EE Double Ratchet

## Masalah Utama
Implementasi Double Ratchet sebelumnya sangat sensitif terhadap urutan pesan. Jika pesan datang tidak berurutan (misal P3 datang sebelum P1), sistem mengalami kegagalan dekripsi permanen karena kunci ratchet sudah terlanjur diputar ke depan tanpa menyimpan kunci yang terlewati.

## Solusi: Skipped Message Keys
Saya telah mengimplementasikan mekanisme **Skipped Message Keys** sesuai standar Signal Protocol:

1.  **Sequence Counters:**
    -   `N`: Nomor urut pesan yang dikirim dalam satu epoch ratchet.
    -   `M`: Nomor urut pesan yang diterima (lokal).
    -   `PN`: Jumlah pesan dalam epoch ratchet sebelumnya.
2.  **Logic Dekripsi Baru:**
    -   Penerima mendeteksi "gap" antara nomor urut pesan yang diterima (`N`) dengan counter lokal (`M`).
    -   Jika ada gap, sistem secara otomatis menghitung kunci-kunci pesan yang terlewat dan menyimpannya ke tabel `skipped_keys` di SQLite.
    -   Jika pesan yang terlambat akhirnya tiba, sistem akan mencari kuncinya di `skipped_keys`, mendekripsinya, lalu segera menghapus kunci tersebut (*Forward Secrecy*).
3.  **Persistensi Database:**
    -   State ratchet (`N`, `M`, `PN`) sekarang disimpan secara permanen di database. Sinkronisasi tidak lagi hilang meskipun node di-restart.

## Hasil Pengujian

### 1. Unit Test (Scratch Script)
Simulasi pengiriman pesan P1, P2, P3 di mana P3 diterima paling awal:
- **Status:** **LULUS**
- **Evidence:** Bob berhasil melompati kunci untuk P1 & P2, mendekripsi P3, lalu mendekripsi P1 dan P2 saat mereka tiba kemudian menggunakan kunci yang disimpan.

### 2. Integrasi Docker (Staged Offline Sync)
Simulasi Alice mengirim 5 pesan ke Bob yang sedang offline:
- **Status:** **LULUS**
- **Evidence:** Bob berhasil melakukan `fetch` sekaligus dan mendekripsi seluruh rangkaian pesan tanpa satu pun kegagalan dekripsi (masalah `ERR E2EE Decryption failed` yang lama sudah teratasi).

## Perubahan Kode Utama
- `pkg/crypto/ratchet.go`: Logika rotasi chain dan perhitungan skipped keys.
- `pkg/storage/database.go`: Skema tabel `sessions` baru dan tabel `skipped_keys`.
- `pkg/protocol/messaging.go`: Integrasi alur dekripsi dengan pengecekan skipped keys terlebih dahulu.

## Kesimpulan
Sistem E2EE kita sekarang jauh lebih tangguh terhadap gangguan jaringan, delay Mailbox, dan sinkronisasi antar node yang sering mati-nyala.
