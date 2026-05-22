#!/bin/bash
# e2e_test_scenarios.sh
# Skrip Pengujian E2E Otomatis untuk Platform Pesan Terdistribusi (Meshsage)
# Memverifikasi 1:1 Chat dan Group Chat dalam kondisi Online/Offline secara bergantian.

set -e

echo "=== MEMULAI SETUP PENGETESAN E2E ==="

# 1. Bersihkan dan buat direktori kerja baru
rm -rf test_e2e_run
mkdir -p test_e2e_run/relay test_e2e_run/alice test_e2e_run/bob test_e2e_run/charlie
touch test_e2e_run/relay/input test_e2e_run/alice/input test_e2e_run/bob/input test_e2e_run/charlie/input

# 2. Compile ulang executable p2p-node
echo "[Compile] Membangun binary p2p-node terbaru..."
go build -o p2p-node ./cmd/node

# 3. Jalankan Dedicated Relay Server
echo "[Relay] Menjalankan Dedicated Relay Server pada port 6001..."
P2P_INPUT_PATH=test_e2e_run/relay/input ./p2p-node -debug -dedicated=true -port=6001 -db=test_e2e_run/relay/node.db -identity=test_e2e_run/relay/node.key > test_e2e_run/relay/log 2>&1 &
RELAY_PID=$!
sleep 3

# Dapatkan Peer ID dan alamat multiaddress Relay
RELAY_ID=$(grep "Local Identity Initialized" test_e2e_run/relay/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')
RELAY_ADDR="/ip4/127.0.0.1/tcp/6001/p2p/$RELAY_ID"
echo "Relay Address: $RELAY_ADDR"

# 4. Jalankan Node Klien (Alice, Bob, Charlie) terhubung ke Relay
echo "[Clients] Menjalankan Alice (6002), Bob (6003), dan Charlie (6004)..."
P2P_INPUT_PATH=test_e2e_run/alice/input ./p2p-node -debug -port=6002 -db=test_e2e_run/alice/node.db -identity=test_e2e_run/alice/node.key -peer="$RELAY_ADDR" >> test_e2e_run/alice/log 2>&1 &
ALICE_PID=$!

P2P_INPUT_PATH=test_e2e_run/bob/input ./p2p-node -debug -port=6003 -db=test_e2e_run/bob/node.db -identity=test_e2e_run/bob/node.key -peer="$RELAY_ADDR" >> test_e2e_run/bob/log 2>&1 &
BOB_PID=$!

P2P_INPUT_PATH=test_e2e_run/charlie/input ./p2p-node -debug -port=6004 -db=test_e2e_run/charlie/node.db -identity=test_e2e_run/charlie/node.key -peer="$RELAY_ADDR" >> test_e2e_run/charlie/log 2>&1 &
CHARLIE_PID=$!

sleep 5

# Dapatkan Peer ID Klien
ALICE_ID=$(grep "Local Identity Initialized" test_e2e_run/alice/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')
BOB_ID=$(grep "Local Identity Initialized" test_e2e_run/bob/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')
CHARLIE_ID=$(grep "Local Identity Initialized" test_e2e_run/charlie/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')

echo "Alice PeerID: $ALICE_ID"
echo "Bob PeerID: $BOB_ID"
echo "Charlie PeerID: $CHARLIE_ID"

# 5. Registrasi Alias
echo "[Alias] Mendaftarkan alias @alice, @bob, @charlie..."
echo "/register alice" > test_e2e_run/alice/input
sleep 1
echo "/register bob" > test_e2e_run/bob/input
sleep 1
echo "/register charlie" > test_e2e_run/charlie/input
sleep 5

echo "=================================================="
echo "SKENARIO 1: 1:1 Messaging (Online) - Alice -> Bob"
echo "=================================================="
echo "Alice mengirim pesan langsung secara online ke Bob..."
echo "/msg @bob Halo Bob! Ini pesan online pertama dari Alice." > test_e2e_run/alice/input
sleep 8

# Verifikasi pesan diterima oleh Bob
if grep -q "Halo Bob! Ini pesan online pertama dari Alice." test_e2e_run/bob/log; then
    echo ">> SKENARIO 1: SUCCESS (Pesan diterima online)"
else
    echo ">> SKENARIO 1: FAILED (Pesan TIDAK diterima)"
fi

echo "=================================================="
echo "SKENARIO 2: 1:1 Messaging (Offline) - Alice -> Bob (Offline)"
echo "=================================================="
echo "Mematikan Bob..."
kill -SIGINT $BOB_PID
sleep 2

echo "Alice mengirim pesan ke Bob yang sedang offline..."
echo "/msg @bob Halo Bob! Ini pesan offline saat kamu sedang tidak aktif." > test_e2e_run/alice/input
sleep 5

echo "Menghidupkan kembali Bob..."
P2P_INPUT_PATH=test_e2e_run/bob/input ./p2p-node -debug -port=6003 -db=test_e2e_run/bob/node.db -identity=test_e2e_run/bob/node.key -peer="$RELAY_ADDR" >> test_e2e_run/bob/log 2>&1 &
BOB_PID=$!
sleep 5

echo "Bob melakukan /fetch pesan offline dari Relay..."
echo "/fetch" > test_e2e_run/bob/input
sleep 8

# Verifikasi pesan offline diterima oleh Bob
if grep -q "Halo Bob! Ini pesan offline saat kamu sedang tidak aktif." test_e2e_run/bob/log; then
    echo ">> SKENARIO 2: SUCCESS (Pesan offline diterima via Mailbox)"
else
    echo ">> SKENARIO 2: FAILED (Pesan offline TIDAK diterima)"
fi

echo "=================================================="
echo "SKENARIO 3: Group Chat (Online) - Alice, Bob, Charlie"
echo "=================================================="
echo "Semua anggota bergabung ke grup GRP_TEST..."
echo "/join GRP_TEST $BOB_ID,$CHARLIE_ID" > test_e2e_run/alice/input
sleep 2
echo "/join GRP_TEST $ALICE_ID,$CHARLIE_ID" > test_e2e_run/bob/input
sleep 2
echo "/join GRP_TEST $ALICE_ID,$BOB_ID" > test_e2e_run/charlie/input

# Tunggu pertukaran Group Sender Keys (Double Ratchet handshake)
echo "Menunggu pertukaran kunci grup (handshake)..."
sleep 10

echo "Alice mengirim pesan grup saat semua online..."
echo "/group GRP_TEST Halo teman-teman! Kita semua online di grup." > test_e2e_run/alice/input
sleep 8

# Verifikasi Bob dan Charlie menerima pesan grup
BOB_RCV_GRP=0
CHARLIE_RCV_GRP=0
if grep -q "Halo teman-teman! Kita semua online di grup." test_e2e_run/bob/log; then BOB_RCV_GRP=1; fi
if grep -q "Halo teman-teman! Kita semua online di grup." test_e2e_run/charlie/log; then CHARLIE_RCV_GRP=1; fi

if [ $BOB_RCV_GRP -eq 1 ] && [ $CHARLIE_RCV_GRP -eq 1 ]; then
    echo ">> SKENARIO 3: SUCCESS (Semua anggota online menerima pesan grup)"
else
    echo ">> SKENARIO 3: FAILED (Bob=$BOB_RCV_GRP, Charlie=$CHARLIE_RCV_GRP)"
fi

echo "=================================================="
echo "SKENARIO 4: Group Chat (Offline Bergantian)"
echo "=================================================="
echo "1. Mematikan Charlie..."
kill -SIGINT $CHARLIE_PID
sleep 2

echo "2. Alice mengirim pesan grup (Bob online, Charlie offline)..."
echo "/group GRP_TEST Halo grup! Charlie sedang offline saat ini." > test_e2e_run/alice/input
sleep 8

# Verifikasi Bob menerima pesan secara online
if grep -q "Halo grup! Charlie sedang offline saat ini." test_e2e_run/bob/log; then
    echo "   -> Bob berhasil menerima pesan grup secara online."
else
    echo "   -> FAILED: Bob tidak menerima pesan grup secara online."
fi

echo "3. Mematikan Bob dan menyalakan kembali Charlie..."
kill -SIGINT $BOB_PID
sleep 2

P2P_INPUT_PATH=test_e2e_run/charlie/input ./p2p-node -debug -port=6004 -db=test_e2e_run/charlie/node.db -identity=test_e2e_run/charlie/node.key -peer="$RELAY_ADDR" >> test_e2e_run/charlie/log 2>&1 &
CHARLIE_PID=$!
sleep 5

echo "4. Charlie mengambil pesan offline grup via /fetch..."
echo "/fetch" > test_e2e_run/charlie/input
sleep 8

if grep -q "Halo grup! Charlie sedang offline saat ini." test_e2e_run/charlie/log; then
    echo "   -> Charlie berhasil mengambil pesan offline grup dari Mailbox."
else
    echo "   -> FAILED: Charlie tidak menerima pesan offline grup."
fi

echo "5. Charlie mengirim pesan grup baru saat Bob offline..."
echo "/group GRP_TEST Halo Alice! Saya sudah online kembali. Bob kemana?" > test_e2e_run/charlie/input
sleep 8

# Verifikasi Alice menerima pesan online dari Charlie
if grep -q "Halo Alice! Saya sudah online kembali. Bob kemana?" test_e2e_run/alice/log; then
    echo "   -> Alice berhasil menerima pesan online dari Charlie."
else
    echo "   -> FAILED: Alice tidak menerima pesan online dari Charlie."
fi

echo "6. Menghidupkan kembali Bob..."
P2P_INPUT_PATH=test_e2e_run/bob/input ./p2p-node -debug -port=6003 -db=test_e2e_run/bob/node.db -identity=test_e2e_run/bob/node.key -peer="$RELAY_ADDR" >> test_e2e_run/bob/log 2>&1 &
BOB_PID=$!
sleep 5

echo "7. Bob mengambil pesan offline grup via /fetch..."
echo "/fetch" > test_e2e_run/bob/input
sleep 10

if grep -q "Halo Alice! Saya sudah online kembali. Bob kemana?" test_e2e_run/bob/log; then
    echo "   -> Bob berhasil mengambil pesan offline grup dari Charlie."
    echo ">> SKENARIO 4: SUCCESS (Group Offline Bergantian bekerja sempurna)"
else
    echo "   -> FAILED: Bob tidak menerima pesan offline grup dari Charlie."
    echo ">> SKENARIO 4: FAILED"
fi

# Cleanup
echo "Pembersihan node P2P..."
kill $RELAY_PID $ALICE_PID $BOB_PID $CHARLIE_PID || true

echo "=== PENGUJIAN E2E SELESAI ==="
