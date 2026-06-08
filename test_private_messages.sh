#!/bin/bash
set -e

# Setup Directories
rm -rf test_env && mkdir -p test_env/relay test_env/alice test_env/bob
touch test_env/alice/input test_env/bob/input

# Start Relay
echo "Starting local relay..."
./p2p-node -debug -dedicated=true -port=5001 -db=test_env/relay/node.db -identity=test_env/relay/node.key > test_env/relay/log 2>&1 &
RELAY_PID=$!
sleep 2

# Get Relay Address
RELAY_ID=$(grep "Local Identity Initialized" test_env/relay/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"')
RELAY_ADDR="/ip4/127.0.0.1/tcp/5001/p2p/$RELAY_ID"
echo "Relay Address: $RELAY_ADDR"

# Start Alice and Bob
echo "Starting Alice..."
P2P_INPUT_PATH=test_env/alice/input ./p2p-node -debug -port=5002 -db=test_env/alice/node.db -identity=test_env/alice/node.key -peer="$RELAY_ADDR" > test_env/alice/log 2>&1 &
ALICE_PID=$!

echo "Starting Bob..."
P2P_INPUT_PATH=test_env/bob/input ./p2p-node -debug -port=5003 -db=test_env/bob/node.db -identity=test_env/bob/node.key -peer="$RELAY_ADDR" > test_env/bob/log 2>&1 &
BOB_PID=$!

sleep 5

# Get Peer IDs
ALICE_ID=$(grep "Local Identity Initialized" test_env/alice/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"')
BOB_ID=$(grep "Local Identity Initialized" test_env/bob/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"')

echo "Alice ID: $ALICE_ID"
echo "Bob ID: $BOB_ID"

# 1. Online Test
echo "--- Testing Online Message ---"
echo "/register alice" > test_env/alice/input
sleep 2
echo "/register bob" > test_env/bob/input
sleep 5

echo "Alice sending message to Bob..."
echo "/msg @bob Halo Bob! Ini pesan online dari Alice." > test_env/alice/input
sleep 10

if grep -q "Halo Bob! Ini pesan online dari Alice." test_env/bob/log; then
    echo "SUCCESS: Bob received online message."
else
    echo "FAILED: Bob did NOT receive online message."
    tail -n 20 test_env/bob/log
fi

# 2. Offline Test
echo "--- Testing Offline Message ---"
echo "Stopping Bob..."
kill $BOB_PID
sleep 2

echo "Alice sending message to Bob (offline)..."
echo "/msg @bob Halo Bob! Ini pesan offline saat kamu sedang tidak aktif." > test_env/alice/input
sleep 5

echo "Starting Bob again..."
# Use same DB and Key
P2P_INPUT_PATH=test_env/bob/input ./p2p-node -debug -port=5003 -db=test_env/bob/node.db -identity=test_env/bob/node.key -peer="$RELAY_ADDR" > test_env/bob/log 2>&1 &
BOB_PID=$!
sleep 10

# Trigger manual fetch just in case auto-fetch is slow
echo "/fetch" > test_env/bob/input
sleep 10

if grep -q "Halo Bob! Ini pesan offline saat kamu sedang tidak aktif." test_env/bob/log; then
    echo "SUCCESS: Bob received offline message from mailbox."
else
    echo "FAILED: Bob did NOT receive offline message."
    echo "--- BOB LOG ---"
    tail -n 50 test_env/bob/log
    echo "--- RELAY LOG ---"
    tail -n 50 test_env/relay/log
fi

# Cleanup
echo "Cleaning up..."
kill $RELAY_PID $ALICE_PID $BOB_PID || true
