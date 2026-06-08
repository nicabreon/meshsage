#!/bin/bash
set -e

# 1. Setup Directories
rm -rf test_run && mkdir -p test_run/relay test_run/alice test_run/bob test_run/charlie

# 2. Start Relay
echo "Starting Relay..."
P2P_INPUT_PATH=test_run/relay/input ./p2p-node -dedicated=true -port=4001 -db=test_run/relay/node.db -identity=test_run/relay/node.key > test_run/relay/log 2>&1 &
RELAY_PID=$!
sleep 3

# 3. Start Clients
echo "Starting Clients..."
P2P_INPUT_PATH=test_run/alice/input ./p2p-node -port=4002 -db=test_run/alice/node.db -identity=test_run/alice/node.key > test_run/alice/log 2>&1 &
ALICE_PID=$!
P2P_INPUT_PATH=test_run/bob/input ./p2p-node -port=4003 -db=test_run/bob/node.db -identity=test_run/bob/node.key > test_run/bob/log 2>&1 &
BOB_PID=$!
P2P_INPUT_PATH=test_run/charlie/input ./p2p-node -port=4004 -db=test_run/charlie/node.db -identity=test_run/charlie/node.key > test_run/charlie/log 2>&1 &
CHARLIE_PID=$!
sleep 5

# 4. Registration
echo "Registering aliases..."
echo "/register alice" > test_run/alice/input
sleep 2
echo "/register bob" > test_run/bob/input
sleep 2
echo "/register charlie" > test_run/charlie/input
sleep 5

# 5. Private Message Test
echo "Testing Private Message Alice -> Bob..."
echo "/msg @bob Halo Bob! Ini pesan rahasia dari Alice." > test_run/alice/input
sleep 5

# 6. Group Message Test
echo "Testing Group Message..."
ID_BOB=$(grep "Local Identity Initialized" test_run/bob/log | grep -oE "12D3Koo[a-zA-Z0-9]+")
ID_CHARLIE=$(grep "Local Identity Initialized" test_run/charlie/log | grep -oE "12D3Koo[a-zA-Z0-9]+")

echo "Alice joining group with Bob and Charlie..."
echo "/join GRP_CORE $ID_BOB,$ID_CHARLIE" > test_run/alice/input
sleep 3
echo "Bob joining group..."
echo "/join GRP_CORE $ID_BOB" > test_run/bob/input # Bob just joins himself effectively or sees others
sleep 2
# Bob actually needs Alice's ID to join? No, JoinGroup takes members to share keys with.
ID_ALICE=$(grep "Local Identity Initialized" test_run/alice/log | grep -oE "12D3Koo[a-zA-Z0-9]+")
echo "/join GRP_CORE $ID_ALICE" > test_run/bob/input
sleep 5

echo "Alice sending group message..."
echo "/group GRP_CORE Halo tim P2P! Kita sudah online." > test_run/alice/input
sleep 10

# 7. Results
echo "=== ALICE LOG ==="
tail -n 20 test_run/alice/log
echo "=== BOB LOG ==="
tail -n 20 test_run/bob/log
echo "=== CHARLIE LOG ==="
tail -n 20 test_run/charlie/log

# 8. Cleanup
kill $RELAY_PID $ALICE_PID $BOB_PID $CHARLIE_PID
