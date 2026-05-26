#!/bin/bash
# test_groups_e2e.sh
# Automated E2E verification of Cryptographic Group Chat (SECURE & UNSECURE)
# Testing membership, access control, signature verification, and forward secrecy.

set -e

# Kill any existing test_meshsage processes from previous runs
killall test_meshsage 2>/dev/null || true
sleep 1

echo "=== MEMULAI GROUP CHAT E2E SETUP ==="

# 1. Setup Directories
rm -rf test_groups_run
mkdir -p test_groups_run/relay test_groups_run/alice test_groups_run/bob
touch test_groups_run/relay/input test_groups_run/alice/input test_groups_run/bob/input

# Define cleanup function
cleanup() {
    echo "Pembersihan node P2P..."
    kill $RELAY_PID $ALICE_PID $BOB_PID 2>/dev/null || true
    killall test_meshsage 2>/dev/null || true
    rm -f test_meshsage
}
trap cleanup EXIT

# 2. Compile latest meshsage binary
echo "[Compile] Building latest meshsage binary..."
go build -o test_meshsage ./cmd/node

# 3. Start Dedicated Relay Node
echo "[Relay] Starting Relay on port 8001..."
P2P_INPUT_PATH=test_groups_run/relay/input ./test_meshsage -debug -dedicated=true -port=8001 -db=test_groups_run/relay/node.db -identity=test_groups_run/relay/node.key > test_groups_run/relay/log 2>&1 &
RELAY_PID=$!
sleep 3

# Extract Relay Address
RELAY_ID=$(grep "Local Identity Initialized" test_groups_run/relay/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')
RELAY_ADDR="/ip4/127.0.0.1/tcp/8001/p2p/$RELAY_ID"
echo "Relay Address: $RELAY_ADDR"

# 4. Start Alice and Bob Nodes
echo "[Clients] Starting Alice (8002) and Bob (8003)..."
P2P_INPUT_PATH=test_groups_run/alice/input ./test_meshsage -debug -port=8002 -db=test_groups_run/alice/node.db -identity=test_groups_run/alice/node.key -peer="$RELAY_ADDR" >> test_groups_run/alice/log 2>&1 &
ALICE_PID=$!

P2P_INPUT_PATH=test_groups_run/bob/input ./test_meshsage -debug -port=8003 -db=test_groups_run/bob/node.db -identity=test_groups_run/bob/node.key -peer="$RELAY_ADDR" >> test_groups_run/bob/log 2>&1 &
BOB_PID=$!

sleep 5

# Extract client peer IDs
ALICE_ID=$(grep "Local Identity Initialized" test_groups_run/alice/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')
BOB_ID=$(grep "Local Identity Initialized" test_groups_run/bob/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')

echo "Alice ID: $ALICE_ID"
echo "Bob ID: $BOB_ID"

# 5. Register aliases
echo "[Alias] Registering @alice and @bob..."
echo "/register alice" > test_groups_run/alice/input
sleep 2
echo "/register bob" > test_groups_run/bob/input
sleep 5

# Verify alias registration
if grep -q "Successfully registered '@alice'" test_groups_run/alice/log; then
    echo "   -> @alice registered successfully."
else
    echo "   -> FAILED: @alice registration failed."
    exit 1
fi
if grep -q "Successfully registered '@bob'" test_groups_run/bob/log; then
    echo "   -> @bob registered successfully."
else
    echo "   -> FAILED: @bob registration failed."
    exit 1
fi

echo "=================================================="
echo "TEST 1: SECURE (Closed/Invite) Group Chat"
echo "=================================================="
echo "Alice creating SECURE group @sec-group inviting @bob..."
echo "/group-create @sec-group SECURE @bob" > test_groups_run/alice/input
sleep 5

# Verify group creation
if grep -q "Successfully joined room: @sec-group (SECURE" test_groups_run/alice/log; then
    echo "   -> Alice created @sec-group successfully."
else
    echo "   -> FAILED: Alice failed to create @sec-group."
    exit 1
fi

# Verify invitation received & auto-joined by Bob
if grep -q "Successfully joined room: @sec-group (SECURE" test_groups_run/bob/log; then
    echo "   -> Bob auto-joined @sec-group invitation successfully."
else
    echo "   -> FAILED: Bob did not auto-join @sec-group."
    exit 1
fi

# Send SECURE group message from Alice
echo "Alice sending message to @sec-group..."
echo "/group @sec-group Hello Bob in closed room!" > test_groups_run/alice/input
sleep 5

# Verify Bob decrypted the message
if grep -q "Hello Bob in closed room!" test_groups_run/bob/log; then
    echo "   -> Bob successfully received and decrypted the secure message."
else
    echo "   -> FAILED: Bob did not receive the secure message or failed to decrypt."
    exit 1
fi

# Send SECURE group message from Bob
echo "Bob sending message to @sec-group..."
echo "/group @sec-group Hi Alice!" > test_groups_run/bob/input
sleep 5

# Verify Alice decrypted Bob's message
if grep -q "Hi Alice!" test_groups_run/alice/log; then
    echo "   -> Alice successfully received and decrypted Bob's message."
else
    echo "   -> FAILED: Alice did not receive Bob's message."
    exit 1
fi

echo "=================================================="
echo "TEST 2: Forward Secrecy on Voluntary Exit"
echo "=================================================="
echo "Bob voluntary exiting @sec-group..."
echo "/group-exit @sec-group" > test_groups_run/bob/input
sleep 5

# Verify Bob left locally
if grep -q "You left group @sec-group successfully" test_groups_run/bob/log; then
    echo "   -> Bob local database exited @sec-group."
else
    echo "   -> FAILED: Bob failed to leave @sec-group locally."
    exit 1
fi

# Verify Alice knows Bob left
if grep -q "left the group" test_groups_run/alice/log; then
    echo "   -> Alice received Bob exit control command."
else
    echo "   -> FAILED: Alice did not process Bob exit command."
    exit 1
fi

# Alice sends a message after Bob left (Key rotation happens)
echo "Alice sending message to @sec-group after Bob left..."
echo "/group @sec-group Bob has left, I am alone." > test_groups_run/alice/input
sleep 5

# Verify Bob does NOT receive/decrypt the new message
if grep -q "Bob has left, I am alone." test_groups_run/bob/log; then
    echo "   -> FAILED: Bob received message after exiting! Forward secrecy failed."
    exit 1
else
    echo "   -> SUCCESS: Bob did not receive messages sent after exiting."
fi

echo "=================================================="
echo "TEST 3: UNSECURE (Open/Public) Group Chat"
echo "=================================================="
echo "Alice creating UNSECURE group @pub-group..."
echo "/group-create @pub-group UNSECURE" > test_groups_run/alice/input
sleep 5

# Verify creation
if grep -q "Successfully joined room: @pub-group (UNSECURE" test_groups_run/alice/log; then
    echo "   -> Alice created @pub-group successfully."
else
    echo "   -> FAILED: Alice failed to create @pub-group."
    exit 1
fi

# Bob joins the unsecure group
echo "Bob joining @pub-group..."
echo "/group-join @pub-group" > test_groups_run/bob/input
sleep 8

# Verify Bob joined
if grep -q "Successfully joined room: @pub-group (UNSECURE" test_groups_run/bob/log; then
    echo "   -> Bob resolved and joined @pub-group successfully."
else
    echo "   -> FAILED: Bob failed to join @pub-group."
    exit 1
fi

# Bob sends a group message
echo "Bob sending message to @pub-group..."
echo "/group @pub-group Hello everyone in public room!" > test_groups_run/bob/input
sleep 5

# Verify Alice received it
if grep -q "Hello everyone in public room!" test_groups_run/alice/log; then
    echo "   -> Alice received Bob's message in the open group."
else
    echo "   -> FAILED: Alice did not receive Bob's message."
    exit 1
fi

echo "=================================================="
echo "TEST 4: Forward Secrecy on Kick (Remove)"
echo "=================================================="
echo "Alice removing Bob from @pub-group..."
echo "/group-remove @pub-group @bob" > test_groups_run/alice/input
sleep 5

# Verify Bob was kicked
if grep -q "You have been removed from group @pub-group" test_groups_run/bob/log; then
    echo "   -> Bob was kicked and removed from @pub-group locally."
else
    echo "   -> FAILED: Bob did not process removal."
    exit 1
fi

# Alice sends a message after Bob is kicked
echo "Alice sending message to @pub-group after kicking Bob..."
echo "/group @pub-group I kicked Bob." > test_groups_run/alice/input
sleep 5

# Verify Bob does NOT receive/decrypt the new message
if grep -q "I kicked Bob." test_groups_run/bob/log; then
    echo "   -> FAILED: Bob received message after being kicked! Forward secrecy failed."
    exit 1
else
    echo "   -> SUCCESS: Bob did not receive messages sent after being kicked."
fi

echo "=== GROUP CHAT E2E SUCCESS ==="
exit 0
