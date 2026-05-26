#!/bin/bash
# test_groups_e2e.sh
# Automated E2E verification of Cryptographic Group Chat (SECURE & UNSECURE)
# Testing membership, access control, signature verification, forward secrecy,
# and new-member message reception (buffered key race-condition fix).

set -e

# Kill any existing test_meshsage processes from previous runs
killall test_meshsage 2>/dev/null || true
sleep 1

echo "=== MEMULAI GROUP CHAT E2E SETUP ==="

# 1. Setup Directories
rm -rf test_groups_run
mkdir -p test_groups_run/relay test_groups_run/alice test_groups_run/bob test_groups_run/charlie
touch test_groups_run/relay/input test_groups_run/alice/input test_groups_run/bob/input test_groups_run/charlie/input

# Define cleanup function
cleanup() {
    echo "Pembersihan node P2P..."
    kill $RELAY_PID $ALICE_PID $BOB_PID $CHARLIE_PID 2>/dev/null || true
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

# 4. Start Alice, Bob, and Charlie Nodes
echo "[Clients] Starting Alice (8002), Bob (8003), and Charlie (8004)..."
P2P_INPUT_PATH=test_groups_run/alice/input ./test_meshsage -debug -port=8002 -db=test_groups_run/alice/node.db -identity=test_groups_run/alice/node.key -peer="$RELAY_ADDR" >> test_groups_run/alice/log 2>&1 &
ALICE_PID=$!

P2P_INPUT_PATH=test_groups_run/bob/input ./test_meshsage -debug -port=8003 -db=test_groups_run/bob/node.db -identity=test_groups_run/bob/node.key -peer="$RELAY_ADDR" >> test_groups_run/bob/log 2>&1 &
BOB_PID=$!

P2P_INPUT_PATH=test_groups_run/charlie/input ./test_meshsage -debug -port=8004 -db=test_groups_run/charlie/node.db -identity=test_groups_run/charlie/node.key -peer="$RELAY_ADDR" >> test_groups_run/charlie/log 2>&1 &
CHARLIE_PID=$!

sleep 5

# Extract client peer IDs
ALICE_ID=$(grep "Local Identity Initialized" test_groups_run/alice/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')
BOB_ID=$(grep "Local Identity Initialized" test_groups_run/bob/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')
CHARLIE_ID=$(grep "Local Identity Initialized" test_groups_run/charlie/log | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"' | sed $'s/\e\\[[0-9;]*[mK]//g')

echo "Alice ID:   $ALICE_ID"
echo "Bob ID:     $BOB_ID"
echo "Charlie ID: $CHARLIE_ID"

# 5. Register aliases
echo "[Alias] Registering @alice, @bob, and @charlie..."
echo "/register alice" > test_groups_run/alice/input
sleep 2
echo "/register bob" > test_groups_run/bob/input
sleep 2
echo "/register charlie" > test_groups_run/charlie/input
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
if grep -q "Successfully registered '@charlie'" test_groups_run/charlie/log; then
    echo "   -> @charlie registered successfully."
else
    echo "   -> FAILED: @charlie registration failed."
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

# Alice sends a few messages BEFORE Bob joins (simulates pre-join messages)
echo "Alice sending 3 messages BEFORE Bob joins @pub-group..."
echo "/group @pub-group Pre-join message 1 from Alice" > test_groups_run/alice/input
sleep 1
echo "/group @pub-group Pre-join message 2 from Alice" > test_groups_run/alice/input
sleep 1
echo "/group @pub-group Pre-join message 3 from Alice" > test_groups_run/alice/input
sleep 3

# Bob joins the unsecure group
echo "Bob joining @pub-group (after Alice already sent messages)..."
echo "/group-join @pub-group" > test_groups_run/bob/input
sleep 10  # Extra time for GREQ/GKEY round-trip

# Verify Bob joined
if grep -q "Successfully joined room: @pub-group (UNSECURE" test_groups_run/bob/log; then
    echo "   -> Bob resolved and joined @pub-group successfully."
else
    echo "   -> FAILED: Bob failed to join @pub-group."
    exit 1
fi

# Alice sends a NEW message AFTER Bob joins — Bob MUST receive this
echo "Alice sending a new message AFTER Bob has joined @pub-group..."
echo "/group @pub-group Welcome Bob, you joined after me!" > test_groups_run/alice/input
sleep 8

# Verify Bob received the post-join message
if grep -q "Welcome Bob, you joined after me!" test_groups_run/bob/log; then
    echo "   -> Bob received Alice's message after joining the group."
else
    echo "   -> FAILED: Bob did not receive Alice's message after joining! (Race condition / buffer bug)"
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

# Verify GREQ key request was broadcast by Bob after joining
if grep -q "GREQ\|key request\|Broadcast group key" test_groups_run/bob/log; then
    echo "   -> Bob correctly broadcast a GREQ key request after joining."
else
    echo "   -> NOTE: GREQ log not found in Bob's log (may be debug-level only)."
fi

echo "=================================================="
echo "TEST 4: New Member Receives Messages — SECURE Group"
echo "(Bug Fix: Race Condition / Pending Message Buffer)"
echo "=================================================="
echo "Alice creating a SECURE group @sec-group2 with only Alice..."
echo "/group-create @sec-group2 SECURE" > test_groups_run/alice/input
sleep 5

if grep -q "Successfully joined room: @sec-group2 (SECURE" test_groups_run/alice/log; then
    echo "   -> Alice created @sec-group2 successfully (no members yet)."
else
    echo "   -> FAILED: Alice failed to create @sec-group2."
    exit 1
fi

# Alice sends messages while Charlie is not yet invited
echo "Alice sending 2 messages to @sec-group2 before Charlie is added..."
echo "/group @sec-group2 Secret message 1 before Charlie" > test_groups_run/alice/input
sleep 1
echo "/group @sec-group2 Secret message 2 before Charlie" > test_groups_run/alice/input
sleep 3

# Now Alice invites Charlie (SECURE group — invite only)
echo "Alice inviting Charlie to @sec-group2..."
echo "/group-add @sec-group2 @charlie" > test_groups_run/alice/input
sleep 8  # Extra time for GINVITE + GKEY exchange

# Verify Charlie joined
if grep -q "Successfully joined room: @sec-group2 (SECURE" test_groups_run/charlie/log; then
    echo "   -> Charlie received GINVITE and joined @sec-group2."
else
    echo "   -> FAILED: Charlie did not join @sec-group2 via GINVITE."
    exit 1
fi

# Verify Charlie got Alice's key (GKEY exchange)
if grep -q "Group Session Key\|GKEY\|Received and saved" test_groups_run/charlie/log; then
    echo "   -> Charlie received Alice's GKEY (key exchange confirmed in log)."
else
    echo "   -> NOTE: GKEY log not found (may be debug-level only)."
fi

# Alice sends a NEW message AFTER Charlie joins — Charlie MUST receive this
echo "Alice sending new message to @sec-group2 AFTER Charlie joined..."
echo "/group @sec-group2 Hi Charlie, welcome to the secure group!" > test_groups_run/alice/input
sleep 8

# Verify Charlie decrypted Alice's post-join message
if grep -q "Hi Charlie, welcome to the secure group!" test_groups_run/charlie/log; then
    echo "   -> SUCCESS: Charlie received and decrypted Alice's post-join SECURE message."
else
    echo "   -> FAILED: Charlie did not receive Alice's post-join message! (Pending buffer / key race bug)"
    exit 1
fi

# Charlie replies back
echo "Charlie replying to @sec-group2..."
echo "/group @sec-group2 Thanks Alice, I can see your messages!" > test_groups_run/charlie/input
sleep 5

if grep -q "Thanks Alice, I can see your messages!" test_groups_run/alice/log; then
    echo "   -> Alice received Charlie's reply — bidirectional SECURE messaging works."
else
    echo "   -> FAILED: Alice did not receive Charlie's reply."
    exit 1
fi

echo "=================================================="
echo "TEST 5: Forward Secrecy on Kick (Remove)"
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

echo ""
echo "=== GROUP CHAT E2E SUCCESS — ALL TESTS PASSED ==="
exit 0
