#!/bin/bash
set -e

# Container names
ALICE="meshsage-client-a-1"
BOB="meshsage-client-b-1"
RELAY="meshsage-relay-server-1"

# Function to send command to a node (bypassing FIFO)
send_command() {
    local container=$1
    local cmd=$2
    echo "Sending to $container: $cmd"
    # Use the regular file path defined in docker-compose
    docker exec $container sh -c "echo '$cmd' > /tmp/p2p_cmd"
}

echo "Waiting for containers to be fully ready..."
sleep 15

echo "--- Peer IDs ---"
ALICE_ID=$(docker logs $ALICE 2>&1 | grep "Local Identity Initialized" | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"')
BOB_ID=$(docker logs $BOB 2>&1 | grep "Local Identity Initialized" | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"')
RELAY_ID=$(docker logs $RELAY 2>&1 | grep "Local Identity Initialized" | awk -F'peerID=' '{print $2}' | awk -F' ' '{print $1}' | tr -d '"')

echo "Alice: $ALICE_ID"
echo "Bob: $BOB_ID"
echo "Relay: $RELAY_ID"

echo "--- Registering Aliases ---"
send_command $ALICE "/register alice"
sleep 5
send_command $BOB "/register bob"
sleep 15

echo "--- Online Private Message Test ---"
echo "Alice sending message to @bob..."
send_command $ALICE "/msg @bob Halo Bob! Ini pesan online dari Alice di Docker."
sleep 15

echo "Checking Bob's logs for online message..."
if docker logs $BOB 2>&1 | grep -q "Halo Bob! Ini pesan online dari Alice di Docker."; then
    echo "SUCCESS: Bob received online message."
else
    echo "FAILED: Bob did NOT receive online message."
    echo "--- ALICE LOGS (Last 20 lines) ---"
    docker logs --tail 20 $ALICE
    echo "--- BOB LOGS (Last 20 lines) ---"
    docker logs --tail 20 $BOB
fi

echo "--- Offline Private Message Test ---"
echo "Stopping Bob..."
docker compose stop client-b
sleep 5

echo "Alice sending message to @bob (offline)..."
send_command $ALICE "/msg @bob Halo Bob! Pesan ini untukmu saat kamu offline."
sleep 10

echo "Starting Bob again..."
docker compose start client-b
sleep 15

echo "Bob triggering manual fetch..."
send_command $BOB "/fetch"
sleep 15

echo "Checking Bob's logs for offline message..."
if docker logs $BOB 2>&1 | grep -q "Halo Bob! Pesan ini untukmu saat kamu offline."; then
    echo "SUCCESS: Bob received offline message from mailbox."
else
    echo "FAILED: Bob did NOT receive offline message."
    echo "--- BOB LOGS (Last 50 lines) ---"
    docker logs --tail 50 $BOB
    echo "--- RELAY LOGS (Last 50 lines) ---"
    docker logs --tail 50 $RELAY
fi

echo "--- Test Complete ---"
