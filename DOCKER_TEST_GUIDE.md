# P2P SDK Manual Testing Guide 🧪

This guide details instructions to verify new features (Binary Protocol, Cluster Sync, Adaptive Relay) using Docker Compose.

---

## 1. Environment Setup
Launch all services:
```bash
docker-compose down
docker-compose up --build -d
```
Check status: `docker-compose ps`

---

## 2. Test Scenario 1: Binary Messaging & E2EE
**Objective:** Verify encrypted binary message delivery.

1.  **Open Client A logs:**
    `docker logs -f distributed-messaging-platform-client-a-1`
2.  **Open Client B logs:**
    `docker logs -f distributed-messaging-platform-client-b-1`
3.  **Send Message:** Type a message in Client A's input field.
4.  **Expected Result:**
    - Logs show `[E2EE DEBUG] Sending Encrypted Payload`.
    - No raw plaintext is visible in the server logs.
    - Messages arrive at Client B within milliseconds.

---

## 3. Test Scenario 2: Offline Mailbox & Cluster Sync 🔄
**Objective:** Confirm offline messages remain queued in the relay cluster.

1.  **Retrieve Client B's Peer ID:** Record the PeerID output when Client B first starts.
2.  **Stop Client B:**
    `docker-compose stop client-b`
3.  **Client A sends offline message to Relay:**
    From Client A: `/store <PeerID_Client_B> Hello from the past!`
4.  **Verify Cluster Sync:**
    Check Relay logs: `docker logs relay-server`
    Expected output: `[Cluster] Syncing mailbox message for <ID>`
5.  **Restart Client B & Fetch Messages:**
    `docker-compose start client-b`
    From Client B: `/fetch`
6.  **Expected Result:**
    - "Hello from the past!" appears on Client B.
    - Relay log shows: `[Mailbox DHT] Delivered and sent PURGE signal`.
    - All synced copies in the cluster are purged automatically.

---

## 4. Test Scenario 3: Adaptive Relay (Smart Mode) 🧠
**Objective:** Verify data-saving behavior in low-resource environments.

1.  **Start Client C in Client-Only mode:**
    Update `docker-compose.yml` command for client-c: `command: ["./p2p-node", "-client-only=true"]`
2.  **Restart Client C:** `docker-compose restart client-c`
3.  **Attempt forwarding a message to Client C as Relay:**
    Try sending a message for transit through Client C.
4.  **Expected Result:**
    - Client C logs show a soft rejection of incoming transit streams.
    - Client C continues to send/receive its own messages, but refuses transit requests.

---

## 5. Test Scenario 4: Multimedia File Sharing 📂
**Objective:** Verify file upload/download capabilities.

1.  **Upload File from Client A:**
    From Client A: `/upload /app/p2p-node` (uploading its own binary)
2.  **Send Notification to Client B:**
    Retrieve the CID and Key from the upload output, and send them to Client B (via chat or `/store`).
3.  **Download on Client B:**
    From Client B: `/download <CID> <KEY>`
4.  **Expected Result:**
    - File is downloaded to `/tmp/downloaded_file.bin`.
    - Logs show Bitswap fetching file chunks in parallel.

---

**Happy Bug Hunting! 🐞**  
If issues arise, check the database contents directly:  
`sqlite3 p2p_node.db "SELECT * FROM mailbox;"`
