# Developer Walkthrough & System Architecture Guide

Welcome to the **Meshsage** development guide. This document serves as a comprehensive, developer-facing overview of the platform's architecture, cryptographic protocols, database layout, user interface design, and testing validation suite.

---

## 1. System Architecture & Component Layering

Meshsage is a completely decentralized, serverless peer-to-peer (P2P) messaging application. It is structured into four distinct layers:

```
┌────────────────────────────────────────────────────────┐
│               Terminal TUI (Bubble Tea)                │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│            Protocol & Cryptographic Services           │
│   (1:1 Double Ratchet, Sender Keys, X3DH, Aliases)     │
└─────┬────────────────────┬───────────────────────┬─────┘
      │                    │                       │
      ▼                    ▼                       ▼
┌───────────┐        ┌───────────┐           ┌───────────┐
│  SQLite   │        │ Kademlia  │           │ GossipSub │
│ Storage   │        │    DHT    │           │  PubSub   │
└───────────┘        └───────────┘           └───────────┘
```

### A. Networking Layer (libp2p)
*   **Kademlia DHT:** Used to advertise and locate peers, store routing records, and register cryptographic usernames/aliases.
*   **GossipSub:** The underlying PubSub protocol used for real-time group chat communication and cluster replication events.
*   **mDNS Discovery:** Enables automatic discovery of neighboring peers on the local area network (LAN) without requiring internet or DHT bootstrap relays.

### B. Cryptographic Layer
*   **X3DH (Extended Triple Diffie-Hellman):** Establishes a shared secret between two nodes when sending the first message, utilizing identity keys, ephemeral keys, and pre-keys uploaded to Relays.
*   **Double Ratchet:** Used for 1:1 messaging. It rotates encryption keys for every single message (Diffie-Hellman ratchet and KDF chain ratchet), guaranteeing **Forward Secrecy** and **Post-compromise Security**.
*   **Sender Key (Group Ratchet):** Used for group chat. Each member generates a local key (`GKEY`) and shares it securely via 1:1 Double Ratchet channels with other members. Group messages are published via GossipSub encrypted with the sender's current ratchet key.

### C. Storage Layer (SQLite)
A local SQLite database (running in WAL mode for safe concurrency) acts as the node's long-term memory:
*   **`pre_keys` / `skipped_keys`**: Manages cryptographic pre-keys for X3DH and skipped message keys to handle out-of-order packet delivery.
*   **`sessions`**: Stores Double Ratchet states, ratchet keys, and message counters per peer.
*   **`messages`**: Persists incoming/outgoing chat history.
*   **`alias_store`**: Maintains the map between human-readable usernames and libp2p Peer IDs.
*   **`group_metadata` / `group_members_v2`**: Stores group configurations, membership lists, roles (Creator vs Member), and signature verifications.

---

## 2. Key Protocol Workflows

### Workflow A: Username (Alias) Registration & Lookup
To prevent username hijacking, registrations must present a digital signature proving key ownership.
1.  **Registration:** The client signs `@alias + PeerID + PubKey` and registers it on closest DHT nodes.
2.  **DHT Validation:** Closest nodes verify the signature, ensure the alias isn't registered to a different key, and persist it to SQLite.
3.  **On-Demand Caching:** When resolving an alias, the resolver fetches it from closest nodes and caches it locally in SQLite for fast, offline future reads.

### Workflow B: End-to-End Encrypted Group Chats
Meshsage group chats support two models:
*   **SECURE (Closed):** The Creator signs group metadata. Adding or removing members broadcasts signed commands (`GCMD:ADD`, `GCMD:REMOVE`). When a member is removed or exits, remaining members automatically regenerate their local `GKEY`s (Forward Secrecy).
*   **UNSECURE (Open):** Anyone runs `/group-join <alias>`. The client resolves metadata from the DHT, queries the Creator for signature proofs, joins the GossipSub topic, and broadcasts `GCMD:JOIN`. Existing online members automatically record the peer and share their keys.

---

## 3. Terminal User Interface (TUI) Architecture

The user interface is built using **Bubble Tea** and **Lipgloss**, implementing a split-pane command line experience:
1.  **System Log Viewport (Top, Yellow Border):** Displays system-level logs (such as connection updates, key rotation events, and DHT queries) formatted with native ANSI terminal colors.
2.  **Chat Viewport (Middle, Blue Border):** Renders incoming user-facing messages, status receipts, latency statistics, and group announcements.
3.  **Status Bar (Green Background):** Shows the local Peer ID, registered alias, network role (Client vs Relay), and active peer connections.
4.  **Command Input (Bottom):** Text input field with focus toggles. Commands start with `/`.

### UI Controls:
*   **`Esc`**: Toggle focus between typing commands and scrolling viewports.
*   **`Tab`**: Switch scrolling active pane between System Logs and Chat Messages.
*   **`Ctrl-D`**: Dump raw plain-text logs directly to a text file.
*   **`Ctrl-C`**: Gracefully close all network services and exit.

---

## 4. Automated Testing Scenarios (E2E Validation)

The platform is validated using two automated Bash test scripts.

### Test Suite 1: Core Swarm & Messaging Scenarios
**Script:** `bash e2e_test_scenarios.sh`
*   **Scenario 1: 1:1 Messaging (Online):** Verifies X3DH handshakes and direct Double Ratchet messaging between Alice and Bob.
*   **Scenario 2: Store-and-Forward (Offline):** Stops Bob, has Alice send a message (stored on Relay), restarts Bob, and calls `/fetch` to decrypt the offline message.
*   **Scenario 3: Group Chat (Online):** Alice, Bob, and Charlie join a group and exchange messages over GossipSub.
*   **Scenario 4: Group Chat (Alternating Offline):** Simulates alternating offline sequences (e.g. Bob offline, Charlie online, then vice versa) and verifies offline group mailbox storage and recovery.
*   **Scenario 5: Hijacking Protection:** Verifies that Bob cannot register or hijack Alice's username (`@super-alice`) since his cryptographic signature does not match.

### Test Suite 2: Cryptographic Group Governance Scenarios
**Script:** `bash test_groups_e2e.sh`
*   **TEST 1: SECURE Group Invites:** Verifies closed group creation, invitation dispatch (`GINVITE`), auto-joining, and secure messaging.
*   **TEST 2: Forward Secrecy on Exit:** Verifies that when Bob leaves the closed group, remaining members rotate keys, preventing Bob from reading future messages.
*   **TEST 3: UNSECURE Group Joins:** Verifies public group creation, open joins without creator intervention, and automated key exchange.
*   **TEST 4: Forward Secrecy on Kick:** Verifies that when the Creator removes Bob, keys are rotated, blocking Bob from subsequent decryptions.

---

## 5. E2E Test Execution Logs Reference

### Swarm & Core Messaging Validation Output:
```text
==================================================
SKENARIO 1: 1:1 Messaging (Online) - Alice -> Bob
==================================================
>> SKENARIO 1: SUCCESS (Message received online)

==================================================
SKENARIO 2: 1:1 Messaging (Offline) - Alice -> Bob (Offline)
==================================================
>> SKENARIO 2: SUCCESS (Offline message received via Mailbox)

==================================================
SKENARIO 3: Group Chat (Online) - Alice, Bob, Charlie
==================================================
>> SKENARIO 3: SUCCESS (All online members received the group message)

==================================================
SKENARIO 4: Group Chat (Offline Alternately)
==================================================
>> SKENARIO 4: SUCCESS (Group offline alternation sync works perfectly)

==================================================
SKENARIO 5: Alias Hijacking Protection & Local Caching
==================================================
1. Alice registering @super-alice...
   -> Alice successfully registered @super-alice locally and on the swarm.
2. Bob attempting to register @super-alice (hijacking)...
   -> Bob was rejected when attempting to register @super-alice (Hijacking Protection Success!).
>> SKENARIO 5: SUCCESS
```

### Group Governance Validation Output:
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
