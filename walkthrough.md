# Walkthrough: Developer Guide, Architectural Design, & E2E Verification

This document is a comprehensive guide to the overall development, architectural components, protocol workflows, and verification evidence of **Meshsage**—a distributed, decentralized peer-to-peer (P2P) messaging platform.

---

## 1. Architectural Component Layering

Meshsage is structured into clean layers to isolate user interactions, encryption protocols, network routing, and storage:

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

*   **User Interface Layer (TUI):** Built using **Bubble Tea** and **Lipgloss**, implementing a split-pane layout to isolate background logs from active conversations.
*   **Protocol & Cryptographic Layer:** Employs **X3DH** for key agreements, **Double Ratchet** for private chats, **Sender Keys** for group ratchets, and digital signatures for ownership checks.
*   **Network Transport Layer (libp2p):** Employs Kademlia DHT for peer routing, GossipSub for pub/sub messaging, and mDNS for offline local area discovery.
*   **Database Storage Layer (SQLite):** Maintains long-term persistence of key materials (pre-keys, active Double Ratchet sessions, skipped keys), messages, alias registries, and group memberships in WAL mode.

---

## 2. Changes Implemented & Component Features

### A. Split-Pane Terminal User Interface (TUI)
We replaced the old sequential terminal prints with a modern, split-pane TUI engine in `pkg/tui/tui.go` and refactored logging:
1.  **Unified Logger & Output Separation (`pkg/logger`):**
    *   Separated stdout prints: system actions (rotations, handshakes, GC, syncing) print to **system logs** (`logger.Info()`), while user-centric notifications (message text, pings, status reports) print to **chat display** (`logger.Displayf()`).
    *   Provided `DisplayWriter` and `SetOutput` to dynamically hook loggers into specific TUI panes at runtime.
2.  **TUI Engine Design Layout:**
    *   **📋 System Log (Top Pane):** Renders colored, structured logs with native ANSI escape codes in real-time.
    *   **💬 Chat Messages (Middle Pane):** Handles user-facing chats, status receipts, and file transfers.
    *   **📊 Node Status Bar:** Displays the Peer ID, resolved alias, active peer count, and node role (Client vs Relay).
    *   **Command Input Bar (Bottom):** Active input box with async command execution to prevent UI locks.
3.  **Keyboard Shortcuts:**
    *   `Esc`: Toggle focus between input typing and log/chat scroll viewports.
    *   `Tab` (when viewports are focused): Switch scrolling active pane between logs and chat messages (indicated by a green border).
    *   `Ctrl-D`: Save raw plain-text logs to a file `meshsage-logs-YYYYMMDD-HHMMSS.txt`.
    *   `Ctrl-C`: Safely shut down all services and exit.

### B. Concurrent Alias Registry & Local Caching
To optimize performance and enforce alias ownership without blocking commands:
1.  **Concurrent Registry Queries:** Previously, lookup loops dialed nodes sequentially, hanging for 10s if any peer was offline. We refactored both `RegisterAlias` and `ResolveAlias` to query closest DHT nodes **concurrently** using goroutines with a strict 2-second dial timeout.
2.  **Local Alias Persistence:** Ensured that a registering node immediately persists its own alias mapping in its local SQLite database and memory (`aliasStore` and `ownerStore`) upon registration, avoiding redundant self-queries.
3.  **Multi-Alias Ownership Support:** Removed the one-key-per-alias constraint. Creators are now permitted to register their own username alias and multiple group aliases concurrently without deleting previous entries, while keeping them protected from hijack attempts by verifying signatures against the registered public key.

### C. Network Stability & Reliability
Introduced optimizations to eliminate flaky network dials in E2E testing:
1.  **DHT Peer Routing (`FindPeer`):** Integrated `corenet.GlobalDHT.FindPeer(ctx, target)` as a fallback when peerstore address information is missing, resolving relay-assisted multiaddresses (like `p2p-circuit`).
2.  **DHT Rendezvous Discovery:** Configured rendezvous tagging so that local and cluster nodes automatically announce and connect to each other.
3.  **Self-Messaging Bypass:** Intercepted self-directed messages in `transmitEnvelope` (`target == h.ID()`) to process them locally, preventing loopback dial failures.
4.  **Test Environment Isolation:** Configured nodes using `-peer` to target local relays and bypass global seed directories (`DefaultSeeds`), preventing alias ownership conflicts.

### D. Cryptographic Group Governance (SECURE & UNSECURE Groups)
Implemented proper cryptographic group chat management featuring E2EE, governance signatures, and two membership models:
1.  **SECURE (Closed / Invite-only):** Creator signs metadata (binding GroupID, GroupAlias, CreatorID, and CreatedAt). Invitations (`GINVITE`) carry verified digital signatures. Kicking members (`/group-remove`) or exits (`/group-exit`) trigger an HMAC-based Group Ratchet key rotation (Forward Secrecy).
2.  **UNSECURE (Open / Public):** Anyone joins dynamically using `/group-join <alias>`. The client resolves metadata from the DHT, queries the Creator for signature proofs, joins the GossipSub topic, and broadcasts `GCMD:JOIN`. Existing members automatically save the peer and securely share their local key (`GKEY`) via 1:1 Double Ratchet channels.

---

## 3. Automated Testing Scenarios & Verification Evidence

We have two automated test suites to validate the entire platform:

### Test Suite 1: Core Messaging & Swarm Scenarios
**Script:** `bash e2e_test_scenarios.sh`
*   **Scenario 1: 1:1 Messaging (Online):** Alice sends an online message to Bob.
    *   *Bob's Log:* Verify initial X3DH handshake, shared secret derivation, session establishment, and plaintext decryption.
*   **Scenario 2: Store-and-Forward (Offline):** Stops Bob, Alice sends a message (Relay queues it), restarts Bob, Bob fetches it.
*   **Scenario 3: Group Chat (Online):** Alice, Bob, and Charlie join a group and exchange E2EE messages over GossipSub.
    *   *Alice's Log:* Verify `[GROUP E2EE] Original Text -> Encrypted Result (B64)` and local ratchet key rotation.
    *   *Bob's Log:* Verify `[GROUP E2EE] Decrypted Result` and signature verification.
*   **Scenario 4: Group Chat (Alternating Offline):** Simulates alternating offline sequences (Bob offline, Charlie online, then vice versa) and verifies offline group mailbox storage and recovery.
*   **Scenario 5: Hijacking Protection:** Verifies Bob is rejected when trying to register Alice's username (`@super-alice`) since his cryptographic signature does not match.

#### Verification Log Outputs (Core Scenarios):
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

---

### Test Suite 2: Cryptographic Group Governance Scenarios
**Script:** `bash test_groups_e2e.sh`
*   **TEST 1: SECURE Group Invites:** Verifies closed group creation, invitation dispatch (`GINVITE`), auto-joining, and secure messaging.
*   **TEST 2: Forward Secrecy on Exit:** Verifies that when Bob leaves the closed group, remaining members rotate keys, preventing Bob from reading future messages.
*   **TEST 3: UNSECURE Group Joins:** Verifies public group creation, open joins without creator intervention, and automated key exchange.
*   **TEST 4: Forward Secrecy on Kick:** Verifies that when the Creator removes Bob, keys are rotated, blocking Bob from subsequent decryptions.

#### Verification Log Outputs (Group Scenarios):
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

---

## 4. How to Execute Tests

Ensure the latest binaries are built before running the E2E scripts:
```bash
go build -o test_meshsage cmd/node/main.go
```

### Run Swarm Scenarios
```bash
bash e2e_test_scenarios.sh
```

### Run Cryptographic Group Governance Scenarios
```bash
bash test_groups_e2e.sh
```

---

## 5. Final Stability Bugfixes

### A. Dart Null List Type Cast Crash Resolution
When loading the joined groups list or fetching group details in the Flutter UI, Dart would intermittently crash with:
`Error loading joined groups: type 'Null' is not a subtype of type 'List<dynamic>' in type cast`
*   **Root Cause:** The Go shared library returned a marshaled `nil` slice as the JSON string `"null"`. When parsed in Dart via `json.decode()`, this resulted in a `null` object, which failed to cast to a Dart `List`.
*   **Resolution:** Modified `GetJoinedGroups` and `GetGroupInfo` in `cmd/libmeshsage/main.go` to explicitly initialize slices as empty non-nil slices (`groups := []GroupJSON{}` and `memberList := []MemberJSON{}`). They now serialize to `[]` instead of `null`, preventing the Dart type cast error.

### B. E2E Test Suite Execution Lock Resolution
When running `e2e_test_scenarios.sh` consecutively, scenario steps would intermittently fail due to locked SQLite databases or port conflicts.
*   **Root Cause:** Background P2P worker processes from previous runs were not being cleaned up, leaving orphan processes bound to ports and locking databases.
*   **Resolution:** Added proactive process termination (`killall p2p-node test_meshsage 2>/dev/null || true`) at the start of `e2e_test_scenarios.sh`, ensuring a clean environment for every E2E run.

---

## 6. ZKP-Secured Anonymous PubSub Handshake & Messaging

### Problem Addressed
When sending handshakes and messages offline via Mailbox or routing them through PubSub relays, the sender's identity (Peer ID) can be leaked, and relays are vulnerable to spam injection because they cannot authenticate senders without deanonymizing them.

### Solution Implemented
We implemented a **Zero-Knowledge Proof (ZKP) / Linkable Ring Signature (LSAG)** protocol over the NIST P-256 elliptic curve:

1. **Deterministic Key Derivation**: Nodes deterministically derive a P-256 ZKP keypair from their existing libp2p private key.
2. **Membership Registration**: Nodes register their ZKP public key on the relays during prekey refills. These public keys are synchronized across the cluster.
3. **ZKP Envelope Wrapping**: When storing offline messages in the mailbox, the envelope is wrapped in a ZKP ring signature:
   `ZKPEnvelope { C0, R, KeyImage, Ring, Payload }`
   The signature proves membership in the active registered user ring without revealing *which* member signed it.
4. **Relay Verification**: Mailbox relays verify the ring signature and check that all ring members are registered before storing and replicating the message, completely blocking spam.
5. **Auto-Unwrapping**: Receivers unmarshal the ZKP JSON envelope automatically on retrieval.

### Verification Results
All cryptographic and protocol integration unit tests passed successfully:
```text
=== RUN   TestZKPKeypairDerivation
--- PASS: TestZKPKeypairDerivation (0.00s)
=== RUN   TestRingSignatureLifecycle
--- PASS: TestRingSignatureLifecycle (0.01s)
=== RUN   TestRingSignatureLinkability
--- PASS: TestRingSignatureLinkability (0.00s)
=== RUN   TestZKPEnvelopeVerification
--- PASS: TestZKPEnvelopeVerification (0.02s)
PASS
```

---

## Walkthrough: TUI Concurrent Buffer Reuse Fix

### Problem Solved
On the Terminal User Interface (TUI), chat messages and system logs would occasionally get garbled, mixed up, or scrambled (e.g. status reports mixed with fetch counts or peer IDs like `1ount=complete27:47+07:0027RCKqy...`). This occurred during periods of concurrent network/messaging activity (such as after starting up and retrieving multiple messages/status updates).

The cause was a classic **concurrency buffer-reuse race condition**:
1. The custom `logWriter` and `chatWriter` in [tui.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/tui/tui.go) received log payload slices (`p []byte`) from the logging framework.
2. These raw byte slices were directly wrapped as custom types (`logMsg(p)` / `chatMsg(p)`) and sent asynchronously to Bubble Tea's main event queue via `w.program.Send(...)`.
3. Since `program.Send` is non-blocking, the log writer immediately returned and released/reused the underlying byte slice `p` for subsequent log entries before Bubble Tea had a chance to dequeue and process/convert it to string.
4. When Bubble Tea finally read the bytes to render them, the array had already been overwritten by newer logging events.

### Changes Made
- Updated type definitions of `logMsg` and `chatMsg` in [tui.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/tui/tui.go) from `[]byte` to `string`.
- Modified `Write` methods in `logWriter` and `chatWriter` to convert the byte slice to a Go string (`string(p)`) immediately before dispatching it. This forces Go to allocate and copy the data, preserving the message contents from being overwritten by subsequent concurrent log operations.

### Verification Results
- Built the node binary successfully (`go build -o build/node ./cmd/node`) with no errors.
- Verified that all unit tests under `pkg/` pass successfully.

---

## Walkthrough: ZKP Startup Clean Fix

### Problem Solved
When a client fell back to sending messages via mailbox, it wrapped the message in a Zero-Knowledge Proof (ZKP) linkable ring signature. However, the mailbox/relay node would sometimes reject the envelope with:
`REJECTED: ZKP verification failed (spammer or invalid membership proof) error="ring contains unregistered pub"`

This was caused by the sender's local `zkp_members` database containing old, stale, or residual ZKP public keys (e.g. from previous app runs, old tests, or reinstalled peer IDs) that did not exist on the relay node's database. Because the relay node must verify that every single public key in the ZKP signature ring is active and registered, any unregistered key in the ring would cause the verification to fail.

### Changes Made
1. **Added `CleanZKPMembersExceptOwner`** in [database.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/storage/database.go) to delete all ZKP public keys in the local database except the node's own key.
2. **Integrated with Startup Refill** in [prekey.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/prekey.go): During the first pre-key refill on startup (`forceCleanRefill = true`), the client runs `CleanZKPMembersExceptOwner` to clear stale third-party keys. 

As other active nodes check in and broadcast their new keys via Gossip PubSub, they are dynamically re-added to the client's `zkp_members` database, ensuring that only active, verified keys are used to construct the ring signature.

### Verification Results
- All Go unit tests under `pkg/` compiled and passed.
- Successfully recompiled Android native shared libraries for all architectures (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).
- Successfully rebuilt and repackaged the Flutter release APK (`meshsage.apk`) and installed it on the running emulator (`emulator-5554`) with no errors.

---

## Walkthrough: Proactive Session Warm-up Probe

### Problem Solved
Previously, there was no proactive check or handshake setup when known chat peers reconnected. If a session did not exist or was outdated, the first message sent by a user would have to perform an inline X3DH handshake (fetching pre-keys from the relay, generating ephemeral keypairs, and deriving secrets). This introduced a 1-2 second delay on the first message. Additionally, without a warm-up probe, decryption issues or session mismatches would only be discovered when the user attempted to send/receive an actual chat message.

### Changes Made
1. **Added `HasSession`** in [database.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/storage/database.go): A lightweight query that checks if an active Double Ratchet session already exists with the given peer.
2. **Added `ProbeSessionWarmup`** in [messaging.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go): If a session exists, sends a silent `MsgTypeHandshakeAck` probe to the peer. This causes the peer to perform a Double Ratchet step, warming up the channel and establishing mutual bidirectional session health.
3. **Integrated with ConnectedF Handlers**:
   - Modified `cmd/node/main.go` to invoke `ProbeSessionWarmup` in the background when a non-infrastructure peer connects and a session is found in the local DB.
   - Modified `cmd/libmeshsage/main.go` (the Android core native library entrypoint) to also trigger this proactive probe on peer connection.

### Verification Results
- All Go unit tests under `pkg/` compiled and passed.
- Successfully built `cmd/node/main.go` and `cmd/libmeshsage/main.go`.
- Recompiled Android native shared libraries (`libmeshsage.so`) and packaging.
- Rebuilt and packaged the Flutter release APK (`meshsage.apk`) successfully.



