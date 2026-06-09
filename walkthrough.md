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

---

## Walkthrough: Fixed Group Invite Signature Verification (Timestamp Drift Fix)

### Problem Solved
When a client received a group invitation (`GINVITE`), they failed to join with the error:
`[16:58:07] 2026-06-02T09:58:07Z ERR Received GINVITE with INVALID signature! group=@kesinidulu`

This was caused by a split-second difference (timestamp drift) between the metadata signature creation and when the metadata was actually stored in the database:
1. During group creation (`CreateGroupProper`), the creator generated `createdAt = time.Now().Unix()` and signed the group metadata using it.
2. The creator then called `JoinGroupProper`, which saved the metadata to the database, but overrode `CreatedAt` with a newly generated `time.Now().Unix()`.
3. When adding members, the creator loaded the metadata from the database (with the drifted timestamp) and sent it in the `GINVITE` payload.
4. The recipient calculated the signature verification payload using the drifted `createdAt` timestamp from the database. Because it differed from the originally signed timestamp, the signature verification failed.

### Changes Made
1. **Parameter Addition**: Modified `JoinGroupProper` in `group.go` to accept `createdAt int64`. If `createdAt` is `0`, it defaults to `time.Now().Unix()`.
2. **Propagated Correct Timestamp**:
   - In `messaging.go`, updated the `GINVITE` incoming handler, the `/group-create` local command handler, and the `/group-join` local command handler to pass the correct `createdAt` timestamp.
   - In `main.go`, updated `CreateGroupProper` and `JoinGroupProper` FFI functions to pass the signed `createdAt` / `meta.CreatedAt` timestamp to the core Go library.

### Verification Results
1. **Unit Tests**: All 19 unit tests in `pkg/protocol` compiled and passed successfully:
   ```text
   ok  	github.com/nicabreon/meshsage/pkg/protocol	0.902s
   ```
2. **Android Builds**:
   - Recompiled native Android libraries (`libmeshsage.so`) for all architectures (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).
   - Rebuilt the Flutter release APK (`meshsage.apk`) successfully and copied it to the workspace directory.

---

## Walkthrough: Offline Invitation Envelope Sorting & Group Alias PM Block

### Problem Solved
1. **Offline Invitation Decryption Failure:** When a group creator invited an offline member, they sent a `GINVITE` (carried in an `X3DH` envelope) and then immediately sent group messages (carried in `DR` envelopes). When the invitee came online and fetched messages from their mailbox, the mailbox relay returned these envelopes without guaranteeing delivery order. If a `DR` envelope was processed before the `X3DH` handshake envelope, the recipient node could not decrypt it because no secure session existed yet. This triggered a `REQUEST_X3DH` reset back to the creator, which erased the creator's active session, causing permanent decryption failures and infinite handshake loops.
2. **Private Messages to Group Aliases:** Group aliases are registered on the DHT to point to the creator's Peer ID (so members can resolve group metadata). However, running `/msg @group_alias` in the CLI/TUI or calling the `SendDirectMessage` FFI function with a group alias resolved to the creator's Peer ID and mistakenly delivered private messages to the group creator.

### Changes Made

#### 1. Go Backend: Mailbox Envelope Sorting
- Modified `FetchMailboxMessages` in [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go) to buffer all fetched envelopes into a slice during the read loop.
- Sorted the slice stable so that payloads starting with `X3DH:` are placed first.
- Processed the sorted envelopes sequentially using `ProcessSecureEnvelope` so that cryptographic handshakes are fully established before any Double Ratchet (DR) messages are decrypted.

#### 2. Go Backend: Block PM to Group Aliases
- Modified `resolveTargetPeerID` in [messaging.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go) to verify if the target alias represents a group by checking local group metadata database (`LoadGroupMetadata`) or querying remote group metadata (`ResolveGroupMetadata`). If it is a group, the resolution is rejected with an error: `'@group_alias' is a group alias, cannot send private messages to it`.
- Added the same verification steps to the FFI entrypoint `SendDirectMessage` in [main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/libmeshsage/main.go) to return: `Failed to resolve alias: @group_alias is a group alias, cannot send private messages to it`.

### Verification Results
1. **Unit Tests:** All unit tests in `pkg/protocol/...` passed successfully.
2. **E2E Swarm Tests:** Ran the full E2E swarm test suite (`./test_groups_e2e.sh`), confirming that secure closed/open group invitations, join operations, key updates, and exits work perfectly.
3. **Flutter App Recompile:** Rebuilt the native library binaries using `./build_android.sh` and successfully recompiled the Flutter Android APK (`meshsage.apk`).


---

## Walkthrough: Media File Replication to Dedicated Relays

### Problem Solved
When a sender behind a symmetric NAT or private network uploaded a file, other nodes in the network could not download the file blocks directly from the sender's local storage block service via Bitswap dial. This resulted in downloads hanging in a permanent loading state.

### Changes Made
1. **Overlayed Replication Protocol:** Added a `REPLICATE <manifestCID>` command to the existing `/p2p-core/mailbox/1.0.0` protocol, allowing communication over active outbound mailbox streams without requiring additional port/protocol registrations.
2. **Replication Command Handler on Relays:**
   - Modified `handleMailboxStream` in [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go) to handle `REPLICATE`.
   - The relay decodes the CID, fetches the file manifest block, parses the JSON to extract the CIDs of all file chunks, and downloads all chunk blocks via Bitswap, caching them in the relay's in-memory datastore.
3. **Sender Replication Trigger:**
   - Implemented `ReplicateFileToRelays` in [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go) to discover connected Dedicated Relays (marked by `/p2p-core/infra/dedicated/1.1.0`) and request replication.
   - Updated `UploadFile` in [main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/libmeshsage/main.go) to trigger replication asynchronously immediately after a successful upload.

---

## Walkthrough: Media Previews & Zoomable Image Viewer

### Problem Solved
1. **Raw JSON in Previews:** In both the Direct Chat and Group Chat tabs, media messages (images, videos, audio) showed raw serialized JSON metadata in the last message preview instead of clean, user-friendly labels.
2. **Static Image Bubble:** Clicked images in the chat room could not be enlarged or zoomed, making it difficult to view details.

### Changes Made
1. **Friendly Preview Getter:**
   - Added a `displayContent` getter to the `ChatMessage` model in [p2p_state.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/p2p_state.dart) that maps media message types to friendly indicators like `📷 Image`, `🎥 Video`, or `🎵 Audio`.
   - Refactored [direct_chat_tab.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/tabs/direct_chat_tab.dart) and [group_chat_tab.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/tabs/group_chat_tab.dart) to display `displayContent` instead of raw `content`.
2. **Interactive Image Zoom Viewer:**
   - Implemented `FullScreenImageViewer` using Flutter's built-in `InteractiveViewer` to allow users to zoom (pinch) and pan images in full screen.
   - Wrapped the downloaded image in `ImageBubble` inside [chat_room_screen.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/screens/chat_room_screen.dart) with a `GestureDetector` that routes to `FullScreenImageViewer` on tap.

### Verification Results
1. **Go package tests passed:** All tests under `pkg/protocol` compiled and passed.
2. **Successful Rebuild:** The native libraries compiled successfully for all architectures using `build_android.sh`.
3. **Flutter APK Built:** The Flutter release APK (`meshsage.apk`) built and packaged the new assets successfully.

---

## Walkthrough: Android Foreground Service & Local Notifications

### Problem Solved
1. **Background App Suspension:** When the mobile client was minimized or backgrounded, the OS suspended CPU cycles and network access (Doze Mode), stopping the P2P message sync.
2. **Missing Notification Support:** There was no notification channel or system banner to alert the user of new incoming messages when the app was minimized or in the foreground.

### Changes Made
1. **Foreground Service & Wake Lock:**
   - Declared `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`, and `WAKE_LOCK` permissions in [AndroidManifest.xml](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/android/app/src/main/AndroidManifest.xml).
   - Created [P2PBackgroundService.kt](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/android/app/src/main/kotlin/com/nicabreon/meshsage/meshsage_flutter/P2PBackgroundService.kt) to manage a persistent background service running under the compliant `dataSync` category. The service displays an ongoing sync notification.
   - Updated [MainActivity.kt](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/android/app/src/main/kotlin/com/nicabreon/meshsage/meshsage_flutter/MainActivity.kt) to auto-start the background service on startup.
2. **Runtime Permission Prompt:**
   - Modified `MainActivity.kt` to trigger the Android `POST_NOTIFICATIONS` runtime permission request dialog automatically on startup for Android 13+ devices, ensuring standard compliance.
3. **Local Message Notifications (MethodChannel):**
   - Configured a MethodChannel (`com.nicabreon.meshsage/notifications`) in `MainActivity.kt` to allow Flutter to trigger system notifications.
   - In [p2p_state.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/p2p_state.dart), added a trigger that fires whenever a new message is received from a peer (`!isMe`).
   - The notification title dynamically displays either the sender's alias/display name or the group title formatted as `Group (Sender)`. The notification body displays the message content formatted cleanly via `displayContent` (e.g. `📷 Image` or the text body).

### Verification Results
1. **Successful Rebuild:** The Flutter app compiled and built successfully with the new Android configurations.
2. **Permissions Prompt Verified:** Tested on the emulator running Android 16 (API 36); the app successfully prompts for notification access on first launch.
3. **Background Sync Active:** Verified that minimizing the app displays a persistent notification drawer item showing "Meshsage P2P Active", preventing OS suspension.
4. **Heads-up Notifications Verified:** Verified that incoming messages trigger a heads-up system banner notification with sound.
5. **Chat Input Spacing Alignment:** Removed default IconButton padding/constraints and set the spacing between the attachment button and the message input field to 12dp, aligning the button to the left edge of the screen container and optimizing readability.

---

## Walkthrough: Dashboard Layout Expansion & Chat Field Optimization

### Problem Solved
1. **Dashboard Empty Space & Fixed Height Logs:** On devices with larger vertical height, the "LIVE NETWORK LOGS" console had a fixed height of `240` and the page used a `SingleChildScrollView`. This caused the logs console to float in the middle of the screen, leaving a massive empty gap between the console and the bottom navigation bar.
2. **Chat Room Placeholder Wrap:** On narrower screens, the text field hint text `"Type an encrypted message..."` was too long, causing it to wrap awkwardly onto two lines and increase the height of the message input box.

### Changes Made
1. **Interactive Expanded Logs Console:**
   - Removed the `SingleChildScrollView` layout wrapper from [dashboard_tab.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/tabs/dashboard_tab.dart) to enable bounded vertical constraints.
   - Wrapped the logs console container in an `Expanded` widget, allowing it to stretch and fill all remaining vertical space on the screen dynamically across all devices.
   - Removed `shrinkWrap: true` from the `ListView.builder` inside the console container for optimal scrolling performance.
   - Set the bottom padding of the dashboard page container to `0` to keep the logs console tightly aligned and flush with the top of the bottom navigation bar.
2. **Shortened Chat Placeholder Hint:**
   - Modified [chat_room_screen.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/screens/chat_room_screen.dart) to change the input text field hint text from `"Type an encrypted message..."` to `"Type message..."`. This prevents wrapping on narrower screens and keeps the input interface compact and clean.

### Verification Results
1. **Dashboard Layout Verified:**
   - Captured screen layout from emulator `emulator-5554` showing the logs console successfully filling the remaining screen space and resting flush against the bottom navigation bar:
     ![Dashboard Layout](/Users/nicabreon/.gemini/antigravity-ide/brain/c843137f-2236-403f-b820-8454a27169bd/new_screenshot.png)
2. **Chat Input Field Verified:**
   - Verified that the placeholder hint text `"Type message..."` sits on a single line cleanly:
     ![Chat Screen Placeholder](/Users/nicabreon/.gemini/antigravity-ide/brain/c843137f-2236-403f-b820-8454a27169bd/new_screenshot_chat.png)

---

## Walkthrough: Android Task Affinity Resolution (Duplicate Entries in Overview Screen)

### Problem Solved
When checking the Android Recent Apps / Overview screen, the `meshsage` app would sometimes show up as two separate instances (duplicate entries in the recents list). This was caused by the presence of `android:taskAffinity=""` inside the `<activity>` tag of `MainActivity` in `AndroidManifest.xml`.
An empty `taskAffinity` prevents the system from grouping activity launches from different contexts (such as launching via a notification/service click, development tools/ADB, or direct launcher clicks) into the same task stack, leading Android to create separate tasks and duplicate windows in the recent apps overview.

### Changes Made
- Removed `android:taskAffinity=""` from the `.MainActivity` definition in [AndroidManifest.xml](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/android/app/src/main/AndroidManifest.xml).

### Verification Results
- Successfully rebuilt the release APK and deployed it on the emulator `emulator-5554`.
- Verified that subsequent launches (via ADB and direct launcher actions) now target a unified single instance of the application, avoiding duplicate task creation in the Recent Apps overview.

---

## Walkthrough: Disabled Session Warm-up & Enhanced Mailbox Diagnostic Logs

### Problem Solved
1. **Unwanted Mailbox Handshake Messages:** The proactive session warm-up feature sent `MsgTypeHandshakeAck` messages to known peers upon connection. If the target peer went offline or the connection was not fully routable, this probe fell back to mailbox storage. When the peer fetched from their mailbox, they fetched the handshake probe (count=1), which was processed silently without showing a user-visible chat message. This caused confusion (fetching a message but showing nothing in the chat room).
2. **Silent Mailbox Fetch and Processing Skips:** If a mailbox message base64 payload, public key, or sender ID failed to parse, or if an envelope failed to decrypt, it was either skipped silently or debug-logged (which does not appear in standard TUI/Dashboard logs). 

### Changes Made
1. **Disabled Warm-up Probes:**
   - Disabled calling `ProbeSessionWarmup` upon peer connection in both [main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/node/main.go) and [main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/libmeshsage/main.go). It has been replaced with a simple debug trace log.
2. **Explicit Mailbox Fetch Logs:**
   - Modified [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go) to use `logger.Error()` or `logger.Warn()` during message base64 decoding, public key unmarshalling, and sender ID derivation.
   - Changed duplicate check logging to `logger.Info()`.
   - Adjusted `foundCount++` to only increment for messages successfully parsed and appended to the fetched list.
3. **Decryption & Payload System Logs:**
   - Modified `ProcessSecureEnvelope` in [messaging.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go) to log an Info trace indicating the prefix type (`DR`, `X3DH`, `RESET`, `REQUEST_X3DH`) and sender ID of the envelope being processed.
   - Added Info logs indicating successful Double Ratchet or X3DH decryption.
   - Added an Info log in `handleIncomingPayload` indicating when a standard text message is successfully saved to SQLite and sent to the UI callback.

### Verification Results
- Successfully rebuilt the native libraries using `./build_android.sh` and recompiled the Flutter Android APK.
- Verified that the application boots and logs successfully on the emulator without any warmup probe logs, and mailbox messages log detailed success and error state information.

---

## Walkthrough: Relay Rate Limit Reduction to 1ms

### Problem Solved
The mailbox relay rate-limited requests from the same Peer ID if they arrived within 50ms of each other, returning `ERROR_RATE_LIMIT_EXCEEDED`. On startup/reconnection, the client concurrently triggered both `AutoRefillPreKeys` and `FetchMailboxMessages` (which are separate requests targeting the mailbox protocol). This caused one of them (usually the fetch) to get rate-limited and fail, delaying mailbox synchronization.

### Changes Made
- Modified the rate-limit window from `50*time.Millisecond` to `1*time.Millisecond` in [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go).
- Staggered the initial mailbox fetch on startup by 100ms in [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go) to avoid overlapping requests.

### Verification Results
- Recompiled the Android shared libraries (`./build_android.sh`) and rebuilt/deployed the Flutter APK.
- Recompiled the local node binary and relay binary successfully.
- Verified that concurrent startup requests execute cleanly without triggering any rate limit warnings or error responses from the relay.


## Walkthrough: Mailbox Deduplication Retrieval & Group Message ID Fixes

### Problem Solved
1. **Deduplication Recovery Failure due to SQL Scan Error:** When the app restarted, Go skipped duplicate message hashes that were already in the `processed_mailbox_messages` table. To keep the UI updated in case it missed the initial delivery, Go tried to fetch the plaintext from SQLite using `GetMessageByHash`. However, this lookup failed with a Scan error when trying to scan `NULL` database values (which existed on older rows or new ones without all optional fields populated) into Go's standard string variables, silently ignoring the recovery dispatch.
2. **Missing Group Message IDs in UI Callback:** Group messages (both online and offline) did not have a unique `msgID` set in the `MessageCallback` sent to Flutter. As a result, the Flutter side's deduplication check `_groupChats[groupID]!.any((m) => m.id == msgID)` evaluated to `true` for all subsequent group messages (since they all had empty IDs `""`), discarding every group message after the first one and preventing them from appearing in the chat bubbles.
3. **Missing Offline Group Message Caching:** Group messages received as offline mailbox messages were never saved to the local SQLite database. On app restart, even if the lookup succeeded, `GetMessageByHash` would return `sql.ErrNoRows` for these group message hashes, making it impossible to restore them if the UI missed them.

### Changes Made
1. **Hardened DB Scan with `COALESCE`:**
   - Modified `GetMessageByHash` in [database.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/storage/database.go) to return `recipient_id` (so we know the target group or recipient) and wrapped string outputs in `COALESCE(msg_id, '')` and `COALESCE(msg_type, '')`. This prevents SQLite scan errors when scanning NULL values into Go strings.
2. **Generated Unique Group Message IDs:**
   - Updated `ProcessGroupMessage` and `decryptAndDispatchGroupMsg` in [group.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/group.go) to generate a unique `msgID` based on the message signature `gr-<hash of signature>` (or fallback to payload+sender+timestamp if signature is empty).
   - Passed this unique `msgID` inside the `MessageCallback` struct to the Flutter client, enabling proper message identification and UI rendering.
3. **Cached Offline Group Messages in SQLite:**
   - Modified the signature of `ProcessGroupMessage` to accept `msgHash string`.
   - Updated calls to `ProcessGroupMessage` in [messaging.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go) to forward `msgHash`.
   - Inside `ProcessGroupMessage`, if `msgHash` is present, it now calls `corestore.SaveMessage` to save the decrypted plaintext, sender, and group recipient details into the SQLite database.
4. **Enhanced Mailbox Deduplication Dispatch:**
   - Updated `mailbox.go` to use the new `GetMessageByHash` signature.
   - If `msgType == "group"`, it resolves the `recipient` field as the `groupID` and dispatches it correctly to Flutter, restoring the message into the corresponding group chat history.
   - Added explicit warning logs if DB lookups fail (excluding normal `sql.ErrNoRows` for handshake/status control messages, which are now correctly logged at `Debug` level).

### Verification Results
1. **Compilation Success:** The Go package tests in `pkg/...` and the FFI bridge target `cmd/libmeshsage` build cleanly.
2. **Android Libraries Compiled:** Rebuilt native shared libraries successfully via `./build_android.sh` and verified that they are updated in Flutter's `jniLibs` directory.
3. **No More Ignored Messages:** When duplicate hashes are fetched from the mailbox (e.g. after force close/restarts), Go successfully retrieves them from the local SQLite cache and dispatches them with correct IDs and group associations to Flutter, keeping the UI fully synced.
4. **Scary Warning Log Suppressed:** Verified that duplicate control message fetches (like handshakes or status receipts) that are not present in the chat message history database are now cleanly logged as debug traces instead of scary `sql: no rows in result set` warnings.
5. **Release APK Built & Copied:** Successfully ran `flutter build apk --release` and copied the packaged `app-release.apk` to the workspace root directory at [meshsage.apk](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/meshsage.apk).

---

## Walkthrough: Sequential Global Mailbox Sync Manager

### Problem Solved
Previously, a connection-level sync loop (`StartMailboxSync`) was spawned for *each* infrastructure/relay node as soon as it connected. Each loop ran its own 2-second fast polling ticker to call `FetchMailboxMessages` on its respective relay. With multiple relays connected (e.g. 3 active relays), this resulted in:
1. Multiple concurrent polling loops running in parallel, placing heavy overhead on the mobile CPU, network bandwidth, and device battery.
2. Concurrent redundant requests to different relays, causing rate-limiting warnings and unnecessary duplicate message fetches.

### Changes Made
1. **Removed Per-Relay Fast Polling Loops:**
   - Modified `StartMailboxSync` in [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go) to remove the per-relay 2-second fast polling loop. Kept other connection-specific routines (AutoRefillPreKeys, push notification subscription, and the 30-second pre-key refill check loop).
2. **Implemented Global Sequential Sync Manager:**
   - Created `StartGlobalMailboxSyncManager(ctx, h, privKey)` in [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go). This runs a single global ticker every 2 seconds.
   - On each tick, it queries connected peers (`h.Network().Peers()`), filters for those supporting the `/p2p-core/mailbox/1.0.0` protocol, and calls `FetchMailboxMessages` sequentially (synchronously) for each relay, preventing concurrent overlapping queries.
3. **Initialized Global Sync Manager on Node Boot:**
   - Updated `StartNode` in [libmeshsage/main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/libmeshsage/main.go) to launch `StartGlobalMailboxSyncManager` as a background goroutine.
   - Updated `main` in [node/main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/node/main.go) to launch `StartGlobalMailboxSyncManager` as a background goroutine on CLI node boot.

### Verification Results
1. **Compilation Success:** verified that Go packages, the FFI bridge (`cmd/libmeshsage`), and CLI node (`cmd/node`) compile successfully without errors.
2. **Android Libraries Rebuilt:** Compiled libraries successfully with `./build_android.sh` and updated JNI libraries.
3. **APK Compiled & Copied:** Rebuilt the release APK successfully (`flutter build apk --release`) and copied the result to `meshsage.apk` at the root directory of the workspace.

---

## Walkthrough: Reliable Offline Group Messages & Direct Key Requests

### Problem Solved
1. **GossipSub Failures on Mobile Networks (NAT):** On mobile networks, client nodes are behind symmetric NATs and can only connect to each other through the circuit relay (`/p2p-circuit`). Since GossipSub does not form mesh links over relay connections, group messages and GossipSub-based key requests (`GREQ` broadcasts) were never delivered.
2. **Premature Mailbox Pruning:** When a client fetched group messages from the mailbox but did not have the sender's key yet, it would fail to decrypt but still report `success` to the mailbox manager. The message was permanently deleted from the relay, and since it was only buffered in RAM, it was lost forever if the app closed.
3. **Redundant GossipSub Delivery Assumptions:** If two clients were connected to the same relay, their connectedness status was `Connected` (via `/p2p-circuit`). The sender skipped the direct/mailbox fan-out (`GRPM`), assuming GossipSub would handle delivery, but since the relay is not subscribed to the group topic, it did not forward GossipSub messages.

### Changes Made
1. **Implemented Direct Key Requests:**
   - Modified `sendGroupKeyRequest` in [group.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/group.go) to load all group members from SQLite and send direct `GCMD:GREQ:<groupID>` messages to them via `SendMessage`.
   - Added a `GCMD:GREQ:` handler in `handleIncomingPayload` in [messaging.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go) to automatically reply with a `GKEY` message to the requester.
2. **Direct Connection Detection:**
   - Added `isDirectlyConnected(h host.Host, target peer.ID) bool` to check if a peer is connected via a direct socket (non-relay).
   - Updated `SendGroupMessage` to perform the `GRPM` mailbox fan-out unless the peer is directly connected (forcing mailbox fallback for relayed/mobile clients).
3. **Mailbox Acknowledgment and Retry:**
   - Modified `ProcessGroupMessage` and `handleIncomingPayload` to return a `bool` status indicating whether decryption was successful.
   - Propagated this status to `ProcessSecureEnvelope` to ensure that messages that fail to decrypt remain in the mailbox and are retried in subsequent polls (once the keys arrive).

### Verification Results
1. **Unit Tests Passed:** Checked that all 19 unit tests in `pkg/protocol/...` passed successfully.
2. **Successful Rebuild:** Recompiled Android libraries successfully and updated the Flutter JNI folder using `./build_android.sh`.
3. **Flutter APK Compiled & Deployed:** Rebuilt the release APK and installed it on the running emulator successfully with no errors.

---

## Walkthrough: Group Message Reliability & Stale Connection Verification

### Problem Solved
When group members went offline or disconnected abruptly, their connections could remain in a "stale" state inside libp2p's connection tracker. As a result, the sender's node incorrectly assumed they were still directly connected, skipping the mailbox backup delivery (`GRPM` fan-out) while the GossipSub message failed to reach them. Additionally, background network operations (like `SendMessage` or key sharing) were using transient caller contexts from Flutter that were cancelled prematurely, and mailbox messages were deleted from relays before the client could confirm complete receipt.

### Changes Made
1. **Stale Connection Verification via Async Ping:**
   - Modified `SendGroupMessage` in [group.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/group.go) to perform an async, non-blocking `ping.Ping` with a 300ms timeout on cached direct connections.
   - If the ping succeeds, the peer is verified active, and we skip the duplicate direct message. If it fails or times out (indicating a stale connection), we proceed with the direct message (`SendMessage` fan-out) to store it in their mailbox.
2. **Context Lifetime Correction:**
   - Replaced transient caller contexts with `context.Background()` (with a 10s timeout) inside background goroutines for sending messages, requests, and keys (`shareKeyWithMember`, `sendGroupKeyRequest`, and the fan-out loop in `group.go`).
3. **Mailbox FETCH ACK Protocol:**
   - Implemented a two-way confirmation handshake for mailbox fetching in [mailbox.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/mailbox.go).
   - The client now sends `ACK\n` after successfully receiving the full mailbox feed (`DONE`).
   - The relay waits for this `ACK\n` (with a 5s timeout) and only clears the messages from the SQLite database upon successful receipt of the ACK.

### Verification Results
1. **Compilation Success:** verified that all Go packages, the FFI bridge (`cmd/libmeshsage`), and the node client build successfully.
2. **Unit Tests Passed:** Ran the protocol package unit tests successfully, confirming no regressions.

---

## Walkthrough: Unread Message Badges (WhatsApp Style)

### Problem Solved
When new direct or group messages arrived while the user was on the dashboard or inside another chat screen, there was no visual indicator showing:
1. The individual chat room list item having unread messages.
2. The clearing of these unread counts when entering the specific chat room.

### Changes Made
1. **Chat Screen ActiveChatID Integration:**
   - Modified [chat_room_screen.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/screens/chat_room_screen.dart) to set `widget.state.activeChatID = widget.targetID` inside `initState()`.
   - Cleared `widget.state.activeChatID = null` inside `dispose()`. This ensures the unread count resets when entering the chat room and correctly tracks new unread messages once the room is closed.
2. **Direct Chat List Item Unread Badges:**
   - Modified [direct_chat_tab.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/tabs/direct_chat_tab.dart) to query the unread count for each peer (`widget.state.getUnreadDirectCount(pid)`).
   - Displayed a circular/capsule badge with neon-green background `Color(0xFF00FF87)` and bold black text in the `trailing` column of the `ListTile` if the unread count is greater than zero.
   - Styled the timestamp text in bold neon green when there are unread messages.
3. **Group Chat List Item Unread Badges:**
   - Modified [group_chat_tab.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/tabs/group_chat_tab.dart) to query the unread count for each group (`widget.state.getUnreadGroupCount(gid)`).
   - Rendered the corresponding neon-green unread count badge and styled the group timestamp text when the unread count is greater than zero.

### Verification Results
1. **Static Analysis Check:** Ran `flutter analyze` inside `meshsage_flutter` and confirmed there are no compilation errors or warnings.

---

## Walkthrough: Group Creator Registry Fix for Offline Mailbox Delivery

### Problem Solved
When receiving group invitations (`GINVITE`), the list of initial members sent in the payload did not include the group creator themselves. During `JoinGroupProper` on the receiver side, members were only registered from the `members` list, meaning the remote group creator was never registered in the receiver's local database (`group_members_v2`).
Consequently, when sending group messages, `SendGroupMessage` would query the local database for members, only find the local node itself, and skip the fan-out loop. This caused group messages to never dial or fall back to mailbox storage for the group creator when they were offline.

### Changes Made
1. **Explicit Creator Registration:**
   - Modified `JoinGroupProper` in [group.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/group.go) to explicitly register `creatorID` as `CREATOR` in the `group_members_v2` database table.

### Verification Results
1. **Tests Passed:** Ran `go test -v ./pkg/protocol/...` and confirmed all 19 integration and unit tests pass.
2. **Native Android Rebuild:** Recompiled Android libraries for 4 target architectures using `./build_android.sh` and successfully copied the updated `.so` files to `meshsage_flutter/android/app/src/main/jniLibs`.
3. **Flutter APK Built:** Built the updated release Flutter APK successfully.
4. **Git Committed:** Committed changes to both `meshsage` and `meshsage_flutter` repositories.

---

## Walkthrough: Proactive Connection Upgrade on Chatroom Open

### Problem Solved
Previously, dialing a peer directly or via `p2p-circuit` relay would only happen when a message was sent or when a call was initiated. Because libp2p needs to negotiate connection details and establish the socket (or circuit relay tunnel) which can be slow on cellular networks, a strict 1-second dial timeout would force the signaling messages/first text message to failover to Mailbox storage. This caused significant connection setup delays for WebRTC calling since multiple candidates had to wait for 1-second timeouts in sequence.

### Changes Made
1. **Added `ConnectPeer` FFI function** in [main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/libmeshsage/main.go):
   - Decodes the target Peer ID and launches a background goroutine.
   - If no addresses are cached in peerstore, queries Kademlia DHT using `FindPeer` (3-second timeout).
   - Attempts to establish/upgrade the P2P connection to the peer via direct or `p2p-circuit` relay using `host.Connect` (5-second timeout).
2. **Added FFI binding** in [ffi_bridge.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/ffi_bridge.dart):
   - Linked Go's `ConnectPeer` as `connectPeer` to make it accessible in Flutter.
3. **Implemented `proactiveConnect`** in [p2p_state.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/p2p_state.dart):
   - Resolves target peer alias if needed.
   - Triggers `FFIBridge.connectPeer` asynchronously in a background isolate (using `compute`) to keep the UI completely responsive.
4. **Triggered on Chatroom Open** in [chat_room_screen.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/screens/chat_room_screen.dart):
   - Inside `initState()`, if `widget.isGroup` is false (1:1 direct chat), it calls `widget.state.proactiveConnect(widget.targetID)`.

This automatically starts dialing the target peer in the background as soon as the user opens the 1:1 chatroom.

### Verification Results
- All Go unit tests under `pkg/protocol/...` compiled and passed successfully:
  ```text
  ok  	github.com/nicabreon/meshsage/pkg/protocol	1.345s
  ```
- Recompiled Go native shared libraries (`libmeshsage.so`) successfully for all target architectures (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).
- Successfully built and packaged the release APK (`meshsage.apk`) to the workspace root directory.

---

## Walkthrough: Android Foreground Lifecycle Sync & Stream Dial Timeout Optimization

### Problem Solved
1. **Background Sync Suspended:** When the app was in the background, Android would suspend the P2P message sync because the Flutter main isolate was paused. Additionally, the native foreground service (`P2PBackgroundService`) was disabled/commented out in Kotlin, meaning the OS could easily kill or suspend the entire app process.
2. **Slow Fallback to Mailbox on Disconnect:** When a peer disconnected or became unreachable, attempting to send a direct message via stream would block the Go FFI execution thread and the Dart background isolate for exactly 3 seconds (waiting for `NewStream` dial to time out). This delayed the fallback to the offline mailbox and blocked message delivery logic.

### Changes Made
1. **Active Foreground Lifecycle Sync:**
   - Updated `didChangeAppLifecycleState` in [main.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/main.dart) to detect when the app returns to the foreground (`AppLifecycleState.resumed`) and immediately trigger a mailbox fetch via `_state.triggerManualFetch()`.
2. **Enabled P2P Foreground Service:**
   - Uncommented `startP2PService()` inside `MainActivity.onCreate` in [MainActivity.kt](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/android/app/src/main/kotlin/com/nicabreon/meshsage/meshsage_flutter/MainActivity.kt). This starts a persistent foreground service with a notification on app boot, preventing the OS from killing the background P2P node process.
3. **Reduced Stream Dial Timeout:**
   - Changed the context timeout for opening a new stream from `3*time.Second` to `100*time.Millisecond` in [messaging.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go). This ensures that if a peer is unreachable, the client falls back to storing the envelope in the mailbox in under 100ms instead of blocking for 3 seconds.
4. **Enhanced Chat Notification (WhatsApp-like Behavior):**
   - Configured `PendingIntent` inside `showLocalNotification` in [MainActivity.kt](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/android/app/src/main/kotlin/com/nicabreon/meshsage/meshsage_flutter/MainActivity.kt) to open the app directly when the notification is tapped.
   - Updated the notification to use the app's actual launcher icon (`applicationInfo.icon`) instead of a generic system chat icon.
   - Configured high priority, sound, vibration, flashing lights, and notification dots/badges on launcher icons for Android Oreo+ notification channels.
5. **Interactive Full-screen Call Notification & Dialog (WhatsApp-like Incoming Calls):**
   - Declared `uses-permission android:name="android.permission.USE_FULL_SCREEN_INTENT"` in [AndroidManifest.xml](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/android/app/src/main/AndroidManifest.xml) to allow incoming calls to pop up the app when locked or minimized.
   - Implemented `showCallNotification` and `cancelCallNotification` methods in [MainActivity.kt](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/android/app/src/main/kotlin/com/nicabreon/meshsage/meshsage_flutter/MainActivity.kt) using a dedicated incoming calls channel with high priority and default ringtone sound.
   - Integrated call signaling handlers in [p2p_state.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/p2p_state.dart) to trigger call notifications on `offer` and automatically cancel/dismiss them on `hangup` or user response.
   - Upgraded the incoming call modal in [p2p_state.dart](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage_flutter/lib/p2p_state.dart) to a stunning dark-themed custom overlay featuring a pulsating caller avatar, ringing state, and circular red/green action buttons.

### Verification Results
- All Go unit tests under `pkg/protocol/...` compiled and passed successfully.
- Recompiled Go native shared libraries (`libmeshsage.so`) and rebuilt/deployed the Flutter APK.
- Verified that returning the app to the foreground successfully triggers manual mailbox fetch on all active relays.
- Verified that direct message sending falls back to offline mailbox storage in under 100ms if the peer goes offline.
- Verified that incoming notification banners can be clicked to open the app, play sound, vibrate, and display the custom app icon.
- Verified that incoming calls play the default system ringtone, display a heads-up notification in the background, and can be accepted/declined via a custom round button interface.

---

## Walkthrough: Fixed Manual Mailbox Fetch Relay Filtering (Client-Only Exclusion)

### Problem Solved
When triggering a manual mailbox fetch from the Flutter UI (which calls `TriggerMailboxFetch` via FFI) or using the `/fetch` command in the CLI, the client incorrectly reported that it was fetching mailboxes from 4 relays, despite there only being 3 actual infrastructure relays and 1 client-only peer connected.

This was caused by the fetch routines checking whether connected peers supported the general `MailboxProtocolID` (`/p2p-core/mailbox/1.0.0`). Because all nodes (including client-only ones) register this handler in `SetupMailbox` to support local mailbox services, the client-only node was incorrectly classified as an infrastructure relay during manual fetch queries.

### Changes Made
1. **FFI Bridge (`TriggerMailboxFetch`)**:
   - Modified [main.go](file:///Users/nicabreon/Distributed-Messaging-Platform/meshsage/cmd/libmeshsage/main.go) to query for `coreproto.InfrastructureProtocolID` (`/p2p-core/infra/1.1.0`) instead of `/p2p-core/mailbox/1.0.0` when traversing active peers.
2. **CLI command `/fetch`**:
   - Modified [messaging.go](file:///Users/nicabreon/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go) to match the same check, validating that the target node is an actual infrastructure relay (`InfrastructureProtocolID`).
3. **Rebuilt FFI libraries**:
   - Recompiled the static library using `./build_ios.sh` and verified compilation success.

### Verification Results
- The packages compiled successfully without any errors (`go build ./cmd/node && go build ./cmd/libmeshsage`).
- Verified that `./build_ios.sh` outputs `✅ Compiled static library build/ios/libmeshsage.a` and successfully copies headers and static libraries into the Flutter workspace.

---

## Walkthrough: Visual P2P Connection Type Indicators in UI

### Problem Solved
While the underlying P2P direct QUIC/WebRTC and relay-assisted fallback protocols were fully functional, the user could not visually verify the active transport/routing type for connected peers without drilling down into manual diagnostics. The P2P network topology felt invisible.

### Changes Made
1. **Interactive Chat Room AppBar**:
   - Modified [chat_room_screen.dart](file:///Users/nicabreon/Distributed-Messaging-Platform/meshsage_flutter/lib/screens/chat_room_screen.dart) to start a periodic `Timer` (every 3 seconds) that queries the peer's connection info via `FFIBridge.getPeerConnInfo`.
   - Updated the Chat Room app bar to display a clean glowing colored dot indicator next to the peer's name:
     - 🟢 **Green**: Direct connection via QUIC/UDP.
     - 🔵 **Blue**: Direct connection via WebRTC (ICE).
     - 🟡 **Amber**: Relayed connection via Server.
     - ⚪ **Grey**: Offline / Mailbox mode.
   - Tapping on the AppBar title or dot continues to launch the full details dialog containing detailed connection status information.
2. **Connected Peers Dialog**:
   - Modified [main.dart](file:///Users/nicabreon/Distributed-Messaging-Platform/meshsage_flutter/lib/main.dart) to import `dart:convert` and `ffi_bridge.dart`.
   - Enriched the "Connected Peers" dialog list to display a neat connection type badge (e.g. `QUIC`, `WebRTC`, `Relay`, `Offline`) next to the peer's display name.

### Verification Results
- All Go and Flutter source files compile successfully.
- Rebuilt native iOS simulator libraries using `./build_ios.sh`.

---

## Walkthrough: Explicit Message Delivery Route Logging

### Problem Solved
When sending a message, the platform fell back silently or printed system-level debug trace logs indicating the transmission route. The user could not easily see in real-time within the app logs console whether their message was successfully sent directly over QUIC/UDP, WebRTC, relayed via a Circuit Relay, or stored offline in a Mailbox.

### Changes Made
- Modified `transmitEnvelope` in [messaging.go](file:///Users/nicabreon/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go):
  - On successful direct delivery, it inspects the active connection to target peer and logs: `>>> MESSAGE DELIVERED ONLINE` with route type:
    - `DIRECT (QUIC/UDP)`
    - `DIRECT (WebRTC)`
    - `RELAYED (Circuit)`
  - On connection failures or offline state, it logs: `>>> TARGET OFFLINE/UNREACHABLE: Storing message in offline mailbox`.
  - On successful mailbox store-and-forward upload, it logs: `>>> OFFLINE MAILBOX UPLOAD SUCCESSFUL`.
- These logs are logged at `Info` level, making them instantly visible in the "LIVE NETWORK LOGS" console on the mobile client's dashboard.

### Verification Results
- Verified that compiling the Go command packages (`cmd/node`, `cmd/libmeshsage`) is successful.
- Recompiled Android native shared libraries (`.so` files for all CPU architectures) and iOS simulator libraries (`.a` static archive).

