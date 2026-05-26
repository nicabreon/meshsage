# **Meshsage: System Architecture & Subsystem Diagrams**

This document provides a detailed breakdown of the system architecture of **Meshsage**, a distributed, peer-to-peer (P2P) messaging platform. It includes high-level architectural block diagrams and detailed sequence and flow diagrams for key subsystems: the **Offline Mailbox (Store-and-Forward)**, **End-to-End Encryption (X3DH & Double Ratchet)**, and **Group Messaging (Sender Key & Fan-out)**.

---

## **1. Overall System Architecture**

Meshsage is a completely decentralized system built on the **libp2p** networking library. Every node runs a local host, handles its own state storage via SQLite, and coordinates with other nodes for routing, messaging, replication, and discovery.

```mermaid
graph TD
    %% Styling
    classDef component fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef network fill:#efebe9,stroke:#4e342e,stroke-width:2px;
    classDef storage fill:#efe8ff,stroke:#512da8,stroke-width:2px;
    classDef protocol fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px;

    %% Client App
    subgraph "Application Layer"
        CLI["CLI / User Interface"]
    end

    %% Node Internals
    subgraph "Meshsage P2P Node"
        direction TB
        
        subgraph "Protocol Handlers"
            direction LR
            MsgProto["Messaging Protocol<br/>/p2p-core/msg/1.0.0"]:::protocol
            MailboxProto["Mailbox Protocol<br/>/p2p-core/mailbox/1.0.0"]:::protocol
            NotifyProto["Notification Protocol<br/>/p2p-core/notify/1.0.0"]:::protocol
            ReplProto["Replication Protocol<br/>/chirp/replicate/1.0.0"]:::protocol
        end

        subgraph "Cryptographic Engine"
            X3DH["X3DH Handshake Engine"]:::component
            DR["Double Ratchet State Machine"]:::component
            SignEngine["Ed25519 Sign / Verify"]:::component
        end

        subgraph "Local Storage"
            SQLite[("SQLite DB (WAL Mode)")]:::storage
            SessionTable["Session Cache"]:::storage
            MsgTable["Persisted Messages"]:::storage
            KeysTable["Pre-Keys & Skipped Keys"]:::storage
            SQLite --- SessionTable
            SQLite --- MsgTable
            SQLite --- KeysTable
        end
    end

    %% Network Layers
    subgraph "libp2p Stack"
        Host["libp2p Host Node"]:::network
        DHT["Kademlia DHT<br/>(Peer & Content Routing)"]:::network
        GossipSub["GossipSub PubSub<br/>(Group Chats & Cluster Sync)"]:::network
        Bitswap["Bitswap & BlockService<br/>(Chunk Transfer / Replication)"]:::network
    end

    %% External Connections
    CLI <--> MsgProto
    CLI <--> MailboxProto
    
    %% Connections within node
    MsgProto <--> X3DH
    MsgProto <--> DR
    MsgProto <--> SignEngine
    MailboxProto <--> DR
    X3DH <--> SQLite
    DR <--> SQLite
    SignEngine <--> SQLite
    
    %% Protocol to Networking
    MsgProto --> Host
    MailboxProto --> Host
    ReplProto --> Bitswap
    
    %% libp2p internal associations
    Host <--> DHT
    Host <--> GossipSub
    Host <--> Bitswap
    
    class CLI,X3DH,DR,SignEngine component;
    class Host,DHT,GossipSub,Bitswap network;
    class SQLite,SessionTable,MsgTable,KeysTable storage;
```

### **Architectural Layers & Modules**
1. **Application Layer (CLI)**: Processes user input commands (`/msg`, `/group`, `/join`, `/fetch`, `/register`, `/latency`) and prints incoming messages, file transfer links, and status reports.
2. **Protocol Handlers**: Defined over libp2p streams. They read incoming byte streams, unpack headers, check rate limits, and dispatch payloads to the cryptographic engine or database.
3. **Cryptographic Engine**: Implements end-to-end security parameters:
   - **X3DH** for ephemeral Diffie-Hellman key exchange.
   - **Double Ratchet** to rotate message keys on every sent and received envelope.
   - **Ed25519 Signatures** for payload authenticity and non-repudiation.
4. **Local Storage (SQLite)**: Persists session states, messages, skipped keys, pre-keys, alias mappings, and group configurations. Runs in WAL (Write-Ahead Logging) mode to support safe concurrent reads/writes from background threads.
5. **libp2p Stack**: Handles multiplexing, encryption (TLS/Noise), NAT traversal, DHT routing (Kademlia), real-time broadcast pub/sub (GossipSub), and direct block transfers (Bitswap).

---

## **2. Relay Message / Mailbox Subsystem**

The Mailbox Subsystem stores messages when a peer is offline and delivers them when the peer comes online. It supports:
- **DHT Coordinate-Based Hashing**: Mailbox coordinate `coord = SHA256(PeerID + "mailbox")`.
- **Relay Redundancy**: Messages are distributed to up to 3 closest active relay/infrastructure nodes.
- **Push Notifications**: Live wake-up signals over a dedicated Notification stream.
- **Metadata Replication**: GossipSub synchronization across relay nodes for cluster state safety.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Alice (Sender)
    participant Relay as Relay Node(s)
    actor Bob as Bob (Receiver)

    Note over Alice, Bob: Bob goes offline.
    
    Note over Alice: Alice tries to send E2EE Message to Bob
    Alice->>Bob: Direct Dial (Messaging Protocol)
    Note over Alice: Connection timeout / fails.
    
    %% Storage Phase
    critical Fallback to Offline Mailbox Storage
        Alice->>Alice: Compute coordinate:<br/>coord = SHA256(Bob_PeerID + "mailbox")
        Alice->>Alice: Query DHT / Search infra list for up to 3 closest Relay Nodes
        Alice->>Relay: Connect via /p2p-core/mailbox/1.0.0
        Alice->>Relay: Send: STORE <msgHash> <coord> <Alice_Pubkey> <Encrypted_Payload>
        
        activate Relay
        Relay->>Relay: Save message to local SQLite mailbox table
        Relay-->>Alice: Respond with "OK" (ACK)
        deactivate Relay
        
        opt Cluster Replication
            Relay->>Relay: Broadcast cluster event "MAILBOX_ADD" via GossipSub
            Note over Relay: Other relays in cluster cache the message
        end
    end
    
    Note over Bob: Bob comes back online.
    
    %% Optional Notify Stream
    opt Active Notification Stream
        Bob->>Relay: Establish notify stream: /p2p-core/notify/1.0.0
        Relay->>Bob: Send push notification: "PING" (Wake up client)
    end

    %% Retrieval Phase
    critical Fetching Mailbox Messages
        Bob->>Bob: Compute coordinate:<br/>coord = SHA256(Bob_PeerID + "mailbox")
        Bob->>Relay: Connect via /p2p-core/mailbox/1.0.0
        Bob->>Relay: Send: FETCH <coord>
        
        activate Relay
        Relay->>Relay: Query SQLite for messages matching <coord>
        
        loop For each message found
            Relay->>Bob: Send: MSG <msgHash> <Alice_Pubkey> <Encrypted_Payload>
        end
        
        Relay->>Bob: Send: DONE
        
        Relay->>Relay: Delete fetched messages from local SQLite (Purge)
        deactivate Relay
        
        opt Sync Purge Across Cluster
            Relay->>Relay: Broadcast cluster event "MAILBOX_PURGE" via GossipSub
            Note over Relay: Other relays delete the purged message from their cache
        end
    end

    %% Decryption Phase
    Note over Bob: Bob processes incoming envelopes,<br/>ratchets sessions, and decrypts payloads.
```

---

## **3. Encryption / Decryption Subsystem (X3DH & Double Ratchet)**

Meshsage protects 1:1 messages using a hybrid protocol combining **X3DH** (Extended Triple Diffie-Hellman) for initial session establishment and the **Double Ratchet** for continuous forward secrecy and post-compromise security.

### **A. Session Initiation & X3DH Handshake**
If Alice does not have an active session with Bob, she must perform an X3DH handshake using Bob's pre-key registered on the network.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Alice (Sender)
    participant Relay as Relay / Pre-Key Store
    actor Bob as Bob (Receiver)

    %% Bob registers keys
    opt Bob Key Registration
        Bob->>Bob: Generate Identity Keypair (IK_B) & Signed Pre-Key (SPK_B)
        Bob->>Relay: Publish Pre-Key (KeyID, SPK_B, Sig_B)
    end

    Note over Alice: Alice wants to send a message to Bob.<br/>No active session found in SQLite.

    %% X3DH Fetch & Derivation
    Alice->>Relay: Fetch Bob's Pre-Key (FetchPreKey)
    Relay-->>Alice: Return (KeyID, SPK_B, Sig_B)
    
    Alice->>Alice: Generate Ephemeral Keypair (EK_A)
    Alice->>Alice: Compute Shared Secret = X25519(EK_A_Priv, SPK_B_Pub)
    Alice->>Alice: Generate Local Ratchet Keypair (RK_A)
    Alice->>Alice: Perform Initial DH Send Step:<br/>Derive Initial RootKey & SendChainKey
    Alice->>Alice: Save Session State (RootKey, SendChainKey, RK_A_Pub)
    
    %% Envelope Transmission
    Alice->>Bob: Send: X3DH:<keyID>:<EK_A_Pub>:<RK_A_Pub>:<EncryptedPayload>
    
    %% Bob Derivation
    activate Bob
    Bob->>Bob: Look up SPK_B_Priv from SQLite matching <keyID>
    Bob->>Bob: Compute Shared Secret = X25519(SPK_B_Priv, EK_A_Pub)
    Bob->>Bob: Perform Initial DH Recv Step using RK_A_Pub:<br/>Derive Initial RootKey & RecvChainKey
    Bob->>Bob: Generate Local Ratchet Keypair (RK_B)
    Bob->>Bob: Perform Initial DH Send Step:<br/>Derive SendChainKey
    Bob->>Bob: Save Session State (RootKey, SendChainKey, RecvChainKey, RK_B, RK_A_Pub)
    
    Bob->>Bob: Decrypt Payload using derived Shared Secret
    Bob-->>Alice: Response: ACK ("OK")
    deactivate Bob
    Note over Alice, Bob: Session established. Future communications use Double Ratchet.
```

---

### **B. Double Ratchet Message Exchange**
Once a session is established, every message is encrypted using a unique **Message Key** generated by advancing either the Symmetric Ratchet (per-message) or the DH Ratchet (when a new DH public key is received from the peer).

```mermaid
graph TD
    %% Styling
    classDef state fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    classDef process fill:#e0f2f1,stroke:#004d40,stroke-width:2px;
    classDef input fill:#fce4ec,stroke:#880e4f,stroke-width:2px;

    %% DH Ratchet
    subgraph "DH Ratchet (Diffie-Hellman Step)"
        NewPub["Receive New Remote Ratchet Pubkey"]:::input
        LocalPriv["Local Ratchet Private Key"]:::state
        DH_SS["Derive Shared Secret<br/>X25519(LocalPriv, RemotePub)"]:::process
        HKDF_DH["HKDF Expand<br/>(Extracts Root Key & Chain Key)"]:::process
        
        NewPub & LocalPriv --> DH_SS --> HKDF_DH
    end

    %% Symmetric Ratchet
    subgraph "Symmetric-Key Ratchet (Chain Key Step)"
        ChainKey[("Current Chain Key")]:::state
        HKDF_Sym["HKDF Expand<br/>(p2p-core-ratchet-v1)"]:::process
        MsgKey[("Message Key (32 bytes)")]:::state
        NextChain[("Next Chain Key")]:::state
        
        HKDF_DH -->|Update| ChainKey
        ChainKey --> HKDF_Sym
        HKDF_Sym -->|Top 32 bytes| MsgKey
        HKDF_Sym -->|Bottom 32 bytes| NextChain
        NextChain -->|Feeds next step| ChainKey
    end

    %% Encryption / Decryption
    subgraph "Message Payload Cryptography"
        Plaintext["Plaintext Message"]:::input
        GZIP["Gzip Compression"]:::process
        AES_GCM["AES-GCM Encryption"]:::process
        Ciphertext["Ciphertext + Auth Tag"]:::input

        MsgKey & GZIP & Plaintext --> AES_GCM --> Ciphertext
    end

    class ChainKey,MsgKey,NextChain,LocalPriv state;
    class DH_SS,HKDF_DH,HKDF_Sym,GZIP,AES_GCM process;
    class NewPub,Plaintext,Ciphertext input;
```

---

### **C. Skipped Keys Handling (Out-of-Order Delivery)**
Because P2P networks can deliver messages out of order, Meshsage keeps track of skipped chain key states. If message counter $N$ is greater than the expected counter $M$, intermediate keys are saved as **Skipped Keys** in SQLite and retrieved when the missed messages arrive.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Alice
    actor Bob as Bob
    
    Note over Alice, Bob: Active Session: Bob expects message with counter M = 0.
    Alice->>Alice: Encrypt message 1 (N = 0)
    Alice->>Alice: Encrypt message 2 (N = 1)
    Alice->>Alice: Encrypt message 3 (N = 2)
    
    Alice-)Bob: Send message 1 (N=0) -- DELAYED/LOST IN NETWORK
    Alice-)Bob: Send message 3 (N=2) -- ARRIVES FIRST
    
    activate Bob
    Note over Bob: Bob receives N = 2.<br/>Expects M = 0.<br/>Gap detected! (2 > 0)
    
    loop Skip step for N = 0 and N = 1
        Bob->>Bob: Advance Recv Chain Key using RatchetStep
        Bob->>Bob: Save Message Key for counter (M) in SQLite skipped_keys table
        Bob->>Bob: Increment expected counter M
    end
    
    Bob->>Bob: Derive Message Key for N = 2
    Bob->>Bob: Decrypt message 3 successfully
    Bob->>Bob: Increment expected counter M (M becomes 3)
    deactivate Bob
    
    Note over Bob: Sometime later...
    Alice-)Bob: Send message 1 (N=0) -- FINALLY ARRIVES
    
    activate Bob
    Note over Bob: Bob receives N = 0.<br/>N (0) < expected M (3).<br/>Check skipped_keys.
    Bob->>Bob: Query SQLite: Find skipped key for counter = 0
    Bob->>Bob: Retrieve Key from DB
    Bob->>Bob: Decrypt message 1 successfully
    Bob->>Bob: Delete skipped key for counter = 0 from DB
    deactivate Bob
```

---

## **4. Cryptographic Group Management Subsystem**

Meshsage group messaging utilizes a **Sender Key** mechanism combined with **Cryptographic Ownership Governance**. Every group is managed by a **Creator** who signs the group's metadata and controls membership (adding or removing members). 

Meshsage supports two group membership models:
1. **SECURE (Closed / Invite-Only Group)**:
   * Access is strictly creator-controlled.
   * Members are explicitly invited by the Creator via `/group-create` or `/group-add`.
   * Key distribution and membership command signatures are fully verified.
   * Forward secrecy key rotation occurs on exits (`/group-exit`) and removals (`/group-remove`).
2. **UNSECURE (Open / Public Group)**:
   * Anyone can dynamically request to join using `/group-join <alias>`.
   * The joining node resolves the group's metadata, validates the creator's metadata signature, joins the group's GossipSub topic, and broadcasts a signed `GCMD:JOIN` command.
   * All online group members receive the join request, record the new member locally, and securely share their local `GKEY`s with the new member via 1:1 secure channels.

Security guarantees:
*   **Decentralized Control**: No central server. Membership changes are validated using the Creator's digital signature.
*   **Forward Secrecy**: When a member is removed or exits, all remaining members rotate their local Group Keys (`GKEY`) and share them *only* with the remaining members, preventing the former member from decrypting future messages.
*   **Collision Isolation**: Naming collisions (groups with the same alias) are isolated cryptographically because nodes only accept and decrypt messages if they have shared keys with the sender.

### **A. Group Creation & Key Distribution**
When a group is created:
1. The Creator generates a unique `GroupID` and signs the **Group Metadata** (binding `GroupID`, `GroupAlias`, `CreatorID`, and creation timestamp).
2. The Creator registers the `GroupAlias` to the Kademlia DHT Alias Registry.
3. The Creator generates their local 32-byte group encryption key (`GKEY`) and shares the Metadata + `GKEY` with the initial member(s) over secure 1:1 channels (Double Ratchet).

```mermaid
sequenceDiagram
    autonumber
    actor Creator as Creator (Alice)
    actor Member as Member (Bob)
    participant DHT as DHT Registry
    
    Creator->>Creator: Generate Group ID & Sign Group Metadata
    Creator->>DHT: Register group alias (e.g., @kopi-senja) -> Group ID
    Creator->>Creator: Generate local Group Key (GKEY_Alice)
    Creator->>Member: Send Group Metadata + GKEY_Alice (Secure 1:1 Double Ratchet)
    Note over Member: Verify Creator Signature & Save Metadata to SQLite
    Creator->>Swarm: Subscribe GossipSub Topic (Group ID)
    Member->>Swarm: Subscribe GossipSub Topic (Group ID)
```

---

### **B. Member Management & Key Rotation**
Only the Creator is authorized to add or remove members by broadcasting signed command envelopes (`GCMD`).

#### **Add Member (Creator Only)**
1. The Creator sends the Group Metadata and their current `GKEY` to the new member via a 1:1 secure channel.
2. The Creator broadcasts `GCMD:ADD:<new_member>` signed by the Creator to the group.
3. All existing members verify the Creator's signature, save the new member to their SQLite database, and share their own local `GKEY`s with the new member via secure 1:1 channels.

```mermaid
sequenceDiagram
    autonumber
    actor Creator as Creator (Alice)
    actor Existing as Member (Bob)
    actor New as New Member (Charlie)
    participant Swarm as GossipSub Topic (Group ID)
    
    Creator->>New: Send Group Metadata + GKEY_Alice (Secure 1:1)
    Creator->>Swarm: Broadcast control message GCMD:ADD:Charlie (Signed by Alice)
    Swarm->>Existing: Deliver GCMD:ADD:Charlie
    Note over Existing: Verify Alice's Signature & Add Charlie to SQL
    Existing->>New: Send GKEY_Bob (Secure 1:1)
    Note over New: Charlie now has keys to decrypt group messages from Alice & Bob
```

#### **Remove Member & Key Rotation (Creator Only)**
1. The Creator broadcasts `GCMD:REMOVE:<target_member>` signed by the Creator to the group.
2. All remaining members verify the Creator's signature and delete the removed member from their SQLite database.
3. To enforce **Forward Secrecy**, the Creator and all remaining members **rotate their group encryption keys (generate new random `GKEY`s)** and share them *only* with the remaining members. The removed member is excluded, losing access to all subsequent group communication.

```mermaid
sequenceDiagram
    autonumber
    actor Creator as Creator (Alice)
    actor Remaining as Member (Bob)
    actor Kicked as Kicked Member (Charlie)
    participant Swarm as GossipSub Topic (Group ID)

    Creator->>Swarm: Broadcast control message GCMD:REMOVE:Charlie (Signed by Alice)
    Swarm->>Remaining: Deliver GCMD:REMOVE:Charlie
    Note over Remaining: Verify Alice's Signature & Delete Charlie from SQL
    
    Note over Creator, Remaining: Key Rotation Sequence (Forward Secrecy)
    Creator->>Creator: Generate new key GKEY_Alice_v2
    Remaining->>Remaining: Generate new key GKEY_Bob_v2
    
    Creator->>Remaining: Share GKEY_Alice_v2 (Secure 1:1)
    Remaining->>Creator: Share GKEY_Bob_v2 (Secure 1:1)
    Note over Kicked: Charlie is bypassed and cannot decrypt future messages
```

---

## **5. Alias Registration & Resolution Subsystem**

Meshsage implements a secure, decentralized identity registry mapping human-readable usernames (e.g., `@alice`) to cryptographic `PeerID`s. This subsystem protects against hijacking through digital signatures and optimizes lookup performance using on-demand caching.

### **A. Secure Alias Registration**
To prevent alias hijacking, registering an alias requires presenting a digital signature proving ownership of the corresponding public key.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Alice
    participant Swarm as DHT / Swarm Nodes
    participant SQLite as SQLite DB / Memory

    Alice->>Alice: Generate Signature over:<br/>data = "@alice" + Alice_PeerID + Alice_Pubkey_B64
    Alice->>Swarm: Connect via /p2p-core/alias/1.0.0
    Alice->>Swarm: Send: REGISTER @alice Alice_PeerID Alice_Pubkey_B64 Signature_B64

    activate Swarm
    Swarm->>Swarm: 1. Derive PeerID from Pubkey & verify it matches Alice_PeerID
    Swarm->>Swarm: 2. Verify signature using Alice_Pubkey
    Swarm->>Swarm: 3. Check if "@alice" is already registered to a different key
    alt Verification Fails (Hijack Attempt)
        Swarm-->>Alice: Respond: ERROR_ALREADY_OWNED / ERROR_INVALID_SIGNATURE
    else Verification Success
        Swarm->>SQLite: Save to alias_store database table
        Swarm->>Swarm: Update local memory maps (aliasStore & ownerStore)
        Swarm-->>Alice: Respond: OK
    end
    deactivate Swarm
```

### **B. On-Demand Resolution & Cache Propagation**
Resolving an alias employs a hybrid local-first resolution search with fallback lookup cache propagation.

```mermaid
sequenceDiagram
    autonumber
    actor Bob as Bob
    participant MemBob as Bob's Local Memory/DB
    actor Relay as Dedicated Relay Node
    participant MemRelay as Relay's Local Memory/DB
    actor Alice as Alice (@alice)

    Bob->>MemBob: 1. Call ResolveAlias("@alice") & check aliasStore
    alt Found in Local Cache (Fast Path)
        MemBob-->>Bob: Return Peer ID (Done)
    else Not Found in Local Cache
        Bob->>Relay: 2. Send stream RESOLVE @alice (Slow Path)
        
        activate Relay
        Relay->>MemRelay: 3. Check local memory ONLY (prevents infinite loop)
        
        alt Relay has cached @alice
            MemRelay-->>Bob: Return FOUND Alice_PeerID Alice_Pubkey_B64
        else Relay does not have cache
            Relay-->>Bob: Return NOT_FOUND
            Note over Bob: Bob performs DHT query to closest swarm / Alice directly
            Bob->>Alice: Send stream RESOLVE @alice
            Alice-->>Bob: Return FOUND Alice_PeerID Alice_Pubkey_B64
            
            critical 4. Public Key Validation & Local Caching
                Bob->>Bob: Derive PeerID from Alice_Pubkey & match with Alice_PeerID
                Bob->>MemBob: Save to SQLite & Memory (aliasStore & ownerStore)
            end
        end
        deactivate Relay
    end
```

