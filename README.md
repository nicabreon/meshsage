# **Meshsage: Distributed P2P Messaging Platform**

**Meshsage** is a peer-to-peer (P2P) communication platform focused on privacy, security, and network resilience. Built on top of the **libp2p** protocol, Meshsage enables secure messaging without relying on any central server, featuring industry-standard encryption and a robust offline delivery system.

---

## **🚀 Key Features**

*   **🛡️ True End-to-End Encryption (E2EE)**: 
    *   **X3DH (Extended Triple Diffie-Hellman)** for secure initial key exchange.
    *   **Double Ratchet Algorithm** (similar to the Signal Protocol) for per-message encryption with rotating keys (*Forward Secrecy*).
    *   **Skipped Keys Handling**: Ensures message decryption even if packets arrive out-of-order due to P2P network latency.

*   **📫 Offline Mailbox (Store-and-Forward)**:
    *   Messages are automatically stored on **Relay Nodes** if the recipient is offline.
    *   Automatic synchronization when a node comes back online using coordinate-based hashing.

*   **👥 Secure Group Messaging**:
    *   Encrypted group communications using the *Sender Key* mechanism.
    *   HMAC-based automatic key rotation to maintain group forward secrecy.

*   **🌐 Decentralized Infrastructure**:
    *   No central authority or single point of failure.
    *   Adaptive Node Roles: Automatically transitions between **Relay** and **Client-Only** modes based on available resources.

---

## **🛠️ Prerequisites**

Ensure you have the following installed:
*   [Go](https://golang.org/doc/install) (version 1.21 or newer)
*   [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)

---

## **🏃 Getting Started**

### **1. Using Docker (Recommended for Testing)**
Launch a simulated cluster (Alice, Bob, Charlie, and a Relay) with a single command:
```bash
docker-compose up -d --build
```

### **2. Running Locally**
Build the application:
```bash
go build -o meshsage ./cmd/node
```
Start a node:
```bash
./meshsage -port 4001 -db messages.db
```

### **3. Automated E2E Testing**
We have an automated End-to-End test script that validates the Double Ratchet implementation, Offline Mailbox, and Group Messaging in various scenarios:
```bash
bash e2e_test_scenarios.sh
```
Check out the [Test Walkthrough](test_walkthrough.md) for detailed results and cryptographic verification logs.

---

## **💬 CLI Command Guide**

Once the node is running, you can interact with it using the following commands:

| Command | Description |
| :--- | :--- |
| `/msg <PeerID> <message>` | Send a private message to a specific Peer ID. |
| `/join <RoomName> <Members>` | Join a group (comma-separated list of Peer IDs). |
| `/group <RoomName> <message>` | Send an encrypted message to all group members. |
| `/fetch` | Manually trigger a mailbox fetch for offline messages. |
| `/register @alias` | Register an alias for your Peer ID. |

---

## **🏗️ System Architecture**

For a detailed look at the subsystems, sequence flows, and network topology, see the [System Architecture & Subsystem Diagrams](architecture_diagrams.md).

*   **Networking**: libp2p (Kademlia DHT, GossipSub, mDNS).
*   **Cryptography**: X25519 (Diffie-Hellman), AES-GCM (Encryption), HMAC-SHA256 (Ratchet).
*   **Storage**: SQLite (with WAL mode for high concurrency).

---

## **📜 License**
This project is licensed under the MIT License.
