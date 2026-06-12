# Meshsage Core Protocol Specification

This document details the wire format, encryption layers, and state machines of the Meshsage distributed messaging protocol.

---

## 1. Cryptographic Handshake (X3DH)

Meshsage uses an adaptation of the Extended Triple Diffie-Hellman (X3DH) protocol to establish a shared secret key between two nodes asynchronously, even when one node is offline.

### 1.1 Pre-key Registration & Upload
Nodes register pre-keys on a cluster relay. A pre-key bundle upload is encoded as a JSON payload:

```json
{
  "owner_id": "<peer_id_string>",
  "signature": "<signature_b64>",
  "keys": [
    {
      "key_id": "<key_id_string>",
      "public_key": "<public_key_b64>",
      "signature": "<signature_b64>"
    }
  ]
}
```

- **Keys**: 10 ephemeral public keys.
- **Signature**: Digital signature of the owner's identity private key over the concatenated key IDs and public keys, proving ownership.

### 1.2 Handshake Message Envelope
When Alice initiates a session with Bob, she fetches one of Bob's pre-keys from a relay. She derives the initial shared secret using X25519 DH. The handshake payload is sent to Bob's mailbox or directly as:

`X3DH:<prekey_id>:<alice_ephemeral_pub_b64>:<alice_ratchet_pub_b64>:<encrypted_payload_b64>`

- **Format**: Plaintext parts separated by colons (`:`).
- **Encrypted Payload**: Contains the message details (usually standard JSON `MessageEnvelope` representing the initial message or handshake ACK) encrypted via AES-GCM using the initial X3DH shared key.

---

## 2. Double Ratchet (Per-Message Encryption)

Once the X3DH handshake succeeds, both nodes transition to standard Double Ratchet mode. Every message is encrypted with a unique, one-time symmetric key.

### 2.1 Wire Format
A Double Ratchet envelope is serialized as:

`DR:<header_and_ciphertext_b64>`

The base64 encoded payload has the internal format:
`<sender_ratchet_pub_b64>|<previous_chain_length>|<message_number>|<ciphertext>`

- **Fields** separated by vertical pipes (`|`).
- **Sender Ratchet Public Key**: Used by the receiver to step their DH ratchet forward if changed.
- **PN (Previous Chain Length)**: The number of messages sent in the previous chain.
- **N (Message Number)**: Index of the current message in the current sending chain.
- **Ciphertext**: AES-GCM encrypted payload, containing the `MessageEnvelope`.

### 2.2 Out-of-Order Message Handling (Skipped Keys)
If a message is lost or received out of order, the receiver advances their ratchet and stores the skipped message keys in the local database (`skipped_keys` table) indexed by peer ID and message counter, allowing later decryption.

---

## 3. Mailbox Protocol (Offline Storage)

Relay nodes act as Mailbox storage for offline nodes.

### 3.1 Store Message Command (Client to Relay)
A client stores a message in another client's mailbox by sending a `STORE` line followed by the payload length prefix:

```
STORE <recipient_peer_id> <sender_pubkey_b64> <envelope_b64>
```

- **Sender Public Key**: Used by the relay to perform anti-spam checks (ensuring the sender has registered pre-keys).
- **Envelope B64**: The X3DH or DR envelope wrapped inside a `SignedMailboxEnvelope`:

```json
{
  "payload": "<ciphertext_envelope>",
  "signature": "<signature_b64>",
  "sender": "<sender_peer_id>"
}
```

### 3.2 Fetch Messages Command (Client to Relay)
A client fetches their mailbox using a standard fetch query, and deletes processed messages after successful decryption to keep the relay storage clean.

---

## 4. Group Chat Protocol

Group Chats are established using a peer-to-peer tree distribution with local group keys.

### 4.1 Group Metadata Setup
A group is uniquely identified by a group ID (`grp-<hash>`). The group creator publishes the metadata containing members list, roles, and signature.

### 4.2 Group Key Distribution
Each member generates a local Ephemeral DH key pair and signs it. Members share group key history updates through direct E2EE sessions to establish cryptographic group consensus.
