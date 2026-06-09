# Privacy Policy for Meshsage

**Last Updated: June 9, 2026**

Meshsage is a decentralized, open-source, peer-to-peer (P2P) messaging application. This Privacy Policy explains how Meshsage processes data. Because Meshsage is built on a decentralized network topology, **we do not collect, store, or share any personal information on any central server.**

---

## 1. Zero Data Collection Policy

We believe in absolute privacy. 
* **No Accounts**: You do not need to register an email address, phone number, or social media account to use Meshsage. Your identity is represented solely by a locally generated cryptographic keypair (PeerID).
* **No Analytics or Tracking**: We do not use third-party analytics SDKs, trackers, or diagnostic reporting tools (such as Google Analytics or Firebase). 
* **No Ads**: Meshsage does not serve any advertisements.

---

## 2. Local Data Storage

All data generated during your use of Meshsage is stored **locally on your device** in an encrypted SQLite database. This includes:
* Your chat message history (text and metadata).
* Shared media and files.
* Your cryptographic private keys (which represent your P2P identity).

Uninstalling the application or using the "Clear Database" feature in the app settings will permanently erase all of this data from your device. We do not have any backups, and we cannot recover this data for you.

---

## 3. Peer-to-Peer Data Transmission

When you send a message, it is transmitted directly to the recipient over a secure peer-to-peer connection (using QUIC or WebRTC direct transport protocols).
* **End-to-End Encryption (E2EE)**: All communications are encrypted end-to-end using the Double Ratchet Algorithm (Signal Protocol family) and X3DH key exchange. Nobody except you and the intended recipient can read your messages or view your shared files.
* **Decentralized Offline Mailbox**: If the recipient is offline, the encrypted message payload (a secure envelope) is temporarily uploaded to decentralized infrastructure mailbox nodes. 
  * Mailbox nodes **cannot decrypt** the message contents or access any personal identifiers.
  * Mailbox nodes only hold the encrypted payload temporarily until the recipient comes online and fetches it, after which the message is delivered and stored locally on the recipient's device.

---

## 4. Required Device Permissions

Meshsage requires the following permissions on your device to function correctly. These permissions are used strictly for local processing and P2P communication:

* **INTERNET / ACCESS_NETWORK_STATE**: Required to search the Kademlia DHT, discover peers, and establish P2P connection paths.
* **CAMERA**: Used exclusively for real-time video calling. Video streams are transmitted peer-to-peer and are never recorded or stored.
* **RECORD_AUDIO (Microphone)**: Used exclusively for real-time voice and video calling. Audio streams are transmitted peer-to-peer and are never recorded or stored.
* **READ/WRITE_EXTERNAL_STORAGE**: Required to select and share files/images with other peers, and to save incoming files locally on your device.
* **FOREGROUND_SERVICE / WAKE_LOCK**: Required to maintain background connectivity to the decentralized P2P network so you can receive incoming messages while the app is minimized.
* **POST_NOTIFICATIONS**: Required to show local system alerts when you receive a message.

---

## 5. Data Safety Declaration (Google Play)

For your Google Play Data Safety form, you can declare:
* **Data Collected**: **No** personal data is collected.
* **Data Shared**: **No** personal data is shared with third parties.
* **Security Practices**:
  * **Data Encrypted in Transit**: Yes, all P2P traffic and mailbox uploads are encrypted end-to-end.
  * **Data Deletion**: Yes, users can request data deletion by uninstalling the application or clearing the database locally.

---

## 6. Open Source Transparency

As an open-source project, our entire codebase, including all cryptographic and networking protocols, is fully auditable. You can inspect the implementation at:
[https://github.com/nicabreon/meshsage](https://github.com/nicabreon/meshsage)

---

## 7. Contact Us

If you have any questions or concerns about this Privacy Policy, you can open an issue on our GitHub repository:
[https://github.com/nicabreon/meshsage/issues](https://github.com/nicabreon/meshsage/issues)
