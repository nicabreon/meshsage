# Privacy Policy for Meshsage

**Last Updated: June 15, 2026**

Meshsage is a decentralized, open-source, peer-to-peer (P2P) messaging application. This Privacy Policy explains how Meshsage processes data. Because Meshsage is built on a decentralized network topology, **we do not collect, store, or share any personal information on any central server.**

---

## 1. Zero Data Collection Policy

We believe in absolute privacy. 
* **No Accounts**: You do not need to register an email address, phone number, or social media account to use Meshsage. Your identity is represented solely by a locally generated cryptographic keypair (PeerID).
* **No Analytics or Tracking**: We do not use third-party analytics SDKs, trackers, or diagnostic reporting tools for user profiling. To support push notifications when the application is offline or minimized on mobile devices, we utilize Google Firebase Cloud Messaging (FCM). This is strictly used for notification delivery and not for user tracking.
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
* **Push Notifications (Firebase Cloud Messaging)**: On mobile platforms, because direct P2P connections cannot be sustained in the background indefinitely due to OS constraints, we use FCM to deliver "silent push" wake-up notifications.
  * When the app initializes, it retrieves a push token from Firebase.
  * This token is encrypted asymmetrically via **ECIES** with the public key of the FCM Push Service daemon and signed using your private key, ensuring only the daemon can decrypt it and verifying your ownership of the PeerID.
  * When an offline message is stored in your mailbox, a secure event triggers the Push Service daemon to dispatch a push notification to wake up your device for retrieval. No personal data is attached to this notification.

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
* **Data Collected**: Yes, **Device or other IDs** (specifically the FCM Push Token) are collected strictly for App Functionality and Communications.
* **Data Shared**: No personal data is shared with third parties (the FCM token is transmitted only to our own push service daemon and processed by Google FCM strictly to deliver notifications).
* **Data Linkage**: The collected Device ID is **not linked** to your real-world identity (no name, email, or phone number is collected).
* **Security Practices**:
  * **Data Encrypted in Transit**: Yes, all P2P traffic, mailbox uploads, and FCM token registrations are encrypted in transit.
  * **Data Deletion**: Yes, users can request data deletion by uninstalling the application or clearing the database locally. The push service daemon automatically updates or replaces your token when a new registration event occurs.

---

## 6. Open Source Transparency

As an open-source project, our entire codebase, including all cryptographic and networking protocols, is fully auditable. You can inspect the implementation at:
[https://github.com/nicabreon/meshsage](https://github.com/nicabreon/meshsage)

---

## 7. Contact Us

If you have any questions or concerns about this Privacy Policy, you can open an issue on our GitHub repository:
[https://github.com/nicabreon/meshsage/issues](https://github.com/nicabreon/meshsage/issues)
