# Walkthrough: Automated E2E Testing & Message Encryption/Decryption Proofs

Automated end-to-end (E2E) testing was successfully completed using the [e2e_test_scenarios.sh](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/e2e_test_scenarios.sh) script. All scenarios (Scenarios 1, 2, 3, and 4) finished with a status of **SUCCESS** and proved that E2EE encryption and decryption work correctly in both online and offline states.

---

## Testing Node Identity Summary

* **Dedicated Relay Port 6001**: `12D3KooWMuRGHZZG6ZRDJ4dy4aegKkdv1zwof3xtrzegPjuc77KA`
* **Alice Port 6002**: `12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9` (@alice)
* **Bob Port 6003**: `12D3KooWJKdw7ZqVnoG1x2uH2ohJEAWhyviXuHwk2mVNAXk8pmjs` (@bob)
* **Charlie Port 6004**: `12D3KooWQ5ey8EUFVd1YsazgwnxkqHk4n5nS39ym4WtkSCAvL7nM` (@charlie)

---

## Scenarios & Verification Log Evidence

### SCENARIO 1: 1:1 Messaging (Online) - Alice -> Bob

* **Action**: Alice sends an online message to Bob, who is also actively online.
* **Original Message**: `Halo Bob! Ini pesan online pertama dari Alice.`
* **Receipt Proof in Bob's Log**:
  ```text
  [HANDSHAKE] Receiving new X3DH Handshake from 12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9
  [HANDSHAKE] Deriving shared secret from receiver's Pre-Key...
  [HANDSHAKE] Initial session established. RootKey: mGbJ3n...
  [Message from 12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9]: Halo Bob! Ini pesan online pertama dari Alice.
  ```

---

### SCENARIO 2: 1:1 Messaging (Offline) - Alice -> Bob (Offline)

* **Action**: Bob is turned off, then Alice sends a message to Bob. The message is automatically routed to the Relay Mailbox. After Bob is turned back on, Bob calls `/fetch`.
* **Original Message**: `Halo Bob! Ini pesan offline saat kamu sedang tidak aktif.`
* **Receipt Proof in Bob's Log after /fetch**:
  ```text
  [Message from 12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9]: Halo Bob! Ini pesan offline saat kamu sedang tidak aktif.
  ```

---

### SCENARIO 3: Group Chat (Online) - Alice, Bob, Charlie

* **Action**: All members join group `GRP_TEST`. Alice sends a group message online while all members are active.
* **Original Message**: `Halo teman-teman! Kita semua online di grup.`
* **Encryption Proof in Alice's Log**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP ENCRYPTION ---
  [GROUP E2EE] Original Text: Halo teman-teman! Kita semua online di grup.
  [GROUP E2EE] Encrypted Result (B64): XX8ExfU3/zxDEfRMAjrWGbhBO2Rc2mhD3v36RXMbTWw/lVbBuLJ34rSYZVJY73e1IpJcjzIG5uNI1xHtmVl3RLFxHffXEevGI0SB5ExCZ+2Ab6SMUrAuJDArTHun
  [Group Ratchet] Rotated our local key for group GRP_TEST
  ```
* **Decryption Proof in Bob's Log**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---
  [GROUP E2EE] Decrypted Result: Halo teman-teman! Kita semua online di grup.
  [Group Security] Message from @12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9 verified with Digital Signature.
  [Group GRP_TEST] @12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9: Halo teman-teman! Kita semua online di grup.
  ```
* **Decryption Proof in Charlie's Log**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---
  [GROUP E2EE] Decrypted Result: Halo teman-teman! Kita semua online di grup.
  [Group GRP_TEST] @12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9: Halo teman-teman! Kita semua online di grup.
  ```

---

### SCENARIO 4: Group Chat (Offline Alternately)

This scenario verifies group messaging functionality when members are offline alternately, as well as automatic group membership recovery on node startup.

#### 1. Charlie Offline, Alice sends group message:
* **Original Message**: `Halo grup! Charlie sedang offline saat ini.`
* **Encryption Proof in Alice's Log**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP ENCRYPTION ---
  [GROUP E2EE] Original Text: Halo grup! Charlie sedang offline saat ini.
  [GROUP E2EE] Encrypted Result (B64): 4YF4S+UHH9XTGjAkwghjW/2R2EoaWK6oLEyIsbW8NjUC/Dw4GsBjnvarupHqQ2VxCg3wnRnN8s7pgS3Zdkec0fF8HEKZuD1D0TOaSsetiCsfLl6yOqePIAaEiLDuQXA=
  ```
* **Online Receipt Proof in Bob's Log**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---
  [GROUP E2EE] Decrypted Result: Halo grup! Charlie sedang offline saat ini.
  [Group GRP_TEST] @12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9: Halo grup! Charlie sedang offline saat ini.
  ```

#### 2. Bob Offline, Charlie turned back on:
* **Group Recovery Proof on Charlie Startup**:
  ```text
  [Alias DHT] Loaded 2 persisted aliases from database.
  [GROUP HANDSHAKE] Sharing our local key for group GRP_TEST with member 12D3KooWPvLqf5C8dxsnCyThSiNHVBSRbRTbwXubbsSrWdcTJuq9 via Double Ratchet...
  [Group] Successfully joined room: GRP_TEST with 3 members
  [90m2026-05-22T09:32:47+07:00 [0m [32mINF [0m [1mAuto-restored group membership on startup [0m [36mgroupID= [0mGRP_TEST
  ```
* **Charlie calls `/fetch` for offline messages**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION (OFFLINE) ---
  [GROUP E2EE] Decrypted Result: Halo grup! Charlie sedang offline saat ini.
  ```

#### 3. Charlie sends new group message while Bob is offline:
* **Original Message**: `Halo Alice! Saya sudah online kembali. Bob kemana?`
* **Encryption Proof in Charlie's Log**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP ENCRYPTION ---
  [GROUP E2EE] Original Text: Halo Alice! Saya sudah online kembali. Bob kemana?
  ```
* **Online Receipt Proof in Alice's Log**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION ---
  [GROUP E2EE] Decrypted Result: Halo Alice! Saya sudah online kembali. Bob kemana?
  ```

#### 4. Bob turned back on & retrieves offline messages:
* **Bob calls `/fetch`**:
  ```text
  [GROUP E2EE] --- LAYER 1: GROUP DECRYPTION (OFFLINE) ---
  [GROUP E2EE] Decrypted Result: Halo Alice! Saya sudah online kembali. Bob kemana?
  ```

---

## Final Verification

All functionalities of the distributed messaging platform (Meshsage) have been verified to work stably:
1. **Double Ratchet & X3DH**: Online and offline 1:1 messaging is secure with no decryption errors.
2. **GossipSub Group Messaging**: Real-time distribution of group messages works flawlessly.
3. **Offline Group Mailbox**: Group messages sent while members are offline are saved in the relay mailbox server and retrieved completely intact.
4. **Group State Restoration**: When a node restarts, group membership is automatically restored from the SQLite database, allowing immediate key exchanges and communication without manual rejoin commands.
