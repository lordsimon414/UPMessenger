# UPM implementation security review — Phase 0–2

This review compares the repository implementation with UPM SRS 1.1 and records the security fixes applied in this update. It is an engineering review, not a cryptographic certification.

## Fixed in this update

- **Transactional ratchet decryption:** failed or tampered messages are processed against cloned candidate state. Ratchet/DH/skipped-key state is committed only after AEAD authentication succeeds.
- **Recipient-scoped ACKs:** message acknowledgement/deletion is authorized by the authenticated recipient device, so one device cannot delete another device's queued ciphertext by message ID alone.
- **Authenticated device key refresh:** `/v1/devices/keys` now updates only the authenticated device and requires an X25519 identity-exchange key, signed prekey, and Ed25519 signature.
- **X3DH key binding:** the Ed25519 signature now covers both the X25519 identity-exchange public key and signed prekey public key.
- **Hashed session tokens:** bearer tokens are stored as SHA-256 digests rather than plaintext token values. Existing Phase 1 token tables are migrated on startup.
- **Typed protocol envelope:** the server accepts sender-generated message IDs and a protocol version, constructs the shared `upm-protocol::MessageEnvelope` with authenticated sender/recipient device IDs, and rejects unsupported protocol versions.
- **Windows 1:1 E2EE path:** the client now retrieves the peer's public X3DH-lite bundle, verifies peer identity continuity, signs the first-message bootstrap, establishes a Double-Ratchet-style session, encrypts/decrypts message content locally, and ACKs only after successful decryption.
- **Attachment ownership:** attachment metadata create/delete operations are bound to the authenticated device.
- **Protocol migration safety:** pre-v2 queued messages are removed during startup rather than relabeled as v2.

## Still release-blocking / intentionally outstanding

- Full X3DH with one-time prekeys is not implemented yet; the core remains X3DH-lite.
- Full transactional outbox recovery is not implemented; the Windows client now persists encrypted ratchet snapshots and message history, but send-state and server-queue acknowledgement are not yet one atomic workflow.
- Native/Web clients are not implemented.
- The server is still a console binary rather than a Windows service.
- TLS/public deployment is still external to the server process; the intended deployment remains the SRS localhost + outbound tunnel model.
- Encrypted attachment blob upload/download is not implemented; only metadata slots exist.
- Queue/disk quotas, fuzz/property tests, persistence/restart tests, privacy-log verification, cross-platform interoperability, and independent security review remain outstanding.

Before wider real-world use, follow the SRS release gate: known critical findings must be fixed and residual risk explicitly accepted, with an independent security review of the protocol/key-management design.


## Windows client addition

The Phase 3 Windows client stores the local profile and long-lived identity key material through the Windows Credential Manager abstraction (`keyring`) rather than ordinary plaintext files. Message history and serialized Double-Ratchet session state are stored as ChaCha20-Poly1305-encrypted records in local SQLite, with the database key held through the credential-store abstraction. Transactional outbox recovery and full attachment storage remain future work.
