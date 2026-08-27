# Implementation roadmap (mirrors SRS §23)

| Phase | Deliverable | Priority | Status |
|---|---|---|---|
| 0. Foundation | Repo structure, protocol versioning, Rust core boundaries, CI, threat model | P0 | **Implemented** |
| 1. Server skeleton | Windows service, SQLite schema, TLS, account directory, queue | P0 | **Partially done**: SQLite schema, REST API, challenge-response auth, device-scoped pull/ack, bounded TTL queue, and localhost binding are implemented. Windows-service packaging and deployment hardening remain open. |
| 2. Crypto/session core | Identity keys, session establishment, ratchet integration, envelope format | P0 | **Partially done**: primitive wrappers, UPM X3DH-style OPKs, transactional Double-Ratchet-style session, versioned server queue envelopes, and restart-persistent client session/history state are implemented. A standards-compatible Signal/X3DH implementation is not claimed and still requires independent review. |
| 3. Windows + Android | 1:1 messaging, encrypted local DB, attachments | P0 | **In progress**: Windows 1:1 E2EE, UPM X3DH-style OPKs, transactional Double-Ratchet state, encrypted local history/outbox recovery, and client-side encrypted attachment upload/download are wired. Android client and stronger key-change UX remain. |
| 4. iOS | Shared core integration, Keychain, APNs-compatible wakeup flow | P0 | Not started |
| 5. Web | WASM core, browser storage, secure-session UX | P0 | Not started |
| 6. Small groups | Group key epochs, membership lifecycle, attachment sharing | P1 | Not started |
| 7. Hardening | Fuzzing, privacy-log audit, external security review | P0 before wider use | Not started |
| 8. Later | MLS-based groups, stronger multi-device model, calls, advanced recovery | P2 | Not started |

## What exists right now

- Cargo workspace with four crates: `upm-protocol`, `upm-crypto`, `upm-core`,
  `upm-server`.
- `upm-protocol`: protocol version type, compatibility-range negotiation
  (fails closed, per AC-12), `MessageEnvelope` wire type.
- `upm-crypto`: working wrappers for Ed25519 signatures, X25519 agreement
  (rejects non-contributory results), HKDF-SHA-256 with domain-separated
  labels, ChaCha20-Poly1305 AEAD. All backed by maintained crates, not
  hand-rolled.
- `upm-core`: **working session layer**.
  - `handshake.rs`: UPM X3DH-style key agreement using identity-exchange key,
    signed prekey, and an optional signed one-time prekey. The Ed25519
    signatures bind the published X25519 public keys and prekey IDs to the
    device identity. This is intentionally not labeled standards-compatible
    X3DH/Signal without independent review.
  - `ratchet.rs`: `DoubleRatchetSession` — a full Double-Ratchet-style
    implementation (DH ratchet + per-direction symmetric-key chains,
    skipped-message-key storage bounded at 1000 messages, JSON+base64
    wire framing). Implements the `Session` trait. Fails closed on
    tampering and rejects exact replays.
  - Tested: handshake key agreement, first-message roundtrip,
    multi-turn bidirectional conversation (several DH ratchet steps),
    out-of-order delivery within one chain, replay rejection, tamper
    rejection. 8 tests, all green.
  - Security hardening now includes **transactional decrypt**: failed AEAD
    authentication no longer commits ratchet/DH/skipped-key state, and the
    Windows client commits decrypted history, processed-message markers, and
    session snapshots atomically.
  - `upm-protocol::MessageEnvelope` now uses fixed 16-byte hex identifiers
    in JSON, `MessageId::random()` provides sender-side IDs, and the Windows
    client sends typed envelopes through `/v1/messages/send`. Protocol v4
    binds the X3DH-style bootstrap to the intended recipient device.
  - `/v1/devices/keys` refreshes the authenticated device's X3DH bundle
    (X25519 identity-exchange key, signed prekey, and Ed25519 signature)
    rather than creating an arbitrary device for a caller-supplied account.

- `upm-server`: working HTTP server (SQLite via `rusqlite`, `tiny_http`)
  implementing account registration, username directory resolution,
  authenticated device X3DH key refresh, message send/pull/ack (opaque
  ciphertext queue with TTL and protocol version), attachment metadata
  create/delete, and public profile lookup.
  **Authentication**: `POST /v1/auth/challenge` + `POST /v1/auth/verify`
  implement an Ed25519 challenge-response against the device's own stored
  identity key (no passwords, reusing the same primitive as message
  auth) and issue a bearer session token. `/v1/messages/send`,
  `/v1/messages/pull` (device-scoped — a token can only pull its own
  queue), `/v1/messages/ack`, `/v1/attachments/create`,
  `DELETE /v1/attachments/{id}` and `/v1/devices/keys` all require a valid
  bearer token; registration, directory resolve and public profile stay
  open by design. Verified end-to-end against a real Ed25519 keypair
  (Python `cryptography`), including a cross-device 403 check.
  Binds to localhost only by design — TLS and public exposure are left to
  a reverse proxy / Cloudflare Tunnel per SRS §10.1. No Windows-service
  wrapper yet (currently a plain console binary); no WebSocket/streaming
  push (clients must poll `GET /v1/messages/pull` for now).
- CI: `cargo build`, `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check` on every push (see `.github/workflows/ci.yml`).

## Next concrete steps

1. Add stronger device/key-change UX and explicit trust-state screens in the Windows client.
2. Package `upm-server` as a Windows service and document filesystem ACL/firewall/Cloudflare Tunnel deployment.
3. Add request/queue/disk quotas, fuzz/property tests, privacy-log tests, and restart/interoperability tests. A local `upm-smoke` transport test now covers registration/authentication/send/pull/ack.
4. Finish Windows security UX and platform abstraction work, then start Android client integration against the same protocol/core boundaries, followed by iOS and Web as specified in SRS §23.
5. Keep the UPM X3DH-style design explicitly versioned; do not call it Signal/X3DH-compatible without independent review.
6. Run an independent security review before wider real-world use, as required by the SRS release posture.

## Windows client status

A Phase 3 Windows desktop client exists under `clients/upm-windows`. It uses the shared Rust protocol/crypto crates and wires account registration, Ed25519 challenge-response authentication, UPM X3DH-style signed/one-time prekey publication and claim, peer identity pinning, first-message bootstrap, Double-Ratchet-style 1:1 encryption/decryption, queue polling, authenticated acknowledgements, encrypted local persistence of message history/session snapshots, transactional outbox retry, and encrypted attachment upload/download. Android remains the next client target.
