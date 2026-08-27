# Implementation roadmap (mirrors SRS §23)

| Phase | Deliverable | Priority | Status |
|---|---|---|---|
| 0. Foundation | Repo structure, protocol versioning, Rust core boundaries, CI, threat model | P0 | **Implemented** |
| 1. Server skeleton | Windows service, SQLite schema, TLS, account directory, queue | P0 | **Partially done**: SQLite schema, REST API, challenge-response auth, device-scoped pull/ack, bounded TTL queue, and localhost binding are implemented. Windows-service packaging and deployment hardening remain open. |
| 2. Crypto/session core | Identity keys, session establishment, ratchet integration, envelope format | P0 | **Partially done**: primitive wrappers, X3DH-lite, transactional Double-Ratchet-style session, and versioned server queue envelopes are implemented. Full X3DH OPKs, persistence, and complete shared-envelope integration remain open. |
| 3. Windows + Android | 1:1 messaging, encrypted local DB, attachments | P0 | **In progress**: Windows 1:1 peer session, X3DH-lite bootstrap, Double-Ratchet message encryption/decryption, encrypted local message/session records, and authenticated queue flow are wired; attachments, Android client, stronger key-change UX, and full X3DH OPKs remain |
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
  - `handshake.rs`: X3DH-lite key agreement (identity exchange key +
    signed prekey, no one-time prekey yet — documented gap, see below)
    producing a shared root key and initial chain keys. The Ed25519
    signature binds both published X25519 public keys to the device identity.
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
    authentication no longer commits ratchet/DH/skipped-key state. The
    remaining session gaps are no one-time prekeys and session persistence.
  - `upm-protocol::MessageEnvelope` now uses fixed 16-byte hex identifiers
    in JSON, `MessageId::random()` provides sender-side IDs, and
    `DoubleRatchetSession::encrypt_envelope()` packages authenticated
    ciphertext into the typed envelope. The HTTP client integration remains
    part of Phase 3.
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

1. Add a one-time-prekey table/server operation and extend the handshake to
   full X3DH, closing the documented initial-handshake gap.
2. Expand the encrypted Windows local store with stronger transactional
   outbox/restart recovery semantics and key-change state.
3. Add encrypted attachment blob upload/download and ownership checks.
4. Package `upm-server` as a Windows service, add Windows CI, and document
   filesystem ACL/firewall/Cloudflare Tunnel deployment.
5. Add request/queue/disk quotas, fuzz/property tests, privacy-log tests,
   persistence/restart tests, and cross-platform interoperability tests.
6. Run an independent security review before wider real-world use, as
   required by the SRS release posture.


## Windows client status

A Phase 3 Windows desktop client now exists under `clients/upm-windows`. It uses the shared Rust protocol/crypto crates and wires account registration, Ed25519 challenge-response authentication, X3DH-lite prekey publication/lookup, peer identity verification, first-message session bootstrap, Double-Ratchet-style 1:1 encryption/decryption, queue polling, authenticated acknowledgements, and encrypted local persistence of message history/session snapshots. Transactional outbox recovery and full attachment storage remain open.
