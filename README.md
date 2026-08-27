# UPM — Private Messaging Platform

UPM is a small private end-to-end encrypted messaging system for a trusted user group. The engineering baseline is defined by `UPM SRS 1.1` and targets Windows, Android, iOS, and Web with a deliberately small operational footprint.

## Current implementation

The repository currently contains:

- `upm-protocol`: versioned wire types and compatibility negotiation.
- `upm-crypto`: reviewed-library wrappers for Ed25519, X25519, HKDF-SHA-256, and ChaCha20-Poly1305.
- `upm-core`: X3DH-lite handshake and Double-Ratchet-style 1:1 session implementation with transactional failed-decryption handling.
- `upm-server`: SQLite-backed delivery server with challenge-response device authentication, public X3DH bundle lookup/refresh, sender/recipient-bound envelopes, TTL queues, and attachment metadata.
- `clients/upm-windows`: Windows desktop client with account registration, authenticated login, peer discovery, X3DH-lite session bootstrap, Double-Ratchet 1:1 encryption/decryption, and recipient-scoped acknowledgement.

## Important status

This is **not yet a production release**. Full X3DH one-time prekeys, real encrypted attachment blob transfer, Windows service packaging, the Android/iOS/Web clients, fuzzing/interoperability testing, stronger key-change UX, and independent security review remain outstanding.

See `docs/ROADMAP.md`, `docs/SECURITY_REVIEW.md`, and the supplied UPM SRS for the authoritative requirements and release posture.

## Windows client

Build or run on a Windows Rust/MSVC environment:

```text
cargo run -p upm-windows
cargo build -p upm-windows --release
```

The workspace CI contains a Windows build job that packages the release executable as a workflow artifact.
