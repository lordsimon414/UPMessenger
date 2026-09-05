# UPM — Private Messaging Platform

UPM is a small private end-to-end encrypted messaging system for a trusted user group. The engineering baseline is defined by `UPM SRS 1.1` and targets Windows, Android, iOS, and Web with a deliberately small operational footprint.

## Current implementation

The repository currently contains:

- `upm-protocol`: versioned wire types and compatibility negotiation.
- `upm-crypto`: reviewed-library wrappers for Ed25519, X25519, HKDF-SHA-256, and ChaCha20-Poly1305.
- `upm-core`: UPM X3DH-style handshake with signed one-time prekeys, Double-Ratchet-style 1:1 session implementation with transactional failed-decryption handling, and client-side attachment encryption.
- `upm-server`: SQLite-backed delivery server with challenge-response device authentication, username/UPM-ID lookup, X3DH-style key publication/OPK claim, sender/recipient-bound envelopes, TTL/bounded queues, and opaque attachment blob storage.
- `clients/upm-windows`: Windows desktop client with account registration, authenticated login, peer identity pinning, X3DH-style session bootstrap, Double-Ratchet 1:1 encryption/decryption, encrypted local history/session state, outbox recovery, and encrypted attachment transfer.

## Important status

This is **not yet a production release**. The Android/iOS/Web clients, fuzzing/interoperability testing, and independent security review remain outstanding. The UPM X3DH-style protocol is not claimed to be Signal/X3DH standards-compatible without independent review.

See `docs/ROADMAP.md`, `docs/SECURITY_REVIEW.md`, and the supplied UPM SRS for the authoritative requirements and release posture. See `docs/BETA_DEPLOYMENT.md` for exposing the server beyond localhost (Cloudflare Tunnel) for real beta testers.

## Running the server

```text
cargo run -p upm-server
```

Binds to `127.0.0.1:8787` by default (main API) plus `127.0.0.1:8788` (a local-only admin dashboard at `/admin` — never expose this port beyond localhost; see `docs/BETA_DEPLOYMENT.md`). On Windows, `upm-server install`/`upm-server uninstall` register it as a proper Windows service instead of running it in a console.

## Windows client

Build or run on a Windows Rust/MSVC environment:

```text
cargo run -p upm-windows
cargo build -p upm-windows --release
```

The workspace CI contains a Windows build job that packages the release executable as a workflow artifact.

## Local Windows test workflow

After installing Rust, run these from the repository root in PowerShell:

```powershell
.\scripts\check.ps1
.\scripts\build-windows.ps1
```

For a local development server:

```powershell
.\scripts\run-server.ps1
```

The server binds to `127.0.0.1:8787` by default and uses `upm-dev.sqlite3`. This is a development setup only; the production SRS deployment requires the documented localhost/tunnel/network-isolation arrangement.

## Server smoke test

With the development server running in one PowerShell window:

```powershell
cargo run -p upm-server
```

run the transport smoke test in another:

```powershell
cargo run -p upm-smoke -- http://127.0.0.1:8787
```

The smoke test deliberately does not claim to prove the cryptographic ratchet; it verifies the server's registration, challenge-response authentication, opaque envelope routing, protocol version handling, and recipient-scoped ACK behavior.
