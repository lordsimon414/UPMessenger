# UPM Windows Client

Initial Phase 3 Windows desktop client shell, built on the shared UPM Rust protocol/crypto core.

## Current scope

- Native desktop window via `eframe`/`winit`.
- UPM account registration using the device Ed25519 identity key.
- Challenge-response authentication.
- UPM X3DH-style device-key bundle publication, including signed one-time prekeys.
- Username directory resolution.
- Authenticated message queue polling and recipient-scoped acknowledgement.
- Remote X3DH-lite prekey-bundle retrieval and peer identity verification.
- First-message session bootstrap plus Double-Ratchet-style 1:1 encryption/decryption.
- Typed, versioned message envelopes carrying sender and recipient device IDs.
- Windows Credential Manager-backed local profile and long-lived identity-key storage through `keyring`.

## Remaining Phase 3 gaps

The Windows client stores decrypted message history and serialized Double-Ratchet state in a local SQLite database, with each record encrypted using a random-nonce ChaCha20-Poly1305 key held through the Windows credential-store abstraction. Android integration, stronger key-change UX, and broader interoperability/security testing remain next steps. The UPM X3DH-style construction is not claimed to be standards-compatible X3DH/Signal without independent review.

Build on Windows with:

```text
cargo run -p upm-windows
```

Release build:

```text
cargo build -p upm-windows --release
```


## Release CI

The workspace CI now contains a Windows runner that builds `upm-windows` in release mode and uploads `upm-windows.exe` as a workflow artifact. Local compilation requires a Windows Rust/MSVC environment.
