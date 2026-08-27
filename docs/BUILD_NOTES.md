# UPM build and smoke-test notes

The repository requires a Rust/MSVC Windows environment for the Windows client.
The recommended first checks are:

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p upm-server
```

In a second PowerShell window:

```powershell
cargo run -p upm-smoke -- http://127.0.0.1:8787
```

The smoke test exercises registration, Ed25519 challenge-response authentication,
an opaque message send/pull/ack, protocol-version handling, and device-bound queue
access. It intentionally does **not** claim to validate the full X3DH/ratchet protocol.

For a Windows client build:

```powershell
cargo build --release -p upm-windows
```

The workspace lockfile may need regeneration when new workspace members/dependencies
are first resolved on a clean checkout:

```powershell
cargo generate-lockfile
```
