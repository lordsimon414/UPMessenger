# UPM Web client scaffold (Phase 5)

The browser client remains a weaker endpoint than native clients, per SRS §12. The future build will use
WebAssembly for the shared Rust protocol/crypto core and browser storage only for encrypted local state.

This folder currently contains the typed API boundary; no plaintext message data should be written to
browser console logs or persistent unencrypted storage.
