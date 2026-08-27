//! Session / ratchet layer — the boundary between raw primitives
//! (`upm-crypto`), wire format (`upm-protocol`), and platform clients.
//!
//! # Status: Phase 2 — working implementation
//! `handshake` implements an X3DH-lite key agreement and `ratchet`
//! implements a Double-Ratchet-style session (`DoubleRatchetSession`) on
//! top of it, providing forward secrecy, out-of-order delivery within a
//! bounded window, and fail-closed replay/tamper rejection (AC-05, AC-06,
//! SRS §8). See `ratchet.rs` module docs for the specific, documented
//! scope limits (no one-time prekey yet, bounded skipped-key window).

pub mod handshake;
pub mod ratchet;

pub use handshake::{HandshakeError, HandshakeResult, InitiatorHandshake, PreKeyBundle};
pub use ratchet::{DoubleRatchetSession, SessionSnapshot};

use upm_crypto::CryptoError;
use upm_protocol::{DeviceId, ProtocolVersion};

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("malformed session wire message (bad JSON/base64 framing)")]
    Encoding,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("replay or stale envelope detected")]
    Replay,
    #[error("session not yet established with this device")]
    NotEstablished,
    #[error("peer's message counter skipped too many messages ahead (possible attack or corrupted state)")]
    TooManySkipped,
}

/// One end of a 1:1 ratcheting session with a specific peer device.
///
/// `DoubleRatchetSession` in `ratchet.rs` is the concrete implementation:
/// each successful `encrypt`/`decrypt` call advances the ratchet state,
/// providing forward secrecy and (per AC-06) rejecting replayed ciphertext
/// without producing a duplicate delivered message.
pub trait Session {
    fn protocol_version(&self) -> ProtocolVersion;
    fn peer_device(&self) -> DeviceId;

    /// Encrypts `plaintext` for the current ratchet step and advances state.
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError>;

    /// Decrypts and authenticates `ciphertext`, advancing/skipping ratchet
    /// state as needed. MUST fail closed on tampering or replay (SRS §8).
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError>;
}
