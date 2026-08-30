//! Session / ratchet layer — the boundary between raw primitives
//! (`upm-crypto`), wire format (`upm-protocol`), and platform clients.
//!
//! # Status: Phase 2 — working implementation
//! `handshake` implements a UPM X3DH-style key agreement with signed
//! one-time-prekey support and `ratchet` implements a Double-Ratchet-style
//! session (`DoubleRatchetSession`) on top of it, providing forward secrecy,
//! bounded out-of-order delivery, and fail-closed replay/tamper rejection
//! (AC-05, AC-06, SRS §8).

pub mod attachments;
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
    #[error("peer's message counter is far ahead of the last one decrypted (usually a long gap since the two of you last synced; corrupted local state is possible but less likely)")]
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
