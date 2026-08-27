//! Cryptographic primitive boundary for UPM.
//!
//! Every primitive here maps directly to a row in SRS §6 ("Cryptography and
//! protocol requirements"). This crate only *wraps* established, maintained
//! libraries — per SEC-02 in the SRS requirement index, no custom cipher,
//! KDF, signature scheme or ratchet may be invented for UPM. Session state
//! machines (the Double-Ratchet-style model) belong in `upm-core`, which
//! consumes these primitives; they are deliberately not implemented here.
//!
//! Foundation-phase scope (this file): identity signatures, key agreement,
//! key derivation, authenticated encryption. Phase 2 (SRS §23) builds the
//! session/ratchet layer on top of this boundary in `upm-core`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("key agreement produced a non-contributory (e.g. all-zero) shared secret")]
    NonContributoryKeyAgreement,
    #[error("key derivation failed: output length not available from this PRK")]
    KeyDerivation,
    #[error(
        "authenticated encryption failed (wrong key, nonce reuse guard, or tampered ciphertext)"
    )]
    Aead,
}

// ---------------------------------------------------------------------
// Identity signatures — Ed25519 (SRS §6: "MUST be implemented through a
// maintained, reviewed library").
// ---------------------------------------------------------------------

pub struct IdentityKeyPair {
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        IdentityKeyPair {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Exports the Ed25519 private key bytes so platform clients can place
    /// them in OS-protected credential/key storage. The bytes MUST NOT be
    /// logged or persisted in ordinary files.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Restores an Ed25519 identity key from OS-protected client storage.
    pub fn from_private_key_bytes(bytes: [u8; 32]) -> Self {
        Self { signing_key: SigningKey::from_bytes(&bytes) }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidSignature)?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

// ---------------------------------------------------------------------
// Key agreement — X25519 (SRS §6: "MUST use established implementation and
// reject invalid/all-zero shared results where applicable").
// ---------------------------------------------------------------------

#[derive(Clone)]
pub struct AgreementSecret(x25519_dalek::StaticSecret);

impl AgreementSecret {
    pub fn generate() -> Self {
        AgreementSecret(x25519_dalek::StaticSecret::random_from_rng(OsRng))
    }

    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }

    /// Exports the X25519 private key bytes for OS-protected platform storage.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Restores an X25519 private key from OS-protected client storage.
    pub fn from_private_key_bytes(bytes: [u8; 32]) -> Self {
        AgreementSecret(x25519_dalek::StaticSecret::from(bytes))
    }

    /// Diffie-Hellman agreement. Rejects non-contributory (degenerate /
    /// all-zero) results per SRS §6 instead of returning them silently.
    pub fn agree(&self, their_public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let their_public = x25519_dalek::PublicKey::from(*their_public);
        let shared = self.0.diffie_hellman(&their_public);
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributoryKeyAgreement);
        }
        Ok(shared.to_bytes())
    }
}

// ---------------------------------------------------------------------
// Key derivation — HKDF-SHA-256 (SRS §6: "MUST be used with domain
// separation / explicit context labels").
// ---------------------------------------------------------------------

/// Derives `output.len()` bytes from `input_key_material`, salted with
/// `salt` and bound to an explicit domain-separation `info` label. Callers
/// MUST pass a distinct `info` label per use (e.g. b"upm/v1/root-key",
/// b"upm/v1/chain-key") so outputs of the same IKM never collide.
pub fn derive(
    salt: &[u8],
    input_key_material: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    hk.expand(info, output)
        .map_err(|_| CryptoError::KeyDerivation)
}

// ---------------------------------------------------------------------
// Message encryption — ChaCha20-Poly1305 (SRS §6: "MUST provide
// authenticated encryption; unique nonces per key as required").
// ---------------------------------------------------------------------

/// A 256-bit symmetric key. Zeroized on drop — SRS §11/§12 require
/// sensitive local key material not to linger in memory longer than needed.
pub struct AeadKey([u8; 32]);

impl AeadKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        AeadKey(bytes)
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        // Minimal dependency-free zeroize: volatile writes the compiler
        // cannot optimize away, followed by a fence so the writes are not
        // reordered past this point. If a vetted `zeroize` crate release
        // becomes compatible with the project's MSRV, prefer that instead.
        for byte in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Encrypts `plaintext` under `key` with a caller-supplied 12-byte nonce.
/// Nonce uniqueness per key is the caller's responsibility (see module docs
/// in `upm-core`, which owns the ratchet's nonce/counter bookkeeping) —
/// reusing a nonce with the same key breaks confidentiality.
pub fn encrypt(
    key: &AeadKey,
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// Decrypts and authenticates `ciphertext`. Fails closed (SRS §8: "Crypto
/// failures MUST fail closed; no automatic plaintext fallback") — any
/// tampering or wrong key/nonce returns `Err`, never partial plaintext.
pub fn decrypt(
    key: &AeadKey,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = IdentityKeyPair::generate();
        let msg = b"upm handshake";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_key(), msg, &sig).is_ok());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let kp = IdentityKeyPair::generate();
        let msg = b"upm handshake";
        let mut sig = kp.sign(msg);
        sig[0] ^= 0xFF;
        assert!(verify(&kp.public_key(), msg, &sig).is_err());
    }

    #[test]
    fn x25519_agreement_matches_both_sides() {
        let alice = AgreementSecret::generate();
        let bob = AgreementSecret::generate();
        let a_shared = alice.agree(&bob.public_key()).unwrap();
        let b_shared = bob.agree(&alice.public_key()).unwrap();
        assert_eq!(a_shared, b_shared);
    }

    #[test]
    fn aead_roundtrip_and_tamper_detection() {
        let key = AeadKey::from_bytes([7u8; 32]);
        let nonce = [0u8; 12];
        let ct = encrypt(&key, &nonce, b"hello upm", b"header").unwrap();
        let pt = decrypt(&key, &nonce, &ct, b"header").unwrap();
        assert_eq!(pt, b"hello upm");

        let mut tampered = ct.clone();
        tampered[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, &tampered, b"header").is_err());
    }

    #[test]
    fn hkdf_derives_deterministic_domain_separated_keys() {
        let ikm = b"shared-secret-material";
        let mut root_key = [0u8; 32];
        let mut chain_key = [0u8; 32];
        derive(b"upm-salt", ikm, b"upm/v1/root-key", &mut root_key).unwrap();
        derive(b"upm-salt", ikm, b"upm/v1/chain-key", &mut chain_key).unwrap();
        assert_ne!(
            root_key, chain_key,
            "distinct info labels must yield distinct output"
        );
    }
}
