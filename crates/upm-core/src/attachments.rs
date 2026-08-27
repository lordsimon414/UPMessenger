//! Client-side encrypted attachment blobs (SRS §9).
//!
//! The server sees only an opaque blob. The attachment key is carried inside
//! the E2EE chat payload and is never sent to the server as plaintext.

use rand::RngCore;
use upm_crypto::{AeadKey, CryptoError};
use upm_protocol::MessageId;

pub const NONCE_LEN: usize = 12;

#[derive(Clone, Copy)]
pub struct AttachmentKey(pub [u8; 32]);

impl AttachmentKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }
}

pub fn encrypt(key: AttachmentKey, attachment_id: MessageId, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let aead_key = AeadKey::from_bytes(key.0);
    let ciphertext = upm_crypto::encrypt(&aead_key, &nonce, plaintext, &attachment_id.0)?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub fn decrypt(key: AttachmentKey, attachment_id: MessageId, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN {
        return Err(CryptoError::Aead);
    }
    let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN]
        .try_into()
        .map_err(|_| CryptoError::Aead)?;
    let aead_key = AeadKey::from_bytes(key.0);
    upm_crypto::decrypt(&aead_key, &nonce, &blob[NONCE_LEN..], &attachment_id.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_id_fail() {
        let key = AttachmentKey::generate();
        let id = MessageId::random();
        let plaintext = b"private attachment";
        let blob = encrypt(key, id, plaintext).unwrap();
        assert_eq!(decrypt(key, id, &blob).unwrap(), plaintext);
        assert!(decrypt(key, MessageId::random(), &blob).is_err());
    }

    #[test]
    fn tamper_fails_authentication() {
        let key = AttachmentKey::generate();
        let id = MessageId::random();
        let mut blob = encrypt(key, id, b"payload").unwrap();
        *blob.last_mut().unwrap() ^= 0x80;
        assert!(decrypt(key, id, &blob).is_err());
    }
}
