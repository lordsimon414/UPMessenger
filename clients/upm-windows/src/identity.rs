use base64::Engine;
use upm_crypto::{AgreementSecret, IdentityKeyPair};

#[derive(Debug)]
pub struct LocalIdentity {
    pub signing: IdentityKeyPair,
    pub exchange: AgreementSecret,
    pub signed_prekey: AgreementSecret,
}

impl LocalIdentity {
    pub fn generate() -> Self {
        Self {
            signing: IdentityKeyPair::generate(),
            exchange: AgreementSecret::generate(),
            signed_prekey: AgreementSecret::generate(),
        }
    }

    pub fn identity_public_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.signing.public_key())
    }

    pub fn exchange_public_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.exchange.public_key())
    }

    pub fn signed_prekey_public_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.signed_prekey.public_key())
    }

    pub fn signed_prekey_signature_b64(&self) -> String {
        let mut message = [0u8; 64];
        message[..32].copy_from_slice(&self.exchange.public_key());
        message[32..].copy_from_slice(&self.signed_prekey.public_key());
        base64::engine::general_purpose::STANDARD.encode(self.signing.sign(&message))
    }
}


impl LocalIdentity {
    pub fn private_key_bytes(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (
            self.signing.private_key_bytes(),
            self.exchange.private_key_bytes(),
            self.signed_prekey.private_key_bytes(),
        )
    }

    pub fn from_private_key_bytes(signing: [u8; 32], exchange: [u8; 32], signed_prekey: [u8; 32]) -> Self {
        Self {
            signing: IdentityKeyPair::from_private_key_bytes(signing),
            exchange: AgreementSecret::from_private_key_bytes(exchange),
            signed_prekey: AgreementSecret::from_private_key_bytes(signed_prekey),
        }
    }
}
