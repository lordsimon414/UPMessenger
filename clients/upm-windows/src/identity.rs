use base64::Engine;
use upm_crypto::{AgreementSecret, IdentityKeyPair};
use upm_protocol::PreKeyId;

#[derive(Debug)]
pub struct LocalOneTimePreKey {
    pub id: PreKeyId,
    pub secret: AgreementSecret,
}

#[derive(Debug)]
pub struct LocalIdentity {
    pub signing: IdentityKeyPair,
    pub exchange: AgreementSecret,
    pub signed_prekey: AgreementSecret,
    pub one_time_prekeys: Vec<LocalOneTimePreKey>,
}

impl LocalIdentity {
    pub fn generate() -> Self {
        Self {
            signing: IdentityKeyPair::generate(),
            exchange: AgreementSecret::generate(),
            signed_prekey: AgreementSecret::generate(),
            one_time_prekeys: Self::generate_one_time_prekeys(12),
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
        let mut message = Vec::with_capacity(21 + 32 + 32);
        message.extend_from_slice(b"UPM/v4/signed-prekey/");
        message.extend_from_slice(&self.exchange.public_key());
        message.extend_from_slice(&self.signed_prekey.public_key());
        base64::engine::general_purpose::STANDARD.encode(self.signing.sign(&message))
    }

    pub fn publishable_one_time_prekeys(&self) -> Vec<(PreKeyId, String, String)> {
        self.one_time_prekeys
            .iter()
            .map(|entry| {
                let public = entry.secret.public_key();
                let signature = self
                    .signing
                    .sign(&upm_core::handshake::one_time_prekey_signature_message(entry.id, &public));
                (
                    entry.id,
                    base64::engine::general_purpose::STANDARD.encode(public),
                    base64::engine::general_purpose::STANDARD.encode(signature),
                )
            })
            .collect()
    }

    pub fn find_one_time_prekey(&self, id: PreKeyId) -> Option<&AgreementSecret> {
        self.one_time_prekeys
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| &entry.secret)
    }

    pub fn remove_one_time_prekey(&mut self, id: PreKeyId) {
        self.one_time_prekeys.retain(|entry| entry.id != id);
    }

    pub fn ensure_one_time_prekey_pool(&mut self, target: usize) {
        let missing = target.saturating_sub(self.one_time_prekeys.len());
        if missing > 0 {
            self.one_time_prekeys.extend(Self::generate_one_time_prekeys(missing));
        }
    }

    fn generate_one_time_prekeys(count: usize) -> Vec<LocalOneTimePreKey> {
        use rand::RngCore;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut id = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut id);
            out.push(LocalOneTimePreKey {
                id: PreKeyId(id),
                secret: AgreementSecret::generate(),
            });
        }
        out
    }

    pub fn private_key_bytes(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (
            self.signing.private_key_bytes(),
            self.exchange.private_key_bytes(),
            self.signed_prekey.private_key_bytes(),
        )
    }

    pub fn one_time_prekey_private_keys(&self) -> Vec<(PreKeyId, [u8; 32])> {
        self.one_time_prekeys
            .iter()
            .map(|entry| (entry.id, entry.secret.private_key_bytes()))
            .collect()
    }

    pub fn from_private_key_bytes(
        signing: [u8; 32],
        exchange: [u8; 32],
        signed_prekey: [u8; 32],
        one_time_prekeys: Vec<(PreKeyId, [u8; 32])>,
    ) -> Self {
        Self {
            signing: IdentityKeyPair::from_private_key_bytes(signing),
            exchange: AgreementSecret::from_private_key_bytes(exchange),
            signed_prekey: AgreementSecret::from_private_key_bytes(signed_prekey),
            one_time_prekeys: one_time_prekeys
                .into_iter()
                .map(|(id, key)| LocalOneTimePreKey {
                    id,
                    secret: AgreementSecret::from_private_key_bytes(key),
                })
                .collect(),
        }
    }
}
