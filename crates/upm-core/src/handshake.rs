//! X3DH-style session establishment for UPM (SRS §6/§23).
//!
//! v4 keeps Ed25519 identity signing separate from X25519 key agreement,
//! authenticates the signed prekey, and optionally consumes one signed
//! one-time prekey (OPK) for the initial handshake. This is a UPM protocol
//! component inspired by X3DH; it is not claimed to be a standards-compatible
//! implementation of Signal's protocol without independent review.

use upm_crypto::{AgreementSecret, CryptoError};
use upm_protocol::PreKeyId;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("signed prekey signature does not verify against the published identity signing key")]
    InvalidPrekeySignature,
    #[error(
        "one-time prekey signature does not verify against the published identity signing key"
    )]
    InvalidOneTimePrekeySignature,
    #[error("one-time prekey id/public key/signature must either all be present or all be absent")]
    InvalidOneTimePrekeyBundle,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

pub struct PreKeyBundle {
    pub identity_signing_public: [u8; 32],
    pub identity_exchange_public: [u8; 32],
    pub signed_prekey_public: [u8; 32],
    pub signed_prekey_signature: [u8; 64],
    pub one_time_prekey_id: Option<PreKeyId>,
    pub one_time_prekey_public: Option<[u8; 32]>,
    pub one_time_prekey_signature: Option<[u8; 64]>,
}

fn signed_prekey_signature_message(
    identity_exchange_public: &[u8; 32],
    signed_prekey_public: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(21 + 32 + 32);
    message.extend_from_slice(b"UPM/v4/signed-prekey/");
    message.extend_from_slice(identity_exchange_public);
    message.extend_from_slice(signed_prekey_public);
    message
}

pub fn one_time_prekey_signature_message(id: PreKeyId, public_key: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(24 + 16 + 32);
    message.extend_from_slice(b"UPM/v4/one-time-prekey/");
    message.extend_from_slice(&id.0);
    message.extend_from_slice(public_key);
    message
}

fn verify_bundle(bundle: &PreKeyBundle) -> Result<(), HandshakeError> {
    upm_crypto::verify(
        &bundle.identity_signing_public,
        &signed_prekey_signature_message(
            &bundle.identity_exchange_public,
            &bundle.signed_prekey_public,
        ),
        &bundle.signed_prekey_signature,
    )
    .map_err(|_| HandshakeError::InvalidPrekeySignature)?;

    match (
        bundle.one_time_prekey_id,
        bundle.one_time_prekey_public,
        bundle.one_time_prekey_signature,
    ) {
        (None, None, None) => Ok(()),
        (Some(id), Some(public_key), Some(signature)) => upm_crypto::verify(
            &bundle.identity_signing_public,
            &one_time_prekey_signature_message(id, &public_key),
            &signature,
        )
        .map_err(|_| HandshakeError::InvalidOneTimePrekeySignature),
        _ => Err(HandshakeError::InvalidOneTimePrekeyBundle),
    }
}

#[derive(Debug)]
pub struct HandshakeResult {
    pub root_key: [u8; 32],
    pub sending_chain_key: [u8; 32],
    pub receiving_chain_key: [u8; 32],
}

/// `(root_key, chain_a_to_b, chain_b_to_a)` — named here purely to satisfy
/// clippy's type-complexity lint on the raw triple-tuple; carries no
/// additional semantics beyond `derive_chains`'s own doc comment.
type DerivedChains = ([u8; 32], [u8; 32], [u8; 32]);

fn derive_chains(ikm: &[u8]) -> Result<DerivedChains, CryptoError> {
    const SALT: &[u8] = b"upm/v4/x3dh/salt";
    let mut root_key = [0u8; 32];
    upm_crypto::derive(SALT, ikm, b"upm/v4/x3dh/root-key", &mut root_key)?;
    let mut chain_a_to_b = [0u8; 32];
    upm_crypto::derive(SALT, ikm, b"upm/v4/x3dh/chain-a-to-b", &mut chain_a_to_b)?;
    let mut chain_b_to_a = [0u8; 32];
    upm_crypto::derive(SALT, ikm, b"upm/v4/x3dh/chain-b-to-a", &mut chain_b_to_a)?;
    Ok((root_key, chain_a_to_b, chain_b_to_a))
}

pub struct InitiatorHandshake {
    pub my_identity_exchange_public: [u8; 32],
    pub ephemeral_public: [u8; 32],
    pub result: HandshakeResult,
    pub bob_initial_ratchet_public: [u8; 32],
    pub one_time_prekey_id: Option<PreKeyId>,
}

pub fn initiate(
    my_identity_exchange: &AgreementSecret,
    their_bundle: &PreKeyBundle,
) -> Result<InitiatorHandshake, HandshakeError> {
    verify_bundle(their_bundle)?;

    let ephemeral = AgreementSecret::generate();
    let dh1 = my_identity_exchange.agree(&their_bundle.signed_prekey_public)?;
    let dh2 = ephemeral.agree(&their_bundle.identity_exchange_public)?;
    let dh3 = ephemeral.agree(&their_bundle.signed_prekey_public)?;

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if let Some(opk_public) = their_bundle.one_time_prekey_public {
        ikm.extend_from_slice(&ephemeral.agree(&opk_public)?);
    }

    let (root_key, chain_a_to_b, chain_b_to_a) = derive_chains(&ikm)?;
    Ok(InitiatorHandshake {
        my_identity_exchange_public: my_identity_exchange.public_key(),
        ephemeral_public: ephemeral.public_key(),
        result: HandshakeResult {
            root_key,
            sending_chain_key: chain_a_to_b,
            receiving_chain_key: chain_b_to_a,
        },
        bob_initial_ratchet_public: their_bundle.signed_prekey_public,
        one_time_prekey_id: their_bundle.one_time_prekey_id,
    })
}

pub fn respond(
    my_identity_exchange: &AgreementSecret,
    my_signed_prekey: &AgreementSecret,
    their_identity_exchange_public: &[u8; 32],
    their_ephemeral_public: &[u8; 32],
    one_time_prekey: Option<&AgreementSecret>,
) -> Result<HandshakeResult, HandshakeError> {
    let dh1 = my_signed_prekey.agree(their_identity_exchange_public)?;
    let dh2 = my_identity_exchange.agree(their_ephemeral_public)?;
    let dh3 = my_signed_prekey.agree(their_ephemeral_public)?;

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if let Some(opk) = one_time_prekey {
        ikm.extend_from_slice(&opk.agree(their_ephemeral_public)?);
    }

    let (root_key, chain_a_to_b, chain_b_to_a) = derive_chains(&ikm)?;
    Ok(HandshakeResult {
        root_key,
        sending_chain_key: chain_b_to_a,
        receiving_chain_key: chain_a_to_b,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use upm_crypto::IdentityKeyPair;

    fn make_bob_bundle() -> (
        PreKeyBundle,
        AgreementSecret,
        AgreementSecret,
        AgreementSecret,
    ) {
        let identity_signing = IdentityKeyPair::generate();
        let identity_exchange = AgreementSecret::generate();
        let signed_prekey = AgreementSecret::generate();
        let opk_id = PreKeyId([0x55; 16]);
        let opk = AgreementSecret::generate();
        let signed_prekey_signature = identity_signing.sign(&signed_prekey_signature_message(
            &identity_exchange.public_key(),
            &signed_prekey.public_key(),
        ));
        let opk_signature = identity_signing.sign(&one_time_prekey_signature_message(
            opk_id,
            &opk.public_key(),
        ));
        let bundle = PreKeyBundle {
            identity_signing_public: identity_signing.public_key(),
            identity_exchange_public: identity_exchange.public_key(),
            signed_prekey_public: signed_prekey.public_key(),
            signed_prekey_signature,
            one_time_prekey_id: Some(opk_id),
            one_time_prekey_public: Some(opk.public_key()),
            one_time_prekey_signature: Some(opk_signature),
        };
        (bundle, identity_exchange, signed_prekey, opk)
    }

    #[test]
    fn alice_and_bob_derive_matching_keys_with_opk() {
        let (bundle, bob_identity_exchange, bob_signed_prekey, bob_opk) = make_bob_bundle();
        let alice_identity_exchange = AgreementSecret::generate();
        let alice_hs = initiate(&alice_identity_exchange, &bundle).unwrap();
        let bob_hs = respond(
            &bob_identity_exchange,
            &bob_signed_prekey,
            &alice_hs.my_identity_exchange_public,
            &alice_hs.ephemeral_public,
            Some(&bob_opk),
        )
        .unwrap();
        assert_eq!(alice_hs.result.root_key, bob_hs.root_key);
        assert_eq!(
            alice_hs.result.sending_chain_key,
            bob_hs.receiving_chain_key
        );
        assert_eq!(
            alice_hs.result.receiving_chain_key,
            bob_hs.sending_chain_key
        );
        assert_eq!(alice_hs.one_time_prekey_id, Some(PreKeyId([0x55; 16])));
    }

    #[test]
    fn invalid_opk_signature_is_rejected() {
        let (mut bundle, _, _, _) = make_bob_bundle();
        bundle.one_time_prekey_signature = Some([0u8; 64]);
        let alice_identity_exchange = AgreementSecret::generate();
        assert!(matches!(
            initiate(&alice_identity_exchange, &bundle),
            Err(HandshakeError::InvalidOneTimePrekeySignature)
        ));
    }
}
