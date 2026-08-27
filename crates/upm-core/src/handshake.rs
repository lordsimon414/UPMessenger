//! X3DH-lite handshake: establishes a shared root key and initial chain
//! keys between two parties before the Double-Ratchet-style session
//! (`ratchet.rs`) takes over.
//!
//! This follows the public, well-analyzed X3DH design (Marlinspike/Perrin,
//! Signal) with one deliberate simplification: **no one-time prekey
//! (OPK)**, because the Phase 1 server (`upm-server`) doesn't have a
//! one-time-prekey table yet (SRS §8 lists per-message forward secrecy as
//! the requirement the *ratchet* provides; the OPK in full X3DH mainly
//! protects the initial handshake itself against a compromised signed
//! prekey). This is a documented, intentional gap — see `docs/ROADMAP.md`
//! — not a substitute cryptographic design: every DH step X3DH defines
//! (identity/signed-prekey combinations) is still present here.
//!
//! Key separation: identity *signing* (Ed25519, `upm_crypto::IdentityKeyPair`,
//! already used for device auth in `upm-server`) is kept separate from
//! identity *key agreement* (X25519, `upm_crypto::AgreementSecret`) rather
//! than reusing one Edwards keypair for both roles via a birational map —
//! simpler to reason about, at the cost of publishing two long-term public
//! keys instead of one.

use upm_crypto::{AgreementSecret, CryptoError};

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("signed prekey signature does not verify against the published identity signing key")]
    InvalidPrekeySignature,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// What a device publishes so others can start a session with it (SRS §16
/// device-key material, extended with the fields X3DH needs).
pub struct PreKeyBundle {
    /// Long-term Ed25519 key already used for device authentication
    /// (`upm-server`'s challenge-response login).
    pub identity_signing_public: [u8; 32],
    /// Long-term X25519 key used only for key agreement.
    pub identity_exchange_public: [u8; 32],
    /// Medium-term X25519 key, rotated periodically by the owning device.
    pub signed_prekey_public: [u8; 32],
    /// Signature over the X25519 identity-exchange key followed by the
    /// signed-prekey public key, made by `identity_signing_public`, so a
    /// malicious server can't swap in its own prekey (SRS §6 MITM
    /// resistance for the handshake).
    pub signed_prekey_signature: [u8; 64],
}


fn prekey_signature_message(identity_exchange_public: &[u8; 32], signed_prekey_public: &[u8; 32]) -> [u8; 64] {
    let mut message = [0u8; 64];
    message[..32].copy_from_slice(identity_exchange_public);
    message[32..].copy_from_slice(signed_prekey_public);
    message
}

fn verify_bundle(bundle: &PreKeyBundle) -> Result<(), HandshakeError> {
    upm_crypto::verify(
        &bundle.identity_signing_public,
        &prekey_signature_message(
            &bundle.identity_exchange_public,
            &bundle.signed_prekey_public,
        ),
        &bundle.signed_prekey_signature,
    )
    .map_err(|_| HandshakeError::InvalidPrekeySignature)
}

/// Root key plus the two initial chain keys, labeled from the
/// initiator's ("A's") point of view.
#[derive(Debug)]
pub struct HandshakeResult {
    pub root_key: [u8; 32],
    pub sending_chain_key: [u8; 32],
    pub receiving_chain_key: [u8; 32],
}

fn derive_chains(ikm: &[u8]) -> Result<([u8; 32], [u8; 32], [u8; 32]), CryptoError> {
    const SALT: &[u8] = b"upm/v2/x3dh-lite/salt";
    let mut root_key = [0u8; 32];
    upm_crypto::derive(SALT, ikm, b"upm/v2/x3dh/root-key", &mut root_key)?;
    let mut chain_a_to_b = [0u8; 32];
    upm_crypto::derive(SALT, ikm, b"upm/v2/x3dh/chain-a-to-b", &mut chain_a_to_b)?;
    let mut chain_b_to_a = [0u8; 32];
    upm_crypto::derive(SALT, ikm, b"upm/v2/x3dh/chain-b-to-a", &mut chain_b_to_a)?;
    Ok((root_key, chain_a_to_b, chain_b_to_a))
}

/// The output of `initiate`: what Alice keeps locally, plus what she must
/// send to Bob alongside her first ratchet-encrypted message (her identity
/// exchange key and the fresh ephemeral key) so he can complete his side.
#[derive(Debug)]
pub struct InitiatorHandshake {
    pub my_identity_exchange_public: [u8; 32],
    pub ephemeral_public: [u8; 32],
    pub result: HandshakeResult,
    /// Bob's signed prekey acts as his *initial* Double-Ratchet public key
    /// (see `ratchet::RatchetState::init_initiator`) — carried through so
    /// the caller doesn't have to thread the bundle around separately.
    pub bob_initial_ratchet_public: [u8; 32],
}

/// Alice's side: she already has Bob's published bundle.
pub fn initiate(
    my_identity_exchange: &AgreementSecret,
    their_bundle: &PreKeyBundle,
) -> Result<InitiatorHandshake, HandshakeError> {
    verify_bundle(their_bundle)?;

    let ephemeral = AgreementSecret::generate();

    let dh1 = my_identity_exchange.agree(&their_bundle.signed_prekey_public)?; // DH(IK_a, SPK_b)
    let dh2 = ephemeral.agree(&their_bundle.identity_exchange_public)?; // DH(EK_a, IK_b)
    let dh3 = ephemeral.agree(&their_bundle.signed_prekey_public)?; // DH(EK_a, SPK_b)

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

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
    })
}

/// Bob's side: he receives Alice's identity-exchange key and ephemeral key
/// (out of band, e.g. attached to her first ratchet message) and redoes
/// the same three DH computations with his own private keys. X25519's
/// `DH(a_priv, b_pub) == DH(b_priv, a_pub)` symmetry makes the results
/// match Alice's without either side ever sending a private key.
pub fn respond(
    my_identity_exchange: &AgreementSecret,
    my_signed_prekey: &AgreementSecret,
    their_identity_exchange_public: &[u8; 32],
    their_ephemeral_public: &[u8; 32],
) -> Result<HandshakeResult, HandshakeError> {
    let dh1 = my_signed_prekey.agree(their_identity_exchange_public)?; // DH(SPK_b, IK_a)
    let dh2 = my_identity_exchange.agree(their_ephemeral_public)?; // DH(IK_b, EK_a)
    let dh3 = my_signed_prekey.agree(their_ephemeral_public)?; // DH(SPK_b, EK_a)

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    let (root_key, chain_a_to_b, chain_b_to_a) = derive_chains(&ikm)?;

    // Bob's sending chain is the a-to-b... no — Bob *receives* on
    // chain_a_to_b (Alice sends on it) and *sends* on chain_b_to_a.
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

    fn make_bob_bundle() -> (PreKeyBundle, AgreementSecret, AgreementSecret) {
        let identity_signing = IdentityKeyPair::generate();
        let identity_exchange = AgreementSecret::generate();
        let signed_prekey = AgreementSecret::generate();
        let signature = identity_signing.sign(&prekey_signature_message(
            &identity_exchange.public_key(),
            &signed_prekey.public_key(),
        ));

        let bundle = PreKeyBundle {
            identity_signing_public: identity_signing.public_key(),
            identity_exchange_public: identity_exchange.public_key(),
            signed_prekey_public: signed_prekey.public_key(),
            signed_prekey_signature: signature,
        };
        (bundle, identity_exchange, signed_prekey)
    }

    #[test]
    fn alice_and_bob_derive_matching_keys() {
        let (bundle, bob_identity_exchange, bob_signed_prekey) = make_bob_bundle();
        let alice_identity_exchange = AgreementSecret::generate();

        let alice_hs = initiate(&alice_identity_exchange, &bundle).unwrap();
        let bob_hs = respond(
            &bob_identity_exchange,
            &bob_signed_prekey,
            &alice_hs.my_identity_exchange_public,
            &alice_hs.ephemeral_public,
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
    }

    #[test]
    fn tampered_identity_exchange_key_is_rejected() {
        let (mut bundle, _bob_ike, _bob_spk) = make_bob_bundle();
        bundle.identity_exchange_public[0] ^= 0xFF;
        let alice_identity_exchange = AgreementSecret::generate();
        let err = initiate(&alice_identity_exchange, &bundle).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidPrekeySignature));
    }

    #[test]
    fn tampered_prekey_signature_is_rejected() {
        let (mut bundle, _bob_ike, _bob_spk) = make_bob_bundle();
        bundle.signed_prekey_signature[0] ^= 0xFF;
        let alice_identity_exchange = AgreementSecret::generate();
        let err = initiate(&alice_identity_exchange, &bundle).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidPrekeySignature));
    }
}
