//! Double-Ratchet-style session (SRS §6, roadmap Phase 2). Implements the
//! `Session` trait from `lib.rs` against the well-analyzed public design
//! (Perrin/Marlinspike, Signal's Double Ratchet Algorithm spec) — combining
//! a Diffie-Hellman ratchet (fresh X25519 keypair per direction switch)
//! with a symmetric-key KDF chain per direction, on top of `upm-crypto`
//! primitives. No custom cryptographic construction is introduced here
//! (SEC-02) — this module *implements* that existing spec, it doesn't
//! invent a new one.
//!
//! Deliberate scope limits, documented rather than silently assumed:
//! - Message keys are used exactly once and then discarded, so a fixed
//!   all-zero AEAD nonce per message is safe (the whole point of a
//!   symmetric-key ratchet is that the key never repeats).
//! - Skipped-message key storage is bounded (`MAX_SKIP`) to avoid a
//!   malicious/broken peer forcing unbounded memory growth by claiming a
//!   huge message counter.
//! - No out-of-band header authentication beyond the AEAD's associated
//!   data over the header fields — this binds a header to its ciphertext
//!   but relies on the transport (`upm-server`, TLS at the tunnel edge)
//!   for anything beyond that.

use crate::{SessionError, WireError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use upm_crypto::{AeadKey, AgreementSecret};
use upm_protocol::{DeviceId, MessageEnvelope, MessageId, ProtocolVersion};

/// Per-message header carried alongside the ciphertext. Serialized and
/// used as AEAD associated data, so any tampering with these fields (e.g.
/// replaying an old ratchet public key) is caught by decryption failing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RatchetHeader {
    /// Sender's current DH ratchet public key.
    dh_pub: [u8; 32],
    /// Length of the sender's *previous* sending chain (lets the receiver
    /// know how many messages from the old chain might still be in flight).
    pn: u32,
    /// Message counter within the sender's current sending chain.
    n: u32,
}

#[derive(Serialize, Deserialize)]
struct WireMessage {
    header: RatchetHeader,
    ciphertext_base64: String,
}

const MAX_SKIP: u32 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedMessageKey {
    pub dh_pub: [u8; 32],
    pub message_number: u32,
    pub message_key: [u8; 32],
}

/// Explicit session snapshot used by a platform client to persist the ratchet
/// state. The snapshot contains secret material and MUST be encrypted with a
/// platform-protected local key before it is written to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub protocol_version: ProtocolVersion,
    pub peer_device: DeviceId,
    pub root_key: [u8; 32],
    pub dh_self_private: [u8; 32],
    pub dh_remote_public: Option<[u8; 32]>,
    pub sending_chain_key: Option<[u8; 32]>,
    pub receiving_chain_key: Option<[u8; 32]>,
    pub send_count: u32,
    pub recv_count: u32,
    pub prev_chain_len: u32,
    pub skipped: Vec<SkippedMessageKey>,
}

fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), SessionError> {
    let mut okm = [0u8; 64];
    upm_crypto::derive(root_key, dh_output, b"upm/v4/ratchet/root-step", &mut okm)?;
    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain_key.copy_from_slice(&okm[32..]);
    Ok((new_root, chain_key))
}

/// Advances a symmetric-key chain by one step, per the standard
/// construction: chain key is used as an HKDF salt over empty input key
/// material (the chain key is already uniformly random, so this is a
/// keyed PRF rather than a true entropy-extraction step) with two
/// distinct domain-separation labels for "next chain key" and "this
/// step's message key".
fn kdf_ck(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), SessionError> {
    let mut next_chain_key = [0u8; 32];
    upm_crypto::derive(
        chain_key,
        &[],
        b"upm/v4/ratchet/chain-key",
        &mut next_chain_key,
    )?;
    let mut message_key = [0u8; 32];
    upm_crypto::derive(
        chain_key,
        &[],
        b"upm/v4/ratchet/message-key",
        &mut message_key,
    )?;
    Ok((next_chain_key, message_key))
}

/// A Double-Ratchet-style 1:1 session, implementing the `Session` trait.
#[derive(Clone)]
pub struct DoubleRatchetSession {
    protocol_version: ProtocolVersion,
    peer_device: DeviceId,

    root_key: [u8; 32],
    dh_self: AgreementSecret,
    dh_self_public: [u8; 32],
    dh_remote_public: Option<[u8; 32]>,

    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,

    send_count: u32,     // Ns
    recv_count: u32,     // Nr
    prev_chain_len: u32, // PN
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl DoubleRatchetSession {
    /// Encrypts one application message and packages the resulting opaque
    /// ratchet ciphertext into the shared SRS MessageEnvelope type. The
    /// message ID is generated on the sender side as required by SRS §8.
    pub fn encrypt_envelope(
        &mut self,
        sender_device: DeviceId,
        server_timestamp: u64,
        expires_at: u64,
        plaintext: &[u8],
    ) -> Result<MessageEnvelope, SessionError> {
        let ciphertext = <Self as crate::Session>::encrypt(self, plaintext)?;
        Ok(MessageEnvelope {
            protocol_version: self.protocol_version,
            message_id: MessageId::random(),
            sender_device_id: sender_device,
            recipient_device_id: self.peer_device,
            ciphertext,
            server_timestamp,
            expires_at,
        })
    }

    /// Exports all session state required to resume after a process restart.
    /// Callers are responsible for encrypting the snapshot before persistence.
    pub fn snapshot(&self) -> SessionSnapshot {
        let skipped = self
            .skipped
            .iter()
            .map(|((dh_pub, message_number), message_key)| SkippedMessageKey {
                dh_pub: *dh_pub,
                message_number: *message_number,
                message_key: *message_key,
            })
            .collect();
        SessionSnapshot {
            protocol_version: self.protocol_version,
            peer_device: self.peer_device,
            root_key: self.root_key,
            dh_self_private: self.dh_self.private_key_bytes(),
            dh_remote_public: self.dh_remote_public,
            sending_chain_key: self.sending_chain_key,
            receiving_chain_key: self.receiving_chain_key,
            send_count: self.send_count,
            recv_count: self.recv_count,
            prev_chain_len: self.prev_chain_len,
            skipped,
        }
    }

    /// Restores a session from a previously encrypted snapshot.
    pub fn from_snapshot(snapshot: SessionSnapshot) -> Result<Self, SessionError> {
        if snapshot.protocol_version != ProtocolVersion::CURRENT {
            return Err(SessionError::NotEstablished);
        }
        let dh_self = AgreementSecret::from_private_key_bytes(snapshot.dh_self_private);
        let dh_self_public = dh_self.public_key();
        let skipped = snapshot
            .skipped
            .into_iter()
            .map(|entry| ((entry.dh_pub, entry.message_number), entry.message_key))
            .collect::<HashMap<_, _>>();
        if skipped.len() > MAX_SKIP as usize {
            return Err(SessionError::TooManySkipped);
        }
        Ok(Self {
            protocol_version: snapshot.protocol_version,
            peer_device: snapshot.peer_device,
            root_key: snapshot.root_key,
            dh_self,
            dh_self_public,
            dh_remote_public: snapshot.dh_remote_public,
            sending_chain_key: snapshot.sending_chain_key,
            receiving_chain_key: snapshot.receiving_chain_key,
            send_count: snapshot.send_count,
            recv_count: snapshot.recv_count,
            prev_chain_len: snapshot.prev_chain_len,
            skipped,
        })
    }

    /// Alice's initialization: she already knows Bob's initial ratchet
    /// public key (his signed prekey — see `handshake::initiate`), so she
    /// can perform the first DH ratchet step immediately and start
    /// sending right away.
    pub fn init_initiator(
        peer_device: DeviceId,
        handshake: &crate::handshake::HandshakeResult,
        bob_initial_ratchet_public: [u8; 32],
    ) -> Result<Self, SessionError> {
        let dh_self = AgreementSecret::generate();
        let dh_self_public = dh_self.public_key();
        let dh_output = dh_self.agree(&bob_initial_ratchet_public)?;
        let (root_key, sending_chain_key) = kdf_rk(&handshake.root_key, &dh_output)?;

        Ok(DoubleRatchetSession {
            protocol_version: ProtocolVersion::CURRENT,
            peer_device,
            root_key,
            dh_self,
            dh_self_public,
            dh_remote_public: Some(bob_initial_ratchet_public),
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: Some(handshake.receiving_chain_key),
            send_count: 0,
            recv_count: 0,
            prev_chain_len: 0,
            skipped: HashMap::new(),
        })
    }

    /// Bob's initialization: his own signed-prekey keypair *is* his
    /// initial ratchet keypair. He has no sending chain yet — it appears
    /// the moment he processes Alice's first message and performs his own
    /// DH ratchet step in `decrypt`.
    pub fn init_responder(
        peer_device: DeviceId,
        handshake: &crate::handshake::HandshakeResult,
        my_signed_prekey: AgreementSecret,
    ) -> Self {
        let dh_self_public = my_signed_prekey.public_key();
        DoubleRatchetSession {
            protocol_version: ProtocolVersion::CURRENT,
            peer_device,
            root_key: handshake.root_key,
            dh_self: my_signed_prekey,
            dh_self_public,
            dh_remote_public: None,
            sending_chain_key: None,
            receiving_chain_key: Some(handshake.receiving_chain_key),
            send_count: 0,
            recv_count: 0,
            prev_chain_len: 0,
            skipped: HashMap::new(),
        }
    }

    fn dh_ratchet_step(&mut self, new_remote_public: [u8; 32]) -> Result<(), SessionError> {
        self.prev_chain_len = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.dh_remote_public = Some(new_remote_public);

        let dh_out_recv = self.dh_self.agree(&new_remote_public)?;
        let (root_after_recv, receiving_chain_key) = kdf_rk(&self.root_key, &dh_out_recv)?;
        self.root_key = root_after_recv;
        self.receiving_chain_key = Some(receiving_chain_key);

        self.dh_self = AgreementSecret::generate();
        self.dh_self_public = self.dh_self.public_key();
        let dh_out_send = self.dh_self.agree(&new_remote_public)?;
        let (root_after_send, sending_chain_key) = kdf_rk(&self.root_key, &dh_out_send)?;
        self.root_key = root_after_send;
        self.sending_chain_key = Some(sending_chain_key);

        Ok(())
    }

    /// Advances the receiving chain up to (but not including) `until`,
    /// stashing each derived message key so an out-of-order message
    /// arriving later can still be decrypted. Bounded by `MAX_SKIP` so a
    /// peer can't force unbounded memory growth with a huge counter.
    fn skip_receiving_keys(&mut self, dh_pub: [u8; 32], until: u32) -> Result<(), SessionError> {
        if until.saturating_sub(self.recv_count) > MAX_SKIP {
            return Err(SessionError::TooManySkipped);
        }
        while self.recv_count < until {
            let chain_key = self
                .receiving_chain_key
                .ok_or(SessionError::NotEstablished)?;
            let (next_chain_key, message_key) = kdf_ck(&chain_key)?;
            self.receiving_chain_key = Some(next_chain_key);
            self.skipped.insert((dh_pub, self.recv_count), message_key);
            self.recv_count += 1;
        }
        Ok(())
    }
}

impl DoubleRatchetSession {
    fn decrypt_inner(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let wire: WireMessage =
            serde_json::from_slice(ciphertext).map_err(|_| WireError::Encoding)?;
        let ciphertext_bytes = base64_decode(&wire.ciphertext_base64).ok_or(WireError::Encoding)?;
        let header = &wire.header;

        // Already-skipped key from an earlier out-of-order delivery?
        if let Some(message_key) = self.skipped.get(&(header.dh_pub, header.n)).copied() {
            let aad = serde_json::to_vec(header).map_err(|_| WireError::Encoding)?;
            let key = AeadKey::from_bytes(message_key);
            let plaintext = upm_crypto::decrypt(
                &key,
                &[0u8; 12],
                &ciphertext_bytes,
                &aad,
            )?;
            self.skipped.remove(&(header.dh_pub, header.n));
            return Ok(plaintext);
        }

        if self.dh_remote_public != Some(header.dh_pub) {
            // New DH ratchet public key from the peer: first stash any
            // still-outstanding keys from the current receiving chain,
            // then perform the DH ratchet step.
            if self.receiving_chain_key.is_some() {
                self.skip_receiving_keys(
                    self.dh_remote_public.unwrap_or(header.dh_pub),
                    header.pn,
                )?;
            }
            self.dh_ratchet_step(header.dh_pub)?;
        }

        if header.n > self.recv_count {
            self.skip_receiving_keys(header.dh_pub, header.n)?;
        } else if header.n < self.recv_count {
            // Would have been served by the skipped-key map above; if it
            // wasn't there, this is a genuine replay/duplicate.
            return Err(SessionError::Replay);
        }

        let chain_key = self
            .receiving_chain_key
            .ok_or(SessionError::NotEstablished)?;
        let (next_chain_key, message_key) = kdf_ck(&chain_key)?;
        let aad = serde_json::to_vec(header).map_err(|_| WireError::Encoding)?;
        let key = AeadKey::from_bytes(message_key);
        let plaintext = upm_crypto::decrypt(
            &key,
            &[0u8; 12],
            &ciphertext_bytes,
            &aad,
        )?;
        self.receiving_chain_key = Some(next_chain_key);
        self.recv_count += 1;
        Ok(plaintext)
    }
}

impl crate::Session for DoubleRatchetSession {
    fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    fn peer_device(&self) -> DeviceId {
        self.peer_device
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let chain_key = self.sending_chain_key.ok_or(SessionError::NotEstablished)?;
        let (next_chain_key, message_key) = kdf_ck(&chain_key)?;
        self.sending_chain_key = Some(next_chain_key);

        let header = RatchetHeader {
            dh_pub: self.dh_self_public,
            pn: self.prev_chain_len,
            n: self.send_count,
        };
        self.send_count += 1;

        let aad = serde_json::to_vec(&header).map_err(|_| WireError::Encoding)?;
        let key = AeadKey::from_bytes(message_key);
        let ciphertext = upm_crypto::encrypt(&key, &[0u8; 12], plaintext, &aad)?;

        let wire = WireMessage {
            header,
            ciphertext_base64: base64_encode(&ciphertext),
        };
        serde_json::to_vec(&wire).map_err(|_| WireError::Encoding.into())
    }


    /// Decryption is transactional: malformed or unauthenticated input must
    /// not advance or otherwise corrupt the ratchet state. Candidate state is
    /// cloned and committed only after successful AEAD authentication.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let mut candidate = self.clone();
        let plaintext = candidate.decrypt_inner(ciphertext)?;
        *self = candidate;
        Ok(plaintext)
    }

}

// Small local base64 (mirrors upm-server's — kept dependency-free here too;
// see that crate's util.rs docs for why no external base64 crate is used).
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    if clean.iter().any(|&b| val(b).is_none()) {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{self, PreKeyBundle};
    use crate::Session;
    use upm_crypto::IdentityKeyPair;

    #[allow(dead_code)] // kept for symmetry/clarity even though tests don't read it directly
    struct Bundle {
        signing: IdentityKeyPair,
        exchange: AgreementSecret,
        signed_prekey: AgreementSecret,
    }

    fn bob_bundle() -> (PreKeyBundle, Bundle) {
        let signing = IdentityKeyPair::generate();
        let exchange = AgreementSecret::generate();
        let signed_prekey = AgreementSecret::generate();
        let mut signature_message = Vec::new();
        signature_message.extend_from_slice(b"UPM/v4/signed-prekey/");
        signature_message.extend_from_slice(&exchange.public_key());
        signature_message.extend_from_slice(&signed_prekey.public_key());
        let signature = signing.sign(&signature_message);
        let bundle = PreKeyBundle {
            identity_signing_public: signing.public_key(),
            identity_exchange_public: exchange.public_key(),
            signed_prekey_public: signed_prekey.public_key(),
            signed_prekey_signature: signature,
            one_time_prekey_id: None,
            one_time_prekey_public: None,
            one_time_prekey_signature: None,
        };
        (
            bundle,
            Bundle {
                signing,
                exchange,
                signed_prekey,
            },
        )
    }

    fn establish() -> (DoubleRatchetSession, DoubleRatchetSession) {
        let (bundle, bob_secrets) = bob_bundle();
        let alice_identity_exchange = AgreementSecret::generate();

        let alice_hs = handshake::initiate(&alice_identity_exchange, &bundle).unwrap();
        let bob_hs = handshake::respond(
            &bob_secrets.exchange,
            &bob_secrets.signed_prekey,
            &alice_hs.my_identity_exchange_public,
            &alice_hs.ephemeral_public,
            None,
        )
        .unwrap();

        let alice_session = DoubleRatchetSession::init_initiator(
            DeviceId([0xB; 16]),
            &alice_hs.result,
            alice_hs.bob_initial_ratchet_public,
        )
        .unwrap();
        let bob_session = DoubleRatchetSession::init_responder(
            DeviceId([0xA; 16]),
            &bob_hs,
            bob_secrets.signed_prekey,
        );
        (alice_session, bob_session)
    }

    #[test]
    fn typed_message_envelope_contains_sender_generated_id_and_peer() {
        let (mut alice, mut bob) = establish();
        let envelope = alice.encrypt_envelope(DeviceId([0xA; 16]), 100, 200, b"typed envelope").unwrap();
        assert_eq!(envelope.protocol_version, ProtocolVersion::CURRENT);
        assert_eq!(envelope.sender_device_id, DeviceId([0xA; 16]));
        assert_eq!(envelope.recipient_device_id, DeviceId([0xB; 16]));
        assert_ne!(envelope.message_id, MessageId([0u8; 16]));
        assert_eq!(bob.decrypt(&envelope.ciphertext).unwrap(), b"typed envelope");
    }

    #[test]
    fn snapshot_roundtrip_preserves_session_state() {
        let (mut alice, mut bob) = establish();
        let first = alice.encrypt(b"before snapshot").unwrap();
        assert_eq!(bob.decrypt(&first).unwrap(), b"before snapshot");

        let snapshot = bob.snapshot();
        let mut restored = DoubleRatchetSession::from_snapshot(snapshot).unwrap();

        let reply = alice.encrypt(b"after snapshot").unwrap();
        assert_eq!(restored.decrypt(&reply).unwrap(), b"after snapshot");

        let restored_snapshot = restored.snapshot();
        assert_eq!(restored_snapshot.peer_device, DeviceId([0xA; 16]));
        assert_eq!(restored_snapshot.protocol_version, ProtocolVersion::CURRENT);
    }

    #[test]
    fn x3dh_style_opk_bootstrap_roundtrips_first_message() {
        use crate::handshake::PreKeyBundle;
        use upm_crypto::IdentityKeyPair;
        use upm_protocol::PreKeyId;

        let alice_exchange = upm_crypto::AgreementSecret::generate();
        let bob_signing = IdentityKeyPair::generate();
        let bob_exchange = upm_crypto::AgreementSecret::generate();
        let bob_signed = upm_crypto::AgreementSecret::generate();
        let bob_opk_id = PreKeyId([0x42; 16]);
        let bob_opk = upm_crypto::AgreementSecret::generate();

        let mut signed_message = Vec::new();
        signed_message.extend_from_slice(b"UPM/v4/signed-prekey/");
        signed_message.extend_from_slice(&bob_exchange.public_key());
        signed_message.extend_from_slice(&bob_signed.public_key());
        let signed_sig = bob_signing.sign(&signed_message);
        let opk_sig = bob_signing.sign(&crate::handshake::one_time_prekey_signature_message(bob_opk_id, &bob_opk.public_key()));

        let bundle = PreKeyBundle {
            identity_signing_public: bob_signing.public_key(),
            identity_exchange_public: bob_exchange.public_key(),
            signed_prekey_public: bob_signed.public_key(),
            signed_prekey_signature: signed_sig,
            one_time_prekey_id: Some(bob_opk_id),
            one_time_prekey_public: Some(bob_opk.public_key()),
            one_time_prekey_signature: Some(opk_sig),
        };
        let hs = crate::handshake::initiate(&alice_exchange, &bundle).unwrap();
        let alice_device = DeviceId([1; 16]);
        let bob_device = DeviceId([2; 16]);
        let mut alice = DoubleRatchetSession::init_initiator(bob_device, &hs.result, hs.bob_initial_ratchet_public).unwrap();
        let bob_hs = crate::handshake::respond(
            &bob_exchange,
            &bob_signed,
            &hs.my_identity_exchange_public,
            &hs.ephemeral_public,
            Some(&bob_opk),
        ).unwrap();
        let mut bob = DoubleRatchetSession::init_responder(alice_device, &bob_hs, bob_signed);
        let wire = alice.encrypt(b"hello with opk").unwrap();
        assert_eq!(bob.decrypt(&wire).unwrap(), b"hello with opk");
    }

    #[test]
    fn alice_to_bob_first_message_roundtrip() {
        let (mut alice, mut bob) = establish();
        let wire = alice.encrypt(b"hello bob").unwrap();
        let plaintext = bob.decrypt(&wire).unwrap();
        assert_eq!(plaintext, b"hello bob");
    }

    #[test]
    fn bidirectional_conversation_roundtrips() {
        let (mut alice, mut bob) = establish();

        let m1 = alice.encrypt(b"hi bob").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"hi bob");

        let m2 = bob.encrypt(b"hi alice").unwrap();
        assert_eq!(alice.decrypt(&m2).unwrap(), b"hi alice");

        let m3 = alice.encrypt(b"how are you").unwrap();
        assert_eq!(bob.decrypt(&m3).unwrap(), b"how are you");

        let m4 = bob.encrypt(b"good, you?").unwrap();
        assert_eq!(alice.decrypt(&m4).unwrap(), b"good, you?");
    }

    #[test]
    fn out_of_order_delivery_within_same_chain_is_handled() {
        let (mut alice, mut bob) = establish();

        let m1 = alice.encrypt(b"first").unwrap();
        let m2 = alice.encrypt(b"second").unwrap();
        let m3 = alice.encrypt(b"third").unwrap();

        // Deliver out of order: 2, then 1, then 3.
        assert_eq!(bob.decrypt(&m2).unwrap(), b"second");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"first");
        assert_eq!(bob.decrypt(&m3).unwrap(), b"third");
    }

    #[test]
    fn replayed_message_is_rejected() {
        let (mut alice, mut bob) = establish();
        let m1 = alice.encrypt(b"only once").unwrap();
        assert!(bob.decrypt(&m1).is_ok());
        assert!(
            bob.decrypt(&m1).is_err(),
            "replaying the exact same message must fail"
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut alice, mut bob) = establish();
        let mut wire: WireMessage =
            serde_json::from_slice(&alice.encrypt(b"tamper me").unwrap()).unwrap();
        let mut ct = base64_decode(&wire.ciphertext_base64).unwrap();
        ct[0] ^= 0xFF;
        wire.ciphertext_base64 = base64_encode(&ct);
        let tampered = serde_json::to_vec(&wire).unwrap();
        assert!(bob.decrypt(&tampered).is_err());
    }

    #[test]
    fn tampered_message_does_not_advance_receiver_state() {
        let (mut alice, mut bob) = establish();
        let m1 = alice.encrypt(b"first authentic message").unwrap();

        let mut wire: WireMessage = serde_json::from_slice(&m1).unwrap();
        let mut ct = base64_decode(&wire.ciphertext_base64).unwrap();
        ct[0] ^= 0x80;
        wire.ciphertext_base64 = base64_encode(&ct);
        let tampered = serde_json::to_vec(&wire).unwrap();

        assert!(bob.decrypt(&tampered).is_err());
        // Because decrypt is transactional, the original packet must still
        // authenticate successfully after the failed tampered attempt.
        assert_eq!(bob.decrypt(&m1).unwrap(), b"first authentic message");
    }

    #[test]
    fn tampered_new_dh_header_does_not_advance_receiver_state() {
        let (mut alice, mut bob) = establish();
        let m1 = alice.encrypt(b"first").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"first");

        let m2 = alice.encrypt(b"second").unwrap();
        let mut wire: WireMessage = serde_json::from_slice(&m2).unwrap();
        wire.header.dh_pub[0] ^= 0x01;
        let tampered = serde_json::to_vec(&wire).unwrap();

        assert!(bob.decrypt(&tampered).is_err());
        assert_eq!(bob.decrypt(&m2).unwrap(), b"second");
    }

    #[test]
    fn many_dh_ratchet_steps_still_roundtrip() {
        let (mut alice, mut bob) = establish();
        for i in 0..10 {
            let msg = format!("message {i}");
            if i % 2 == 0 {
                let wire = alice.encrypt(msg.as_bytes()).unwrap();
                assert_eq!(bob.decrypt(&wire).unwrap(), msg.as_bytes());
            } else {
                let wire = bob.encrypt(msg.as_bytes()).unwrap();
                assert_eq!(alice.decrypt(&wire).unwrap(), msg.as_bytes());
            }
        }
    }
}
