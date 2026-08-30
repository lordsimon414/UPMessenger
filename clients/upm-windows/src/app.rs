use crate::api::{ApiClient, DirectoryEntry};
use crate::identity::LocalIdentity;
use crate::local_store::{LocalStore, OutboxItem};
use crate::storage::{self, LocalProfile};
use base64::Engine;
use eframe::egui;
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use upm_core::{attachments, handshake, DoubleRatchetSession, Session};
use upm_protocol::{DeviceId, MessageEnvelope, MessageId, PreKeyId, ProtocolVersion};

#[derive(Debug, thiserror::Error)]
enum ClientCryptoError {
    #[error("invalid base64 key material from server")]
    InvalidBase64,
    #[error("invalid fixed-size key material from server")]
    InvalidKeyLength,
    #[error("invalid session packet")]
    InvalidPacket,
    #[error("peer identity does not match the previously resolved contact")]
    PeerIdentityMismatch,
    #[error("bootstrap signature does not verify")]
    InvalidBootstrapSignature,
    #[error("local one-time prekey is unavailable")]
    MissingOneTimePrekey,
    #[error(transparent)]
    Handshake(#[from] upm_core::HandshakeError),
    #[error(transparent)]
    Session(#[from] upm_core::SessionError),
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionBootstrap {
    sender_identity_signing_public: [u8; 32],
    sender_identity_exchange_public: [u8; 32],
    ephemeral_public: [u8; 32],
    one_time_prekey_id: Option<PreKeyId>,
    /// Base64-encoded Ed25519 signature (64 bytes). Stored as a string
    /// rather than `[u8; 64]` because serde's built-in array support only
    /// covers fixed arrays up to 32 elements; see `decode_64`/`encode_64`.
    signature_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionPacket {
    protocol_version: u16,
    bootstrap: Option<SessionBootstrap>,
    ratchet_message_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum ChatPayload {
    Text(String),
    Attachment {
        attachment_id: MessageId,
        filename: String,
        size: u64,
        key: [u8; 32],
        capability: String,
    },
}

#[derive(Debug)]
struct ChatLine {
    direction: Direction,
    text: String,
    at: i64,
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Incoming,
    Outgoing,
}

fn load_or_generate_identity() -> LocalIdentity {
    if let Some(secrets) = storage::load_secrets() {
        let decode = |value: &str| -> Option<[u8; 32]> {
            let bytes = base64::engine::general_purpose::STANDARD.decode(value).ok()?;
            bytes.try_into().ok()
        };
        let opks = secrets.one_time_prekeys.iter().filter_map(|item| {
            let key = decode(&item.private_b64)?;
            Some((item.id, key))
        }).collect::<Vec<_>>();
        if let (Some(a), Some(b), Some(c)) = (
            decode(&secrets.signing_private_b64),
            decode(&secrets.exchange_private_b64),
            decode(&secrets.signed_prekey_private_b64),
        ) {
            let mut identity = LocalIdentity::from_private_key_bytes(a, b, c, opks);
            identity.ensure_one_time_prekey_pool(12);
            persist_identity_secrets(&identity);
            return identity;
        }
    }

    let identity = LocalIdentity::generate();
    persist_identity_secrets(&identity);
    identity
}

fn persist_identity_secrets(identity: &LocalIdentity) {
    let (a, b, c) = identity.private_key_bytes();
    let secrets = storage::local_secrets_from_bytes(a, b, c, identity.one_time_prekey_private_keys());
    let _ = storage::save_secrets(&secrets);
}

fn decode_32(value: &str) -> Result<[u8; 32], ClientCryptoError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| ClientCryptoError::InvalidBase64)?;
    bytes.try_into().map_err(|_| ClientCryptoError::InvalidKeyLength)
}

fn decode_64(value: &str) -> Result<[u8; 64], ClientCryptoError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| ClientCryptoError::InvalidBase64)?;
    bytes.try_into().map_err(|_| ClientCryptoError::InvalidKeyLength)
}

fn decode_device_id(value: &str) -> Result<DeviceId, ClientCryptoError> {
    DeviceId::from_hex(value).ok_or(ClientCryptoError::InvalidKeyLength)
}

fn bootstrap_signature_message(
    recipient_device: DeviceId,
    sender_identity_exchange_public: &[u8; 32],
    ephemeral_public: &[u8; 32],
    one_time_prekey_id: Option<PreKeyId>,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(21 + 16 + 32 + 32 + 1 + 16);
    message.extend_from_slice(b"UPM/v4/bootstrap/");
    message.extend_from_slice(&recipient_device.0);
    message.extend_from_slice(sender_identity_exchange_public);
    message.extend_from_slice(ephemeral_public);
    match one_time_prekey_id {
        Some(id) => {
            message.push(1);
            message.extend_from_slice(&id.0);
        }
        None => message.push(0),
    }
    message
}

fn verify_bootstrap(
    bootstrap: &SessionBootstrap,
    recipient_device: DeviceId,
) -> Result<(), ClientCryptoError> {
    let message = bootstrap_signature_message(
        recipient_device,
        &bootstrap.sender_identity_exchange_public,
        &bootstrap.ephemeral_public,
        bootstrap.one_time_prekey_id,
    );
    upm_crypto::verify(
        &bootstrap.sender_identity_signing_public,
        &message,
        &decode_64(&bootstrap.signature_base64)?,
    )
    .map_err(|_| ClientCryptoError::InvalidBootstrapSignature)
}

fn encode_packet(packet: &SessionPacket) -> Result<Vec<u8>, ClientCryptoError> {
    serde_json::to_vec(packet).map_err(|_| ClientCryptoError::InvalidPacket)
}

fn decode_packet(bytes: &[u8]) -> Result<SessionPacket, ClientCryptoError> {
    serde_json::from_slice(bytes).map_err(|_| ClientCryptoError::InvalidPacket)
}

struct Conversation {
    peer: DirectoryEntry,
    session: Option<DoubleRatchetSession>,
    lines: Vec<ChatLine>,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Formats a Unix timestamp as `HH:MM` UTC. Deliberately dependency-free
/// (no `chrono`/`time` crate, matching the rest of this codebase's
/// minimal-dependency style) — this is UTC, not the viewer's local time
/// zone; swap in a proper time crate if local-time display matters later.
fn format_time_hhmm(unix_secs: i64) -> String {
    let secs_of_day = unix_secs.rem_euclid(86_400);
    format!("{:02}:{:02}", secs_of_day / 3600, (secs_of_day / 60) % 60)
}

fn fingerprint_hex(identity_public_key: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(identity_public_key);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes().chunks(8).map(|c| String::from_utf8_lossy(c).to_string()).collect::<Vec<_>>().join(" ")
}

/// A "safety number"-style combined fingerprint over two identity keys.
/// Symmetric by construction (the smaller key always goes first), so both
/// conversation partners compute the exact same string regardless of who
/// is "self" and who is "peer" — meant to be read aloud or compared over
/// an independent channel (in person, a phone call, a separate app) to
/// catch a first-contact impersonation that TOFU pinning alone cannot
/// detect (SECURITY_REVIEW.md finding #1: TOFU only protects against a
/// key *changing after* first contact, not a malicious/compromised
/// directory server lying about a key on the very first lookup).
fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes().chunks(8).map(|c| String::from_utf8_lossy(c).to_string()).collect::<Vec<_>>().join(" ")
}

pub struct UpmApp {
    profile: LocalProfile,
    identity: LocalIdentity,
    api: Option<ApiClient>,
    status: String,
    new_contact: String,
    message_input: String,
    directory: Option<DirectoryEntry>,
    conversation: Option<Conversation>,
    local_store: Option<LocalStore>,
    last_poll: f64,
    directory_visible: bool,
}

impl UpmApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut profile = storage::load();
        if profile.server_url.is_empty() {
            profile.server_url = "http://127.0.0.1:8787".into();
        }
        let api = ApiClient::new(&profile.server_url).ok();
        let identity = load_or_generate_identity();
        let local_store = LocalStore::open().ok();
        let mut app = Self {
            profile,
            identity,
            api,
            status: "Ready".into(),
            new_contact: String::new(),
            message_input: String::new(),
            directory: None,
            conversation: None,
            local_store,
            last_poll: 0.0,
            directory_visible: true,
        };
        // Auto-login: a returning user already has a device_id from a
        // previous run, so log them straight back in instead of leaving
        // them stuck behind a manual "Log in" click every launch. A
        // network hiccup or an expired/unregistered device here is not
        // fatal — authenticate() reports it in self.status and the user
        // can still hit "Log in" manually.
        if app.profile.device_id.is_some() {
            app.status = "Logging in…".into();
            app.authenticate();
        }
        app
    }

    fn save(&mut self) {
        match storage::save(&self.profile) {
            Ok(_) => self.status = "Saved".into(),
            Err(e) => self.status = format!("Storage error: {e}"),
        }
        persist_identity_secrets(&self.identity);
    }

    fn reconnect(&mut self) {
        self.api = ApiClient::new(&self.profile.server_url).ok();
        self.status = format!("Server set to {}", self.profile.server_url);
    }

    fn register(&mut self) {
        let Some(api) = self.api.clone() else {
            self.status = "Invalid server URL".into();
            return;
        };
        match api.register(&self.profile.username, &self.identity.identity_public_b64()) {
            Ok(r) => {
                self.profile.user_id = Some(r.user_id);
                self.profile.upm_id = Some(r.upm_id.clone());
                self.profile.device_id = Some(r.device_id);
                self.save();
                self.status = format!("Registered as {}", r.upm_id);
                self.authenticate();
            }
            Err(e) => self.status = format!("Registration failed: {e}"),
        }
    }

    fn publish_prekeys(&mut self, api: &ApiClient, token: &str) -> Result<(), String> {
        let batch = self.identity.publishable_one_time_prekeys()
            .into_iter()
            .map(|(id, public, signature)| (id.to_hex(), public, signature))
            .collect::<Vec<_>>();
        if batch.is_empty() { return Ok(()); }
        api.publish_one_time_prekeys(token, &batch)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn authenticate(&mut self) {
        let Some(device_id) = self.profile.device_id.clone() else {
            self.status = "Register first".into();
            return;
        };
        let Some(api) = self.api.clone() else { return };
        let challenge = match api.challenge(&device_id) {
            Ok((c, _)) => c,
            Err(e) => { self.status = format!("Challenge failed: {e}"); return; }
        };
        let signature = self.identity.signing.sign(&challenge);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
        match api.verify(&device_id, &signature_b64) {
            Ok(v) => {
                self.profile.session_token = Some(v.session_token);
                self.profile.session_expires_at = Some(v.expires_at);
                self.save();
                let token = self.profile.session_token.clone().unwrap_or_default();
                if let Err(e) = api.publish_keys(&token, &self.identity.exchange_public_b64(), &self.identity.signed_prekey_public_b64(), &self.identity.signed_prekey_signature_b64()) {
                    self.status = format!("Authenticated, key publish failed: {e}");
                    return;
                }
                self.identity.ensure_one_time_prekey_pool(12);
                persist_identity_secrets(&self.identity);
                match self.publish_prekeys(&api, &token) {
                    Ok(()) => self.status = format!("Authenticated + X3DH bundle published ({} OPKs)", self.identity.one_time_prekeys.len()),
                    Err(e) => self.status = format!("Authenticated + signed prekey published; OPK publish failed: {e}"),
                }
            }
            Err(e) => self.status = format!("Authentication failed: {e}"),
        }
    }

    fn update_directory_visibility(&mut self) {
        let Some(token) = self.profile.session_token.clone() else { return; };
        let Some(api) = self.api.clone() else { return; };
        match api.set_directory_visibility(&token, self.directory_visible) {
            Ok(()) => self.status = if self.directory_visible { "Directory visibility enabled" } else { "Directory visibility disabled" }.into(),
            Err(e) => self.status = format!("Privacy setting failed: {e}"),
        }
    }

    fn logout(&mut self) {
        let token = self.profile.session_token.clone();
        // Best-effort server-side logout only when we actually have a
        // connection; the local logout below must happen regardless, or
        // "Log out" would silently do nothing while offline.
        if let (Some(token), Some(api)) = (&token, self.api.clone()) {
            match api.logout(token) {
                Ok(()) => self.status = "Logged out".into(),
                Err(e) => self.status = format!("Logged out locally (server logout failed: {e})"),
            }
        } else {
            self.status = "Logged out".into();
        }
        self.profile.session_token = None;
        self.profile.session_expires_at = None;
        let _ = storage::save(&self.profile);
        // Clean slate: an old conversation/session/lookup belonging to the
        // just-ended login shouldn't linger and look usable in the UI.
        self.conversation = None;
        self.directory = None;
        self.new_contact.clear();
        self.message_input.clear();
    }

    fn resolve(&mut self) {
        let Some(api) = self.api.clone() else { return };
        let query = self.new_contact.trim();
        let result = if query.starts_with('@') { api.resolve_username(query.trim_start_matches('@')) } else if upm_protocol::PreKeyId::from_hex(query).is_some() || query.len() >= 8 { api.resolve_upm_id(query) } else { api.resolve_username(query) };
        match result {
            Ok(entry) => {
                if let Some(store) = &self.local_store {
                    match store.pin_or_verify_peer(&entry.device_id, &entry.identity_public_key) {
                        Ok(true) => {}
                        Ok(false) => { self.status = "SECURITY: peer identity key changed; refusing contact".into(); return; }
                        Err(e) => { self.status = format!("Local trust store error: {e}"); return; }
                    }
                }
                self.status = format!("Found @{} ({})", entry.username, entry.upm_id);
                self.directory = Some(entry.clone());
                self.conversation = None;
                let _ = self.ensure_conversation();
            }
            Err(e) => self.status = format!("Directory lookup failed: {e}"),
        }
    }

    fn ensure_conversation(&mut self) -> Result<(), String> {
        let Some(peer) = self.directory.clone() else { return Err("Resolve a contact first".into()); };
        if let Some(conversation) = &self.conversation {
            if conversation.peer.device_id == peer.device_id { return Ok(()); }
        }
        let mut conversation = Conversation { peer, session: None, lines: Vec::new() };
        if let Some(store) = &self.local_store {
            conversation.session = store.load_session(&conversation.peer.device_id).map_err(|e| e.to_string())?;
            conversation.lines = store.load_messages(&conversation.peer.device_id).map_err(|e| e.to_string())?.into_iter().map(|(incoming, text, at)| ChatLine {
                direction: if incoming { Direction::Incoming } else { Direction::Outgoing }, text, at,
            }).collect();
        }
        self.conversation = Some(conversation);
        Ok(())
    }

    fn make_initial_outgoing_packet(&mut self, plaintext: &[u8]) -> Result<(MessageEnvelope, DoubleRatchetSession), String> {
        self.ensure_conversation()?;
        let api = self.api.clone().ok_or_else(|| "Invalid server URL".to_string())?;
        let my_device = decode_device_id(self.profile.device_id.as_deref().ok_or_else(|| "Register and authenticate first".to_string())?).map_err(|e| e.to_string())?;
        let peer = self.conversation.as_ref().unwrap().peer.clone();
        let peer_device = decode_device_id(&peer.device_id).map_err(|e| e.to_string())?;
        let bundle_response = api.device_keys(&peer.device_id).map_err(|e| format!("key lookup failed: {e}"))?;
        let expected_identity = decode_32(&bundle_response.identity_public_key).map_err(|e| e.to_string())?;
        if expected_identity != decode_32(&peer.identity_public_key).map_err(|e| e.to_string())? { return Err("peer directory identity mismatch".into()); }
        let exchange = decode_32(&bundle_response.identity_exchange_public).map_err(|e| e.to_string())?;
        let signed_prekey = decode_32(&bundle_response.signed_prekey_public).map_err(|e| e.to_string())?;
        let signed_sig = decode_64(&bundle_response.signed_prekey_signature).map_err(|e| e.to_string())?;
        let claimed = api.claim_one_time_prekey(self.profile.session_token.as_deref().ok_or_else(|| "Authenticate first".to_string())?, &peer.device_id)
            .map_err(|e| format!("OPK claim failed: {e}"))?;
        let (opk_id, opk_public, opk_signature) = match claimed {
            Some((id, public, sig)) => {
                let id = PreKeyId::from_hex(&id).ok_or_else(|| "invalid OPK id".to_string())?;
                (Some(id), Some(decode_32(&public).map_err(|e| e.to_string())?), Some(decode_64(&sig).map_err(|e| e.to_string())?))
            }
            None => (None, None, None),
        };
        let bundle = handshake::PreKeyBundle {
            identity_signing_public: expected_identity,
            identity_exchange_public: exchange,
            signed_prekey_public: signed_prekey,
            signed_prekey_signature: signed_sig,
            one_time_prekey_id: opk_id,
            one_time_prekey_public: opk_public,
            one_time_prekey_signature: opk_signature,
        };
        let hs = handshake::initiate(&self.identity.exchange, &bundle).map_err(|e| e.to_string())?;
        if hs.one_time_prekey_id.is_none() {
            // SECURITY_REVIEW.md finding #2: the server can legitimately
            // report "no one-time prekey available", but a compromised
            // server could also lie about that to force every handshake
            // onto the weaker 3-DH path — nothing can cryptographically
            // tell the two cases apart. The best available mitigation is
            // making the degradation *visible* instead of silent, so the
            // user (or a future automated check) can at least notice a
            // pattern of "this contact never seems to have a prekey".
            self.status = format!(
                "Starting a session with @{} without a one-time prekey (server reported none available) — this weakens protection of this specific handshake only if a signed prekey is later compromised; the ongoing conversation's forward secrecy is unaffected.",
                peer.username
            );
        }
        let mut session = DoubleRatchetSession::init_initiator(peer_device, &hs.result, hs.bob_initial_ratchet_public).map_err(|e| e.to_string())?;
        let mut bootstrap = SessionBootstrap {
            sender_identity_signing_public: self.identity.signing.public_key(),
            sender_identity_exchange_public: hs.my_identity_exchange_public,
            ephemeral_public: hs.ephemeral_public,
            one_time_prekey_id: hs.one_time_prekey_id,
            signature_base64: String::new(),
        };
        let message = bootstrap_signature_message(peer_device, &bootstrap.sender_identity_exchange_public, &bootstrap.ephemeral_public, bootstrap.one_time_prekey_id);
        bootstrap.signature_base64 = base64::engine::general_purpose::STANDARD.encode(self.identity.signing.sign(&message));
        let ratchet = session.encrypt(plaintext).map_err(|e| e.to_string())?;
        let packet = SessionPacket { protocol_version: ProtocolVersion::CURRENT.0, bootstrap: Some(bootstrap), ratchet_message_base64: base64::engine::general_purpose::STANDARD.encode(ratchet) };
        let envelope = MessageEnvelope { protocol_version: ProtocolVersion::CURRENT, message_id: MessageId::random(), sender_device_id: my_device, recipient_device_id: peer_device, ciphertext: encode_packet(&packet).map_err(|e| e.to_string())?, server_timestamp: 0, expires_at: 0 };
        Ok((envelope, session))
    }

    fn make_outgoing_packet(&mut self, payload: &[u8]) -> Result<(MessageEnvelope, DoubleRatchetSession), String> {
        self.ensure_conversation()?;
        let existing = self.conversation.as_ref().and_then(|c| c.session.as_ref()).cloned();
        let Some(mut session) = existing else { return self.make_initial_outgoing_packet(payload); };
        let my_device = decode_device_id(self.profile.device_id.as_deref().ok_or_else(|| "Register and authenticate first".to_string())?).map_err(|e| e.to_string())?;
        let peer_device = decode_device_id(&self.conversation.as_ref().unwrap().peer.device_id).map_err(|e| e.to_string())?;
        let ratchet_message = session.encrypt(payload).map_err(|e| format!("encryption failed: {e}"))?;
        let packet = SessionPacket { protocol_version: ProtocolVersion::CURRENT.0, bootstrap: None, ratchet_message_base64: base64::engine::general_purpose::STANDARD.encode(ratchet_message) };
        let envelope = MessageEnvelope { protocol_version: ProtocolVersion::CURRENT, message_id: MessageId::random(), sender_device_id: my_device, recipient_device_id: peer_device, ciphertext: encode_packet(&packet).map_err(|e| e.to_string())?, server_timestamp: 0, expires_at: 0 };
        Ok((envelope, session))
    }

    fn send_payload(&mut self, payload: ChatPayload, display_text: String) {
        let payload_bytes = match serde_json::to_vec(&payload) { Ok(v) => v, Err(e) => { self.status = format!("Payload encode failed: {e}"); return; } };
        let Some(api) = self.api.clone() else { self.status = "Invalid server URL".into(); return; };
        let Some(token) = self.profile.session_token.clone() else { self.status = "Authenticate first".into(); return; };
        let (envelope, candidate_session) = match self.make_outgoing_packet(&payload_bytes) { Ok(v) => v, Err(e) => { self.status = e; return; } };
        let outbox = OutboxItem { message_id: envelope.message_id, peer_device_id: envelope.recipient_device_id.to_hex(), envelope: envelope.clone(), session_after: candidate_session.snapshot(), text: display_text.clone() };
        if let Some(store) = &self.local_store { if let Err(e) = store.save_outbox(&outbox) { self.status = format!("Local outbox save failed: {e}"); return; } }
        match api.send_envelope(&token, &envelope) {
            Ok(()) => {
                if let Some(store) = &self.local_store { let _ = store.commit_outgoing_delivery(&outbox, &candidate_session, unix_now()); }
                if let Some(conversation) = &mut self.conversation { conversation.session = Some(candidate_session); conversation.lines.push(ChatLine { direction: Direction::Outgoing, text: display_text, at: unix_now() }); }
                self.status = "Encrypted message queued".into();
            }
            Err(e) => self.status = format!("Send failed (outbox retained): {e}"),
        }
    }

    fn send_message(&mut self) {
        let text = self.message_input.trim().to_string();
        if text.is_empty() { return; }
        self.send_payload(ChatPayload::Text(text.clone()), text);
        self.message_input.clear();
    }

    fn send_attachment(&mut self) {
        let Some(path) = FileDialog::new().set_title("Select attachment").pick_file() else { return; };
        match self.prepare_attachment(path) {
            Ok(()) => {}
            Err(e) => self.status = e,
        }
    }

    fn prepare_attachment(&mut self, path: PathBuf) -> Result<(), String> {
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let size = meta.len();
        if size == 0 || size > 100 * 1024 * 1024 { return Err("Attachment must be between 1 byte and 100 MB".into()); }
        let plaintext = std::fs::read(&path).map_err(|e| e.to_string())?;
        let key = attachments::AttachmentKey::generate();
        let ciphertext_size = size.checked_add(attachments::NONCE_LEN as u64 + 16).ok_or_else(|| "attachment size overflow".to_string())?;
        let api = self.api.clone().ok_or_else(|| "Invalid server URL".to_string())?;
        let token = self.profile.session_token.clone().ok_or_else(|| "Authenticate first".to_string())?;
        let (attachment_id, capability) = api.create_attachment(&token, ciphertext_size as i64).map_err(|e| format!("attachment slot failed: {e}"))?;
        let id = MessageId::from_hex(&attachment_id).ok_or_else(|| "server returned invalid attachment id".to_string())?;
        let blob = attachments::encrypt(key, id, &plaintext).map_err(|e| e.to_string())?;
        if blob.len() as u64 != ciphertext_size { return Err("attachment ciphertext size mismatch".into()); }
        api.upload_attachment_blob(&token, &attachment_id, &blob).map_err(|e| format!("attachment upload failed: {e}"))?;
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("attachment").to_string();
        let payload = ChatPayload::Attachment { attachment_id: id, filename: filename.clone(), size, key: key.0, capability };
        self.send_payload(payload, format!("📎 {filename} ({size} bytes)"));
        Ok(())
    }

    fn establish_responder_session(&mut self, sender_device: DeviceId, bootstrap: &SessionBootstrap) -> Result<(DoubleRatchetSession, Option<PreKeyId>), ClientCryptoError> {
        let directory = self.directory.as_ref().ok_or(ClientCryptoError::PeerIdentityMismatch)?;
        if directory.device_id != sender_device.to_hex() { return Err(ClientCryptoError::PeerIdentityMismatch); }
        let expected_identity = decode_32(&directory.identity_public_key).map_err(|_| ClientCryptoError::PeerIdentityMismatch)?;
        if expected_identity != bootstrap.sender_identity_signing_public { return Err(ClientCryptoError::PeerIdentityMismatch); }
        let my_device = decode_device_id(self.profile.device_id.as_deref().ok_or(ClientCryptoError::PeerIdentityMismatch)?)?;
        verify_bootstrap(bootstrap, my_device)?;
        let opk = bootstrap.one_time_prekey_id.and_then(|id| self.identity.find_one_time_prekey(id));
        if bootstrap.one_time_prekey_id.is_some() && opk.is_none() { return Err(ClientCryptoError::MissingOneTimePrekey); }
        let sender_exchange = bootstrap.sender_identity_exchange_public;
        let hs = handshake::respond(&self.identity.exchange, &self.identity.signed_prekey, &sender_exchange, &bootstrap.ephemeral_public, opk)?;
        let session = DoubleRatchetSession::init_responder(sender_device, &hs, self.identity.signed_prekey.clone());
        if bootstrap.one_time_prekey_id.is_none() {
            // Symmetric to the initiator-side note in make_initial_outgoing_packet:
            // this incoming handshake didn't claim a one-time prekey. Make that
            // visible rather than silent — see SECURITY_REVIEW.md finding #2.
            self.status = "Incoming session started without a one-time prekey — this weakens protection of this specific handshake only if a signed prekey is later compromised; the ongoing conversation's forward secrecy is unaffected.".into();
        }
        Ok((session, bootstrap.one_time_prekey_id))
    }

    fn retry_outbox(&mut self, api: &ApiClient, token: &str) {
        let Some(store) = &self.local_store else { return; };
        let items = match store.load_outbox() {
            Ok(v) => v,
            Err(_) => return,
        };
        for item in items {
            if api.send_envelope(token, &item.envelope).is_ok() {
                if let Ok(session) = DoubleRatchetSession::from_snapshot(item.session_after.clone()) {
                    let _ = store.commit_outgoing_delivery(&item, &session, unix_now());
                }
            }
        }
    }

    fn poll(&mut self) {
        let (Some(api), Some(token), Some(device_id)) = (self.api.clone(), self.profile.session_token.clone(), self.profile.device_id.clone()) else { return; };
        self.retry_outbox(&api, &token);
        let items = match api.pull(&token, &device_id) { Ok(v) => v, Err(e) => { self.status = format!("Pull failed: {e}"); return; } };
        if items.is_empty() { return; }
        let mut ack_ids = Vec::new();
        let mut count = 0usize;
        for item in items {
            let msg_id = match MessageId::from_hex(&item.message_id) { Some(v) => v, None => continue };
            let sender_device = match decode_device_id(&item.sender_device_id) { Ok(v) => v, Err(_) => continue };
            if let Some(store) = &self.local_store {
                if store.is_message_processed(msg_id, &item.sender_device_id).unwrap_or(false) { ack_ids.push(item.message_id.clone()); continue; }
            }
            let raw = match base64::engine::general_purpose::STANDARD.decode(&item.ciphertext_base64) { Ok(v) => v, Err(_) => continue };
            let packet = match decode_packet(&raw) { Ok(v) => v, Err(_) => continue };
            if packet.protocol_version != ProtocolVersion::CURRENT.0 { continue; }
            let ratchet_wire = match base64::engine::general_purpose::STANDARD.decode(&packet.ratchet_message_base64) { Ok(v) => v, Err(_) => continue };
            let peer_known = self.conversation.as_ref().map(|c| c.peer.device_id == sender_device.to_hex()).unwrap_or(false);
            if !peer_known {
                let Some(bootstrap) = packet.bootstrap.as_ref() else { continue; };
                if let Some(store) = &self.local_store { if !store.pin_or_verify_peer(&sender_device.to_hex(), &base64::engine::general_purpose::STANDARD.encode(bootstrap.sender_identity_signing_public)).unwrap_or(false) { self.status = "SECURITY: incoming identity key mismatch".into(); continue; } }
                let entry = match &self.directory { Some(e) if e.device_id == sender_device.to_hex() => e.clone(), _ => DirectoryEntry { upm_id: String::new(), username: String::new(), device_id: sender_device.to_hex(), identity_public_key: base64::engine::general_purpose::STANDARD.encode(bootstrap.sender_identity_signing_public) } };
                self.directory = Some(entry.clone());
                match self.establish_responder_session(sender_device, bootstrap) {
                    Ok((session, _claimed_opk)) => {
                        self.conversation = Some(Conversation { peer: entry, session: Some(session), lines: Vec::new() });
                    }
                    Err(e) => { self.status = format!("Peer authentication failed: {e}"); continue; }
                }
            }
            let Some(conversation) = self.conversation.as_mut() else { continue; };
            if conversation.peer.device_id != sender_device.to_hex() { continue; }
            let Some(session) = conversation.session.as_mut() else { continue; };
            let plaintext = match session.decrypt(&ratchet_wire) { Ok(v) => v, Err(e) => { self.status = format!("Message authentication failed: {e}"); continue; } };
            let payload = match serde_json::from_slice::<ChatPayload>(&plaintext) { Ok(v) => v, Err(_) => { self.status = "Decrypted payload has unsupported format".into(); continue; } };
            let display = match payload {
                ChatPayload::Text(text) => text,
                ChatPayload::Attachment { attachment_id, filename, size, key, capability } => {
                    let path = PathBuf::from(&filename);
                    match api.download_attachment_blob(&token, &attachment_id.to_hex(), &capability) {
                        Ok(blob) => match attachments::decrypt(attachments::AttachmentKey(key), attachment_id, &blob) {
                            Ok(data) => {
                                let safe_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("attachment.bin");
                                let target = downloads_dir().join(safe_name);
                                match std::fs::create_dir_all(downloads_dir()).and_then(|_| std::fs::write(&target, data)) {
                                    Ok(()) => format!("📎 {filename} ({size} bytes) saved to {}", target.display()),
                                    Err(_) => format!("📎 {filename} ({size} bytes) — download failed"),
                                }
                            }
                            Err(_) => format!("📎 {filename} — attachment authentication failed"),
                        },
                        Err(_) => format!("📎 {filename} — attachment unavailable"),
                    }
                }
            };
            if let Some(store) = &self.local_store {
                if let Err(e) = store.commit_incoming_message(&conversation.peer.device_id, msg_id, &display, session, unix_now()) { self.status = format!("Local commit failed: {e}"); continue; }
            }
            if let Some(bootstrap) = packet.bootstrap.as_ref() {
                if let Some(opk_id) = bootstrap.one_time_prekey_id {
                    self.identity.remove_one_time_prekey(opk_id);
                    self.identity.ensure_one_time_prekey_pool(12);
                    persist_identity_secrets(&self.identity);
                }
            }
            conversation.lines.push(ChatLine { direction: Direction::Incoming, text: display, at: unix_now() });
            ack_ids.push(item.message_id);
            count += 1;
        }
        if !ack_ids.is_empty() {
            match api.ack(&token, &ack_ids) { Ok(_) => self.status = format!("Processed and acknowledged {count} message(s)"), Err(e) => self.status = format!("Processed {count}; ACK failed: {e}") }
        }
        if self.identity.one_time_prekeys.len() < 4 {
            self.identity.ensure_one_time_prekey_pool(12);
            persist_identity_secrets(&self.identity);
            let _ = self.publish_prekeys(&api, &token);
        }
    }
}

fn downloads_dir() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") { PathBuf::from(profile).join("Downloads").join("UPM") } else { PathBuf::from("upm-downloads") }
}

impl eframe::App for UpmApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let elapsed = ctx.input(|i| i.time);
        if elapsed - self.last_poll > 2.0 {
            self.last_poll = elapsed;
            self.poll();
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }

        let connected = self.api.is_some();
        let authenticated = self.profile.session_token.is_some();
        let (status_color, status_word) = if authenticated {
            (egui::Color32::from_rgb(0x2e, 0xa0, 0x4f), "Authenticated")
        } else if connected {
            (egui::Color32::from_rgb(0xd0, 0x9a, 0x1e), "Connected")
        } else {
            (egui::Color32::from_rgb(0xb0, 0x3a, 0x3a), "Offline")
        };

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("UPM").strong());
                ui.separator();
                ui.colored_label(status_color, "●");
                ui.label(status_word);
                ui.separator();
                ui.label(egui::RichText::new(&self.status).weak());
            });
            ui.add_space(4.0);
        });

        egui::SidePanel::left("sidebar").resizable(true).default_width(280.0).show(ctx, |ui| {
            ui.add_space(6.0);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(egui::RichText::new("Server").strong());
                ui.add_space(4.0);
                ui.text_edit_singleline(&mut self.profile.server_url);
                ui.add_space(4.0);
                if ui.button("Connect").clicked() { self.reconnect(); }
            });

            ui.add_space(8.0);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(egui::RichText::new("Identity").strong());
                ui.add_space(4.0);
                ui.add_enabled_ui(!authenticated, |ui| {
                    ui.text_edit_singleline(&mut self.profile.username);
                });
                ui.add_space(4.0);
                let has_account = self.profile.device_id.is_some();
                ui.horizontal_wrapped(|ui| {
                    if authenticated {
                        if ui.button("Log out").clicked() { self.logout(); }
                    } else if has_account {
                        if ui.button("Log in").clicked() { self.authenticate(); }
                        if ui.small_button("Register new account").clicked() { self.register(); }
                    } else {
                        if ui.button("Register").clicked() { self.register(); }
                    }
                });
                ui.add_space(6.0);
                if let Some(id) = &self.profile.upm_id { ui.label(format!("UPM ID: {id}")); }
                if let Some(d) = &self.profile.device_id { ui.small(egui::RichText::new(format!("Device: {d}")).monospace().weak()); }
                if authenticated {
                    ui.small(format!("Protocol: v{}", ProtocolVersion::CURRENT.0));
                    if let Some(expires) = self.profile.session_expires_at { ui.small(format!("Session expires: {expires}")); }
                }
                ui.add_space(6.0);
                let identity_pub = self.identity.signing.public_key();
                egui::Frame::none()
                    .fill(ui.visuals().extreme_bg_color)
                    .rounding(4.0)
                    .inner_margin(6.0)
                    .show(ui, |ui| {
                        ui.small(egui::RichText::new(fingerprint_hex(&identity_pub)).monospace());
                    });
                if authenticated {
                    ui.add_space(4.0);
                    let response = ui.checkbox(&mut self.directory_visible, "Discoverable in directory");
                    if response.changed() { self.update_directory_visibility(); }
                }
            });

            ui.add_space(8.0);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(egui::RichText::new("Contact").strong());
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.new_contact);
                    if ui.button("Resolve").clicked() { self.resolve(); }
                });
                if let Some(entry) = &self.directory {
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(ui.visuals().faint_bg_color)
                        .rounding(4.0)
                        .inner_margin(6.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(format!("@{}", entry.username)).strong());
                            ui.small(&entry.upm_id);
                            ui.small(egui::RichText::new(format!("Device: {}", entry.device_id)).weak());
                        });
                    // Safety number: read this aloud with your contact over
                    // an independent channel (in person, a phone call) to
                    // confirm you're both pinned to the same identity key.
                    // TOFU alone only catches a key *changing later* — it
                    // can't catch a compromised directory server lying on
                    // the very first lookup (SECURITY_REVIEW.md finding #1).
                    if let Ok(their_key) = decode_32(&entry.identity_public_key) {
                        let my_key = self.identity.signing.public_key();
                        ui.add_space(6.0);
                        ui.small(egui::RichText::new("Safety number (compare with your contact):").weak());
                        egui::Frame::none()
                            .fill(ui.visuals().extreme_bg_color)
                            .rounding(4.0)
                            .inner_margin(6.0)
                            .show(ui, |ui| {
                                ui.small(egui::RichText::new(safety_number(&my_key, &their_key)).monospace());
                            });
                    }
                }
            });

            ui.add_space(8.0);
            if ui.button("⟳  Pull now").clicked() { self.poll(); }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if !authenticated {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() / 2.0 - 40.0);
                    ui.heading(egui::RichText::new("You're logged out").weak());
                    ui.label("Log in on the left to see your conversations and send messages.");
                });
                return;
            }
            let peer_heading = self.conversation.as_ref().map(|c| {
                if c.peer.username.is_empty() { c.peer.device_id.clone() } else { format!("@{}", c.peer.username) }
            });
            ui.add_space(4.0);
            match &peer_heading {
                Some(name) => { ui.heading(name); }
                None => { ui.heading(egui::RichText::new("No conversation yet").weak()); }
            }
            ui.separator();

            let available_height = ui.available_height() - 56.0;
            egui::ScrollArea::vertical().stick_to_bottom(true).max_height(available_height.max(80.0)).show(ui, |ui| {
                ui.add_space(4.0);
                if let Some(conversation) = &self.conversation {
                    if conversation.lines.is_empty() {
                        ui.label(egui::RichText::new("No messages yet — say hello.").weak());
                    }
                    for line in &conversation.lines {
                        let outgoing = matches!(line.direction, Direction::Outgoing);
                        let bubble_fill = if outgoing { ui.visuals().selection.bg_fill } else { ui.visuals().faint_bg_color };
                        let text_color = if outgoing { egui::Color32::WHITE } else { ui.visuals().text_color() };
                        let layout = if outgoing { egui::Layout::right_to_left(egui::Align::Min) } else { egui::Layout::left_to_right(egui::Align::Min) };
                        ui.with_layout(layout, |ui| {
                            ui.set_max_width(ui.available_width() * 0.75);
                            egui::Frame::none()
                                .fill(bubble_fill)
                                .rounding(8.0)
                                .inner_margin(9.0)
                                .show(ui, |ui| {
                                    ui.vertical(|ui| {
                                        ui.label(egui::RichText::new(&line.text).color(text_color));
                                        ui.small(egui::RichText::new(format_time_hhmm(line.at)).color(text_color.gamma_multiply(0.75)));
                                    });
                                });
                        });
                        ui.add_space(4.0);
                    }
                } else {
                    ui.label(egui::RichText::new("Resolve a contact on the left to start a conversation.").weak());
                }
            });

            ui.separator();
            ui.horizontal(|ui| {
                let text_edit = ui.add_sized([ui.available_width() - 170.0, 0.0], egui::TextEdit::singleline(&mut self.message_input).hint_text("Type a message…"));
                let send = text_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Send").clicked() || send { self.send_message(); }
                if ui.button("📎 Attach").clicked() { self.send_attachment(); }
            });
            ui.add_space(2.0);
            ui.small(egui::RichText::new("Phase 3: Windows 1:1 E2EE, X3DH-style OPKs, restart-persistent local state, encrypted attachments, automatic polling. This remains an engineering build, not a security certification.").weak());
        });
    }
}

#[cfg(test)]
mod safety_number_tests {
    use super::{fingerprint_hex, safety_number};

    #[test]
    fn safety_number_is_symmetric_regardless_of_argument_order() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a), "both conversation partners must compute the same safety number");
    }

    #[test]
    fn safety_number_differs_for_different_key_pairs() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let c = [0x33u8; 32];
        assert_ne!(safety_number(&a, &b), safety_number(&a, &c));
    }

    #[test]
    fn safety_number_is_deterministic() {
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        assert_eq!(safety_number(&a, &b), safety_number(&a, &b));
    }

    #[test]
    fn fingerprint_hex_is_deterministic_and_key_dependent() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_eq!(fingerprint_hex(&a), fingerprint_hex(&a));
        assert_ne!(fingerprint_hex(&a), fingerprint_hex(&b));
    }
}
