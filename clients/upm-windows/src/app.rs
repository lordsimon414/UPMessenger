use crate::api::{ApiClient, DeviceKeyBundle, DirectoryEntry};
use crate::identity::LocalIdentity;
use crate::local_store::LocalStore;
use crate::storage::{self, LocalProfile};
use base64::Engine;
use eframe::egui;
use serde::{Deserialize, Serialize};
use upm_core::{handshake, DoubleRatchetSession, Session};
use upm_protocol::{DeviceId, MessageEnvelope, MessageId, ProtocolVersion};

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
    signature: [u8; 64],
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionPacket {
    protocol_version: u16,
    bootstrap: Option<SessionBootstrap>,
    ratchet_message_base64: String,
}

#[derive(Debug)]
struct ChatLine {
    direction: Direction,
    text: String,
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
        if let (Some(a), Some(b), Some(c)) = (
            decode(&secrets.signing_private_b64),
            decode(&secrets.exchange_private_b64),
            decode(&secrets.signed_prekey_private_b64),
        ) {
            return LocalIdentity::from_private_key_bytes(a, b, c);
        }
    }

    let identity = LocalIdentity::generate();
    let (a, b, c) = identity.private_key_bytes();
    let secrets = storage::local_secrets_from_bytes(a, b, c);
    let _ = storage::save_secrets(&secrets);
    identity
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
) -> Vec<u8> {
    let mut message = Vec::with_capacity(16 + 32 + 32 + 16);
    message.extend_from_slice(b"UPM/v3/bootstrap/");
    message.extend_from_slice(&recipient_device.0);
    message.extend_from_slice(sender_identity_exchange_public);
    message.extend_from_slice(ephemeral_public);
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
    );
    upm_crypto::verify(
        &bootstrap.sender_identity_signing_public,
        &message,
        &bootstrap.signature,
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

pub struct UpmApp {
    profile: LocalProfile,
    identity: LocalIdentity,
    api: Option<ApiClient>,
    status: String,
    new_contact: String,
    message_input: String,
    directory: Option<DirectoryEntry>,
    received: Vec<String>,
    conversation: Option<Conversation>,
    local_store: Option<LocalStore>,
}

impl UpmApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut profile = storage::load();
        if profile.server_url.is_empty() {
            profile.server_url = "https://upm.local".into();
        }
        let api = ApiClient::new(&profile.server_url).ok();
        let identity = load_or_generate_identity();
        let local_store = LocalStore::open().ok();
        Self {
            profile,
            identity,
            api,
            status: "Ready".into(),
            new_contact: String::new(),
            message_input: String::new(),
            directory: None,
            received: Vec::new(),
            conversation: None,
            local_store,
        }
    }

    fn save(&mut self) {
        match storage::save(&self.profile) {
            Ok(_) => self.status = "Saved".into(),
            Err(e) => self.status = format!("Storage error: {e}"),
        }
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

    fn authenticate(&mut self) {
        let Some(device_id) = self.profile.device_id.clone() else {
            self.status = "Register first".into();
            return;
        };
        let Some(api) = self.api.clone() else { return };
        let challenge = match api.challenge(&device_id) {
            Ok((c, _)) => c,
            Err(e) => {
                self.status = format!("Challenge failed: {e}");
                return;
            }
        };
        let signature = self.identity.signing.sign(&challenge);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
        match api.verify(&device_id, &signature_b64) {
            Ok(v) => {
                self.profile.session_token = Some(v.session_token);
                self.profile.session_expires_at = Some(v.expires_at);
                self.save();
                self.status = "Authenticated".into();
                let token = self.profile.session_token.clone().unwrap_or_default();
                if let Err(e) = api.publish_keys(
                    &token,
                    &self.identity.exchange_public_b64(),
                    &self.identity.signed_prekey_public_b64(),
                    &self.identity.signed_prekey_signature_b64(),
                ) {
                    self.status = format!("Authenticated, key publish failed: {e}");
                } else {
                    self.status = "Authenticated + X3DH bundle published".into();
                }
            }
            Err(e) => self.status = format!("Authentication failed: {e}"),
        }
    }

    fn resolve(&mut self) {
        let Some(api) = self.api.clone() else { return };
        match api.resolve_username(&self.new_contact) {
            Ok(entry) => {
                self.status = format!("Found @{} ({})", entry.username, entry.upm_id);
                self.directory = Some(entry);
                self.conversation = None;
            }
            Err(e) => self.status = format!("Directory lookup failed: {e}"),
        }
    }

    fn ensure_conversation(&mut self) -> Result<(), String> {
        let Some(peer) = self.directory.clone() else {
            return Err("Resolve a contact first".into());
        };
        if let Some(conversation) = &self.conversation {
            if conversation.peer.device_id == peer.device_id {
                return Ok(());
            }
        }
        let mut conversation = Conversation {
            peer,
            session: None,
            lines: Vec::new(),
        };
        if let Some(store) = &self.local_store {
            match store.load_session(&conversation.peer.device_id) {
                Ok(session) => conversation.session = session,
                Err(_) => {
                    self.status = "Stored session could not be restored; a new peer session may be required".into();
                }
            }
            match store.load_messages(&conversation.peer.device_id) {
                Ok(history) => {
                    conversation.lines = history
                        .into_iter()
                        .map(|(incoming, text)| ChatLine {
                            direction: if incoming { Direction::Incoming } else { Direction::Outgoing },
                            text,
                        })
                        .collect();
                }
                Err(_) => {
                    self.status = "Local message history could not be decrypted".into();
                }
            }
        }
        self.conversation = Some(conversation);
        Ok(())
    }

    fn make_initial_outgoing_packet(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(MessageEnvelope, DoubleRatchetSession), String> {
        self.ensure_conversation()?;
        let Some(api) = self.api.clone() else { return Err("Invalid server URL".into()) };
        let my_device = decode_device_id(
            self.profile
                .device_id
                .as_deref()
                .ok_or_else(|| "Register and authenticate first".to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let peer = self.conversation.as_ref().unwrap().peer.clone();
        let peer_device = decode_device_id(&peer.device_id).map_err(|e| e.to_string())?;
        let bundle = api
            .device_keys(&peer.device_id)
            .map_err(|e| format!("key lookup failed: {e}"))?;
        let expected_identity = decode_32(&bundle.identity_public_key).map_err(|e| e.to_string())?;
        let directory_identity = decode_32(&peer.identity_public_key).map_err(|e| e.to_string())?;
        if expected_identity != directory_identity {
            return Err("directory identity changed; refusing silent key change".into());
        }
        let prekey = handshake::PreKeyBundle {
            identity_signing_public: expected_identity,
            identity_exchange_public: decode_32(&bundle.identity_exchange_public).map_err(|e| e.to_string())?,
            signed_prekey_public: decode_32(&bundle.signed_prekey_public).map_err(|e| e.to_string())?,
            signed_prekey_signature: decode_64(&bundle.signed_prekey_signature).map_err(|e| e.to_string())?,
        };
        let hs = handshake::initiate(&self.identity.exchange, &prekey)
            .map_err(|e| format!("session handshake failed: {e}"))?;
        let mut session = DoubleRatchetSession::init_initiator(
            peer_device,
            &hs.result,
            hs.bob_initial_ratchet_public,
        )
        .map_err(|e| format!("session init failed: {e}"))?;
        let signature_message = bootstrap_signature_message(
            peer_device,
            &hs.my_identity_exchange_public,
            &hs.ephemeral_public,
        );
        let bootstrap = SessionBootstrap {
            sender_identity_signing_public: self.identity.signing.public_key(),
            sender_identity_exchange_public: hs.my_identity_exchange_public,
            ephemeral_public: hs.ephemeral_public,
            signature: self.identity.signing.sign(&signature_message),
        };
        let ratchet_message = session
            .encrypt(plaintext)
            .map_err(|e| format!("encryption failed: {e}"))?;
        let packet = SessionPacket {
            protocol_version: ProtocolVersion::CURRENT.0,
            bootstrap: Some(bootstrap),
            ratchet_message_base64: base64::engine::general_purpose::STANDARD.encode(ratchet_message),
        };
        let ciphertext = encode_packet(&packet).map_err(|e| e.to_string())?;
        let envelope = MessageEnvelope {
            protocol_version: ProtocolVersion::CURRENT,
            message_id: MessageId::random(),
            sender_device_id: my_device,
            recipient_device_id: peer_device,
            ciphertext,
            server_timestamp: 0,
            expires_at: 0,
        };
        Ok((envelope, session))
    }

    fn make_outgoing_packet(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(MessageEnvelope, DoubleRatchetSession), String> {
        self.ensure_conversation()?;
        let existing = self
            .conversation
            .as_ref()
            .and_then(|conversation| conversation.session.as_ref())
            .cloned();
        let Some(mut session) = existing else {
            return self.make_initial_outgoing_packet(plaintext);
        };
        let my_device = decode_device_id(
            self.profile
                .device_id
                .as_deref()
                .ok_or_else(|| "Register and authenticate first".to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let peer_device = decode_device_id(
            &self.conversation.as_ref().unwrap().peer.device_id
        )
        .map_err(|e| e.to_string())?;
        let ratchet_message = session
            .encrypt(plaintext)
            .map_err(|e| format!("encryption failed: {e}"))?;
        let packet = SessionPacket {
            protocol_version: ProtocolVersion::CURRENT.0,
            bootstrap: None,
            ratchet_message_base64: base64::engine::general_purpose::STANDARD.encode(ratchet_message),
        };
        let ciphertext = encode_packet(&packet).map_err(|e| e.to_string())?;
        let envelope = MessageEnvelope {
            protocol_version: ProtocolVersion::CURRENT,
            message_id: MessageId::random(),
            sender_device_id: my_device,
            recipient_device_id: peer_device,
            ciphertext,
            server_timestamp: 0,
            expires_at: 0,
        };
        Ok((envelope, session))
    }

    fn send_message(&mut self) {
        let plaintext = self.message_input.trim().as_bytes().to_vec();
        if plaintext.is_empty() {
            return;
        }
        let Some(api) = self.api.clone() else {
            self.status = "Invalid server URL".into();
            return;
        };
        let Some(token) = self.profile.session_token.clone() else {
            self.status = "Authenticate first".into();
            return;
        };
        let result = self.make_outgoing_packet(&plaintext);
        let (mut envelope, _) = match result {
            Ok(value) => value,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        envelope.server_timestamp = 0;
        envelope.expires_at = 0;
        match api.send_envelope(&token, &envelope) {
            Ok(()) => {
                let text = String::from_utf8_lossy(&plaintext).into_owned();
                if let Some(conversation) = &mut self.conversation {
                    conversation.session = Some(candidate_session);
                    conversation.lines.push(ChatLine {
                        direction: Direction::Outgoing,
                        text: text.clone(),
                    });
                    if let Some(store) = &self.local_store {
                        if let Some(session) = conversation.session.as_ref() {
                            let _ = store.save_session(&conversation.peer.device_id, session, unix_now());
                        }
                        let _ = store.append_message(&conversation.peer.device_id, false, &text, unix_now());
                    }
                }
                self.status = "Encrypted message queued".into();
            }
            Err(e) => self.status = format!("Send failed: {e}"),
        }
    }

    fn establish_responder_session(
        &mut self,
        sender_device: DeviceId,
        bootstrap: &SessionBootstrap,
    ) -> Result<DoubleRatchetSession, ClientCryptoError> {
        let directory = self
            .directory
            .as_ref()
            .ok_or(ClientCryptoError::PeerIdentityMismatch)?;
        if directory.device_id != sender_device.to_hex() {
            return Err(ClientCryptoError::PeerIdentityMismatch);
        }
        let expected_identity = decode_32(&directory.identity_public_key).map_err(|_| ClientCryptoError::PeerIdentityMismatch)?;
        if expected_identity != bootstrap.sender_identity_signing_public {
            return Err(ClientCryptoError::PeerIdentityMismatch);
        }
        let my_device = decode_device_id(
            self.profile
                .device_id
                .as_deref()
                .ok_or(ClientCryptoError::PeerIdentityMismatch)?,
        )?;
        verify_bootstrap(bootstrap, my_device)?;
        let hs = handshake::respond(
            &self.identity.exchange,
            &self.identity.signed_prekey,
            &bootstrap.sender_identity_exchange_public,
            &bootstrap.ephemeral_public,
        )?;
        Ok(DoubleRatchetSession::init_responder(
            sender_device,
            &hs,
            self.identity.signed_prekey.clone(),
        ))
    }

    fn poll(&mut self) {
        let (Some(api), Some(token), Some(device_id)) = (
            self.api.clone(),
            self.profile.session_token.clone(),
            self.profile.device_id.clone(),
        ) else {
            self.status = "Register and authenticate first".into();
            return;
        };
        if decode_device_id(&device_id).is_err() {
            self.status = "Invalid local device ID".into();
            return;
        }
        match api.pull(&token, &device_id) {
            Ok(items) => {
                let mut ack_ids = Vec::new();
                let mut decrypted_count = 0usize;
                for item in &items {
                    let sender_device = match decode_device_id(&item.sender_device_id) {
                        Ok(id) => id,
                        Err(e) => {
                            self.status = format!("Invalid sender device: {e}");
                            continue;
                        }
                    };
                    let raw = match base64::engine::general_purpose::STANDARD.decode(&item.ciphertext_base64) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            self.status = "Received malformed ciphertext envelope".into();
                            continue;
                        }
                    };
                    let packet = match decode_packet(&raw) {
                        Ok(packet) => packet,
                        Err(e) => {
                            self.status = e.to_string();
                            continue;
                        }
                    };
                    if packet.protocol_version != ProtocolVersion::CURRENT.0 {
                        self.status = format!("Unsupported session packet protocol v{}", packet.protocol_version);
                        continue;
                    }
                    let ratchet_wire = match base64::engine::general_purpose::STANDARD.decode(&packet.ratchet_message_base64) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            self.status = "Malformed ratchet message".into();
                            continue;
                        }
                    };

                    let mut needs_new_session = false;
                    if let Some(conversation) = &self.conversation {
                        if conversation.peer.device_id == sender_device.to_hex() && conversation.session.is_none() {
                            needs_new_session = true;
                        }
                    } else if let Some(directory) = &self.directory {
                        if directory.device_id == sender_device.to_hex() {
                            needs_new_session = true;
                        }
                    }

                    if needs_new_session {
                        let Some(bootstrap) = packet.bootstrap.as_ref() else {
                            self.status = "Initial peer packet has no handshake bootstrap".into();
                            continue;
                        };
                        match self.establish_responder_session(sender_device, bootstrap) {
                            Ok(session) => {
                                self.conversation = Some(Conversation {
                                    peer: self.directory.clone().unwrap(),
                                    session: Some(session),
                                    lines: Vec::new(),
                                });
                            }
                            Err(e) => {
                                self.status = format!("Peer authentication failed: {e}");
                                continue;
                            }
                        }
                    }

                    let Some(conversation) = self.conversation.as_mut() else {
                        self.status = "Received a message from an unknown device; refusing to decrypt".into();
                        continue;
                    };
                    if conversation.peer.device_id != sender_device.to_hex() {
                        self.status = "Received message from a device outside the active conversation".into();
                        continue;
                    }
                    let Some(session) = conversation.session.as_mut() else {
                        self.status = "Peer session not established".into();
                        continue;
                    };
                    match session.decrypt(&ratchet_wire) {
                        Ok(plaintext) => {
                            let text = String::from_utf8_lossy(&plaintext).into_owned();
                            conversation.lines.push(ChatLine {
                                direction: Direction::Incoming,
                                text: text.clone(),
                            });
                            if let Some(store) = &self.local_store {
                                let _ = store.append_message(&conversation.peer.device_id, true, &text, unix_now());
                                let _ = store.save_session(&conversation.peer.device_id, session, unix_now());
                            }
                            self.received.push(format!("Peer: {text}"));
                            ack_ids.push(item.message_id.clone());
                            decrypted_count += 1;
                        }
                        Err(e) => {
                            self.status = format!("Message authentication/decryption failed: {e}");
                        }
                    }
                }
                if !ack_ids.is_empty() {
                    if let Err(e) = api.ack(&token, &ack_ids) {
                        self.status = format!("Decrypted {decrypted_count} message(s), but ACK failed: {e}");
                    } else {
                        self.status = format!("Decrypted and acknowledged {decrypted_count} message(s)");
                    }
                } else if items.is_empty() {
                    self.status = "No queued messages".into();
                }
            }
            Err(e) => self.status = format!("Pull failed: {e}"),
        }
    }
}

impl eframe::App for UpmApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("UPM");
                ui.separator();
                ui.label(&self.status);
            });
        });

        egui::SidePanel::left("sidebar").resizable(true).show(ctx, |ui| {
            ui.heading("Connection");
            ui.text_edit_singleline(&mut self.profile.server_url);
            if ui.button("Connect").clicked() {
                self.reconnect();
            }
            ui.separator();
            ui.heading("Identity");
            ui.label(format!("Username: @{}", self.profile.username));
            if let Some(id) = &self.profile.upm_id {
                ui.label(format!("UPM ID: {id}"));
            }
            if let Some(d) = &self.profile.device_id {
                ui.label(format!("Device: {d}"));
            }
            ui.text_edit_singleline(&mut self.profile.username);
            ui.horizontal(|ui| {
                if ui.button("Register").clicked() {
                    self.register();
                }
                if ui.button("Authenticate").clicked() {
                    self.authenticate();
                }
            });
            if ui.button("Save local profile").clicked() {
                self.save();
            }
            ui.separator();
            ui.heading("Contact discovery");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.new_contact);
                if ui.button("Resolve").clicked() {
                    self.resolve();
                }
            });
            if let Some(entry) = &self.directory {
                ui.label(format!("@{} — {}", entry.username, entry.upm_id));
                ui.small(format!("Device: {}", entry.device_id));
                ui.monospace(&entry.identity_public_key);
            }
            if ui.button("Pull messages").clicked() {
                self.poll();
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Conversation");
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    if let Some(conversation) = &self.conversation {
                        for line in &conversation.lines {
                            let label = match line.direction {
                                Direction::Incoming => "Peer",
                                Direction::Outgoing => "You",
                            };
                            ui.group(|ui| {
                                ui.label(format!("{label}: {}", line.text));
                            });
                            ui.add_space(4.0);
                        }
                    } else {
                        for line in &self.received {
                            ui.group(|ui| {
                                ui.label(line);
                            });
                        }
                    }
                });
            ui.separator();
            ui.horizontal(|ui| {
                let send = ui
                    .text_edit_singleline(&mut self.message_input)
                    .lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Send encrypted").clicked() || send {
                    self.send_message();
                    self.message_input.clear();
                }
            });
            ui.add_space(8.0);
            ui.small("Phase 3: authenticated account/device, X3DH-lite peer setup, Double-Ratchet message encryption, typed envelopes, and client-side decryption are wired. Session persistence and encrypted local message history remain open.");
        });
    }
}
