use base64::Engine;
use keyring::Entry;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use upm_core::{DoubleRatchetSession, SessionSnapshot};
use upm_crypto::AeadKey;
use upm_protocol::{MessageEnvelope, MessageId};

const SERVICE: &str = "UPM";
const DB_KEY_ACCOUNT: &str = "local-db-key";
const DB_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum LocalStoreError {
    #[error("credential store error: {0}")]
    Credential(String),
    #[error("local database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid local encrypted record")]
    InvalidRecord,
    #[error("invalid local session state: {0}")]
    Session(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessage {
    peer_device_id: String,
    direction: i64,
    text: String,
    created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxItem {
    pub message_id: MessageId,
    pub peer_device_id: String,
    pub envelope: MessageEnvelope,
    pub session_after: SessionSnapshot,
    pub text: String,
}

pub struct LocalStore {
    conn: Connection,
    key: [u8; DB_KEY_LEN],
}

impl LocalStore {
    pub fn open() -> Result<Self, LocalStoreError> {
        let path = db_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                LocalStoreError::Database(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
            })?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (\n\
                id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
                peer_device_id TEXT NOT NULL,\n\
                direction INTEGER NOT NULL,\n\
                created_at INTEGER NOT NULL,\n\
                encrypted_text BLOB NOT NULL\n\
             );\n\
             CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_device_id, id);\n\
             CREATE TABLE IF NOT EXISTS sessions (\n\
                peer_device_id TEXT PRIMARY KEY,\n\
                encrypted_state BLOB NOT NULL,\n\
                updated_at INTEGER NOT NULL\n\
             );\n\
             CREATE TABLE IF NOT EXISTS peer_identities (\n\
                peer_device_id TEXT PRIMARY KEY,\n\
                identity_public_key TEXT NOT NULL,\n\
                pinned_at INTEGER NOT NULL\n\
             );\n\
             CREATE TABLE IF NOT EXISTS outbox (\n\
                message_id TEXT PRIMARY KEY,\n\
                encrypted_record BLOB NOT NULL,\n\
                created_at INTEGER NOT NULL\n\
             );\n\
             CREATE TABLE IF NOT EXISTS processed_messages (\n\
                message_id TEXT PRIMARY KEY,\n\
                peer_device_id TEXT NOT NULL,\n\
                processed_at INTEGER NOT NULL\n\
             );",
        )?;
        Ok(Self {
            conn,
            key: load_or_create_db_key()?,
        })
    }

    pub fn load_messages(&self, peer: &str) -> Result<Vec<(bool, String)>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT direction, encrypted_text FROM messages WHERE peer_device_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![peer], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (direction, blob) = row?;
            let plaintext = self.decrypt_record(&blob)?;
            let stored: StoredMessage = serde_json::from_slice(&plaintext)?;
            out.push((direction == 1, stored.text));
        }
        Ok(out)
    }

    pub fn pin_or_verify_peer(
        &self,
        peer_device_id: &str,
        identity_public_key: &str,
    ) -> Result<bool, LocalStoreError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT identity_public_key FROM peer_identities WHERE peer_device_id = ?1",
                params![peer_device_id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            None => {
                self.conn.execute(
                    "INSERT INTO peer_identities (peer_device_id, identity_public_key, pinned_at) VALUES (?1, ?2, ?3)",
                    params![peer_device_id, identity_public_key, unix_now()],
                )?;
                Ok(true)
            }
            Some(existing_key) => Ok(existing_key == identity_public_key),
        }
    }

    pub fn save_outbox(&self, item: &OutboxItem) -> Result<(), LocalStoreError> {
        let plaintext = serde_json::to_vec(item)?;
        let blob = self.encrypt_record(&plaintext)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO outbox(message_id, encrypted_record, created_at) VALUES (?1, ?2, ?3)",
            params![item.message_id.to_hex(), blob, unix_now()],
        )?;
        Ok(())
    }

    pub fn load_outbox(&self) -> Result<Vec<OutboxItem>, LocalStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT encrypted_record FROM outbox ORDER BY created_at ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let blob = row?;
            let plaintext = self.decrypt_record(&blob)?;
            out.push(serde_json::from_slice(&plaintext)?);
        }
        Ok(out)
    }

    pub fn delete_outbox(&self, message_id: MessageId) -> Result<(), LocalStoreError> {
        self.conn.execute(
            "DELETE FROM outbox WHERE message_id = ?1",
            params![message_id.to_hex()],
        )?;
        Ok(())
    }

    pub fn is_message_processed(
        &self,
        message_id: MessageId,
        peer_device_id: &str,
    ) -> Result<bool, LocalStoreError> {
        let found: Option<String> = self
            .conn
            .query_row(
                "SELECT peer_device_id FROM processed_messages WHERE message_id = ?1",
                params![message_id.to_hex()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.as_deref() == Some(peer_device_id))
    }

    pub fn commit_incoming_message(
        &self,
        peer_device_id: &str,
        message_id: MessageId,
        text: &str,
        session: &DoubleRatchetSession,
        created_at: i64,
    ) -> Result<(), LocalStoreError> {
        let stored = StoredMessage {
            peer_device_id: peer_device_id.to_string(),
            direction: 1,
            text: text.to_string(),
            created_at,
        };
        let message_blob = encrypt_record_with_key(self.key, &serde_json::to_vec(&stored)?)?;
        let snapshot = serde_json::to_vec(&session.snapshot())?;
        let snapshot_blob = encrypt_record_with_key(self.key, &snapshot)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO messages(peer_device_id, direction, created_at, encrypted_text) VALUES (?1, 1, ?2, ?3)",
            params![peer_device_id, created_at, message_blob],
        )?;
        tx.execute(
            "INSERT INTO sessions(peer_device_id, encrypted_state, updated_at) VALUES (?1, ?2, ?3)\
             ON CONFLICT(peer_device_id) DO UPDATE SET encrypted_state=excluded.encrypted_state, updated_at=excluded.updated_at",
            params![peer_device_id, snapshot_blob, created_at],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO processed_messages(message_id, peer_device_id, processed_at) VALUES (?1, ?2, ?3)",
            params![message_id.to_hex(), peer_device_id, created_at],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn commit_outgoing_delivery(
        &self,
        item: &OutboxItem,
        session: &DoubleRatchetSession,
        created_at: i64,
    ) -> Result<(), LocalStoreError> {
        let stored = StoredMessage {
            peer_device_id: item.peer_device_id.clone(),
            direction: 0,
            text: item.text.clone(),
            created_at,
        };
        let message_blob = encrypt_record_with_key(self.key, &serde_json::to_vec(&stored)?)?;
        let snapshot_blob = encrypt_record_with_key(
            self.key,
            &serde_json::to_vec(&session.snapshot())?,
        )?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO messages(peer_device_id, direction, created_at, encrypted_text) VALUES (?1, 0, ?2, ?3)",
            params![item.peer_device_id, created_at, message_blob],
        )?;
        tx.execute(
            "INSERT INTO sessions(peer_device_id, encrypted_state, updated_at) VALUES (?1, ?2, ?3)\
             ON CONFLICT(peer_device_id) DO UPDATE SET encrypted_state=excluded.encrypted_state, updated_at=excluded.updated_at",
            params![item.peer_device_id, snapshot_blob, created_at],
        )?;
        tx.execute(
            "DELETE FROM outbox WHERE message_id = ?1",
            params![item.message_id.to_hex()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn append_message(
        &self,
        peer_device_id: &str,
        incoming: bool,
        text: &str,
        created_at: i64,
    ) -> Result<(), LocalStoreError> {
        let stored = StoredMessage {
            peer_device_id: peer_device_id.to_string(),
            direction: if incoming { 1 } else { 0 },
            text: text.to_string(),
            created_at,
        };
        let plaintext = serde_json::to_vec(&stored)?;
        let blob = self.encrypt_record(&plaintext)?;
        self.conn.execute(
            "INSERT INTO messages(peer_device_id, direction, created_at, encrypted_text) VALUES (?1, ?2, ?3, ?4)",
            params![peer_device_id, stored.direction, created_at, blob],
        )?;
        Ok(())
    }

    pub fn save_session(
        &self,
        peer_device_id: &str,
        session: &DoubleRatchetSession,
        updated_at: i64,
    ) -> Result<(), LocalStoreError> {
        let snapshot = session.snapshot();
        let plaintext = serde_json::to_vec(&snapshot)?;
        let blob = self.encrypt_record(&plaintext)?;
        self.conn.execute(
            "INSERT INTO sessions(peer_device_id, encrypted_state, updated_at) VALUES (?1, ?2, ?3)\
             ON CONFLICT(peer_device_id) DO UPDATE SET encrypted_state=excluded.encrypted_state, updated_at=excluded.updated_at",
            params![peer_device_id, blob, updated_at],
        )?;
        Ok(())
    }

    pub fn load_session(
        &self,
        peer_device_id: &str,
    ) -> Result<Option<DoubleRatchetSession>, LocalStoreError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT encrypted_state FROM sessions WHERE peer_device_id = ?1",
                params![peer_device_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(blob) = blob else { return Ok(None) };
        let plaintext = self.decrypt_record(&blob)?;
        let snapshot: SessionSnapshot = serde_json::from_slice(&plaintext)?;
        DoubleRatchetSession::from_snapshot(snapshot)
            .map(Some)
            .map_err(|e| LocalStoreError::Session(e.to_string()))
    }

    fn encrypt_record(&self, plaintext: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        encrypt_record_with_key(self.key, plaintext)
    }

    fn decrypt_record(&self, blob: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        if blob.len() < 12 {
            return Err(LocalStoreError::InvalidRecord);
        }
        let nonce: [u8; 12] = blob[..12]
            .try_into()
            .map_err(|_| LocalStoreError::InvalidRecord)?;
        let key = AeadKey::from_bytes(self.key);
        upm_crypto::decrypt(&key, &nonce, &blob[12..], b"UPM/local-store/v1")
            .map_err(|_| LocalStoreError::InvalidRecord)
    }
}

fn encrypt_record_with_key(
    key_bytes: [u8; DB_KEY_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, LocalStoreError> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = AeadKey::from_bytes(key_bytes);
    let ciphertext = upm_crypto::encrypt(&key, &nonce, plaintext, b"UPM/local-store/v1")
        .map_err(|_| LocalStoreError::InvalidRecord)?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn load_or_create_db_key() -> Result<[u8; DB_KEY_LEN], LocalStoreError> {
    let entry = Entry::new(SERVICE, DB_KEY_ACCOUNT)
        .map_err(|e| LocalStoreError::Credential(e.to_string()))?;
    if let Ok(value) = entry.get_password() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| LocalStoreError::Credential("invalid stored database key".into()))?;
        return bytes
            .try_into()
            .map_err(|_| LocalStoreError::Credential("invalid stored database key length".into()));
    }
    let mut key = [0u8; DB_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    entry
        .set_password(&encoded)
        .map_err(|e| LocalStoreError::Credential(e.to_string()))?;
    Ok(key)
}

fn db_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data).join("UPM").join("client.db");
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        return PathBuf::from(home)
            .join("AppData")
            .join("Local")
            .join("UPM")
            .join("client.db");
    }
    PathBuf::from("upm-client.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_identity_is_pinned_and_changes_are_detected() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE peer_identities (peer_device_id TEXT PRIMARY KEY, identity_public_key TEXT NOT NULL, pinned_at INTEGER NOT NULL);").unwrap();
        let store = LocalStore { conn, key: [7u8; DB_KEY_LEN] };
        assert!(store.pin_or_verify_peer("A", "KEY1").unwrap());
        assert!(store.pin_or_verify_peer("A", "KEY1").unwrap());
        assert!(!store.pin_or_verify_peer("A", "KEY2").unwrap());
    }

    #[test]
    fn processed_message_marker_survives_commit() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, peer_device_id TEXT NOT NULL, direction INTEGER NOT NULL, created_at INTEGER NOT NULL, encrypted_text BLOB NOT NULL); CREATE TABLE sessions (peer_device_id TEXT PRIMARY KEY, encrypted_state BLOB NOT NULL, updated_at INTEGER NOT NULL); CREATE TABLE processed_messages (message_id TEXT PRIMARY KEY, peer_device_id TEXT NOT NULL, processed_at INTEGER NOT NULL);").unwrap();
        let store = LocalStore { conn, key: [8u8; DB_KEY_LEN] };
        let snapshot = SessionSnapshot {
            protocol_version: upm_protocol::ProtocolVersion::CURRENT,
            peer_device: upm_protocol::DeviceId([2; 16]),
            root_key: [0; 32],
            dh_self_private: [1; 32],
            dh_remote_public: None,
            sending_chain_key: None,
            receiving_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_chain_len: 0,
            skipped: Vec::new(),
        };
        let session = DoubleRatchetSession::from_snapshot(snapshot).unwrap();
        let id = MessageId([3; 16]);
        store.commit_incoming_message("PEER", id, "hello", &session, 1).unwrap();
        assert!(store.is_message_processed(id, "PEER").unwrap());
        assert!(!store.is_message_processed(id, "OTHER").unwrap());
    }
}
