use base64::Engine;
use keyring::Entry;
use rand::RngCore;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use upm_core::{DoubleRatchetSession, SessionSnapshot};
use upm_crypto::AeadKey;

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

pub struct LocalStore {
    conn: Connection,
    key: [u8; DB_KEY_LEN],
}

impl LocalStore {
    pub fn open() -> Result<Self, LocalStoreError> {
        let path = db_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| LocalStoreError::Database(rusqlite::Error::ToSqlConversionFailure(Box::new(e))))?;
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
            "INSERT INTO sessions(peer_device_id, encrypted_state, updated_at) VALUES (?1, ?2, ?3)\n\
             ON CONFLICT(peer_device_id) DO UPDATE SET encrypted_state=excluded.encrypted_state, updated_at=excluded.updated_at",
            params![peer_device_id, blob, updated_at],
        )?;
        Ok(())
    }

    pub fn load_session(&self, peer_device_id: &str) -> Result<Option<DoubleRatchetSession>, LocalStoreError> {
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
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let key = AeadKey::from_bytes(self.key);
        let ciphertext = upm_crypto::encrypt(&key, &nonce, plaintext, b"UPM/local-store/v1")
            .map_err(|_| LocalStoreError::InvalidRecord)?;
        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
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
        return PathBuf::from(home).join("AppData").join("Local").join("UPM").join("client.db");
    }
    PathBuf::from("upm-client.db")
}

// Needed for Connection::query_row(...).optional().
use rusqlite::OptionalExtension;

