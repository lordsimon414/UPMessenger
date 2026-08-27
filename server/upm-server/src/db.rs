//! SQLite schema and data-access functions for UPM (SRS §15, §10).
//!
//! The server never stores message plaintext or private key material —
//! only what SRS §13 ("Privacy and metadata minimization") explicitly
//! allows: username, UPM ID, public key material, and message envelopes
//! bounded by TTL. `ciphertext_blob` here is opaque to the server; nothing
//! in this module ever inspects, decrypts or logs its contents (see
//! `docs/THREAT_MODEL.md`).

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use std::time::{SystemTime, UNIX_EPOCH};
use upm_protocol::{MessageEnvelope, ProtocolVersion};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64
}

/// Opens (creating if needed) the UPM database at `path` and applies the
/// schema. WAL mode per SRS §10 ("SQLite with WAL mode where operationally
/// suitable"). Callers are responsible for the filesystem ACLs mentioned in
/// SRS §10 — this function only talks to SQLite, not the OS permission
/// model.
pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", true)?;
    init_schema(&conn)?;
    crate::auth::init_schema(&conn)?;
    Ok(conn)
}

#[cfg(test)]
pub(crate) fn init_schema_for_tests(conn: &Connection) -> rusqlite::Result<()> {
    init_schema(conn)
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            user_id             TEXT PRIMARY KEY,
            upm_id              TEXT NOT NULL UNIQUE,
            username            TEXT NOT NULL UNIQUE,
            username_normalized TEXT NOT NULL UNIQUE,
            created_at          INTEGER NOT NULL,
            status              TEXT NOT NULL DEFAULT 'active',
            directory_visible  INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id             TEXT PRIMARY KEY,
            user_id                TEXT NOT NULL REFERENCES users(user_id),
            identity_public_key    TEXT NOT NULL,
            identity_exchange_public TEXT,
            signed_prekey_public   TEXT,
            signed_prekey_signature TEXT,
            capabilities           TEXT NOT NULL DEFAULT '[]',
            last_seen_coarse       INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

        CREATE TABLE IF NOT EXISTS one_time_prekeys (
            prekey_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL REFERENCES devices(device_id),
            public_key TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            claimed_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_opk_device_claimed ON one_time_prekeys(device_id, claimed_at);

        CREATE TABLE IF NOT EXISTS conversations (
            conversation_id TEXT PRIMARY KEY,
            type            TEXT NOT NULL,
            created_at      INTEGER NOT NULL,
            state_version   INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS memberships (
            conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
            user_id         TEXT NOT NULL REFERENCES users(user_id),
            role            TEXT NOT NULL DEFAULT 'member',
            joined_at       INTEGER NOT NULL,
            removed_at      INTEGER,
            PRIMARY KEY (conversation_id, user_id)
        );

        -- SRS §15 MessageEnvelope / §8 Messaging and delivery.
        CREATE TABLE IF NOT EXISTS message_envelopes (
            message_id           TEXT PRIMARY KEY,
            sender_device_id     TEXT NOT NULL REFERENCES devices(device_id),
            recipient_device_id  TEXT NOT NULL REFERENCES devices(device_id),
            ciphertext_blob      BLOB NOT NULL,
            created_at           INTEGER NOT NULL,
            expires_at           INTEGER NOT NULL,
            delivery_state       TEXT NOT NULL DEFAULT 'queued',
            protocol_version     INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_envelopes_recipient
            ON message_envelopes(recipient_device_id, delivery_state);

        CREATE TABLE IF NOT EXISTS attachments (
            attachment_id        TEXT PRIMARY KEY,
            owner_message_id     TEXT,
            owner_device_id      TEXT REFERENCES devices(device_id),
            opaque_size          INTEGER NOT NULL,
            storage_key          TEXT NOT NULL,
            capability_hash      TEXT NOT NULL DEFAULT '',
            expires_at            INTEGER NOT NULL,
            uploaded_at           INTEGER
        );

        -- SRS §18: allow-listed, coarse, short-retained. No usernames,
        -- UPM IDs, message IDs or IPs belong in this table.
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id          TEXT PRIMARY KEY,
            event_class       TEXT NOT NULL,
            coarse_timestamp  INTEGER NOT NULL,
            outcome           TEXT NOT NULL
        );
        "#,
    );

    // Migrate databases created by the original Phase 1 scaffold. SQLite's
    // CREATE TABLE IF NOT EXISTS does not add newly introduced columns.
    for stmt in [
        "ALTER TABLE users ADD COLUMN directory_visible INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE devices ADD COLUMN identity_exchange_public TEXT",
        "ALTER TABLE devices ADD COLUMN signed_prekey_signature TEXT",
        "ALTER TABLE message_envelopes ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE message_envelopes ADD COLUMN sender_device_id TEXT REFERENCES devices(device_id)",
        "ALTER TABLE attachments ADD COLUMN owner_device_id TEXT REFERENCES devices(device_id)",
        "ALTER TABLE attachments ADD COLUMN uploaded_at INTEGER",
        "ALTER TABLE attachments ADD COLUMN capability_hash TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE one_time_prekeys ADD COLUMN signature TEXT NOT NULL DEFAULT ''",
    ] {
        let _ = conn.execute(stmt, []);
    }

    // Queue entries from any older protocol revision or from the pre-sender-ID
    // schema cannot safely be relabeled. Drop them rather than delivering
    // them to a client expecting the current authenticated envelope format.
    conn.execute(
        "DELETE FROM message_envelopes WHERE protocol_version != ?1",
        params![ProtocolVersion::CURRENT.0 as i64],
    )?;
    conn.execute("DELETE FROM one_time_prekeys WHERE signature = ''", [])?;
    // Older attachment rows have no capability secret to grant to a recipient.
    // Remove them rather than silently preserving an attachment with weaker
    // access control semantics.
    conn.execute("DELETE FROM attachments WHERE capability_hash = ''", [])?;
    Ok(())
}

// ---------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------

const UPM_ID_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // no 0/O/1/I

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Human-manageable public account identifier (SRS §7), e.g. "7F3A-91D2-4C2M".
/// Not secret — safe to share, directory-resolvable.
fn generate_upm_id() -> String {
    let mut rng = rand::thread_rng();
    let group = |rng: &mut rand::rngs::ThreadRng| -> String {
        (0..4)
            .map(|_| UPM_ID_ALPHABET[(rng.next_u32() as usize) % UPM_ID_ALPHABET.len()] as char)
            .collect()
    };
    format!(
        "{}-{}-{}",
        group(&mut rng),
        group(&mut rng),
        group(&mut rng)
    )
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("username already taken")]
    UsernameTaken,
    #[error("user not found")]
    UserNotFound,
    #[error("device not found")]
    DeviceNotFound,
    #[error("invalid message envelope")]
    InvalidEnvelope,
    #[error("message queue quota exceeded")]
    QueueQuotaExceeded,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

// ---------------------------------------------------------------------
// Accounts (SRS §7, AC-01) and directory (AC-02)
// ---------------------------------------------------------------------

#[derive(Debug)]
pub struct RegisteredAccount {
    pub user_id: String,
    pub upm_id: String,
    pub device_id: String,
}

/// Creates a UPM account and its first device in one step. No phone/email
/// is ever required or accepted (SRS §7, PRIV-01).
pub fn register_account(
    conn: &Connection,
    username: &str,
    identity_public_key: &str,
) -> Result<RegisteredAccount, DbError> {
    let normalized = username.to_lowercase();
    let existing: Option<String> = conn
        .query_row(
            "SELECT user_id FROM users WHERE username_normalized = ?1",
            params![normalized],
            |row| row.get(0),
        )
        .optional()?;
    if existing.is_some() {
        return Err(DbError::UsernameTaken);
    }

    let user_id = random_hex(16);
    let upm_id = generate_upm_id();
    let device_id = random_hex(16);
    let created_at = now();

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO users (user_id, upm_id, username, username_normalized, created_at, status, directory_visible)
         VALUES (?1, ?2, ?3, ?4, ?5, 'active', 1)",
        params![user_id, upm_id, username, normalized, created_at],
    )?;
    tx.execute(
        "INSERT INTO devices (device_id, user_id, identity_public_key, capabilities)
         VALUES (?1, ?2, ?3, '[]')",
        params![device_id, user_id, identity_public_key],
    )?;
    tx.commit()?;

    Ok(RegisteredAccount {
        user_id,
        upm_id,
        device_id,
    })
}

pub struct DirectoryEntry {
    pub upm_id: String,
    pub username: String,
    pub device_id: String,
    /// Primary device's identity key. Multi-device fan-out is a later
    /// phase (SRS §22 "Single Windows server" / roadmap Phase 8 "stronger
    /// multi-device model") — Phase 1 resolves to the first registered
    /// device only.
    pub identity_public_key: String,
}

/// Resolves a username to public directory data only — never anything
/// beyond what SRS §16 lists as the minimum for `/v1/directory/resolve`.
pub fn resolve_username(
    conn: &Connection,
    username: &str,
) -> Result<Option<DirectoryEntry>, DbError> {
    let normalized = username.to_lowercase();
    let result = conn
        .query_row(
            "SELECT u.upm_id, u.username, d.device_id, d.identity_public_key
             FROM users u
             JOIN devices d ON d.user_id = u.user_id
             WHERE u.username_normalized = ?1 AND u.status = 'active' AND u.directory_visible = 1
             ORDER BY d.rowid ASC
             LIMIT 1",
            params![normalized],
            |row| {
                Ok(DirectoryEntry {
                    upm_id: row.get(0)?,
                    username: row.get(1)?,
                    device_id: row.get(2)?,
                    identity_public_key: row.get(3)?,
                })
            },
        )
        .optional()?;
    Ok(result)
}

pub fn resolve_upm_id(
    conn: &Connection,
    upm_id: &str,
) -> Result<Option<DirectoryEntry>, DbError> {
    let result = conn
        .query_row(
            "SELECT u.upm_id, u.username, d.device_id, d.identity_public_key
             FROM users u
             JOIN devices d ON d.user_id = u.user_id
             WHERE u.upm_id = ?1 AND u.status = 'active' AND u.directory_visible = 1
             ORDER BY d.rowid ASC
             LIMIT 1",
            params![upm_id],
            |row| {
                Ok(DirectoryEntry {
                    upm_id: row.get(0)?,
                    username: row.get(1)?,
                    device_id: row.get(2)?,
                    identity_public_key: row.get(3)?,
                })
            },
        )
        .optional()?;
    Ok(result)
}

pub fn set_directory_visibility(
    conn: &Connection,
    authenticated_device_id: &str,
    visible: bool,
) -> Result<(), DbError> {
    let changed = conn.execute(
        "UPDATE users SET directory_visible = ?2 WHERE user_id = (SELECT user_id FROM devices WHERE device_id = ?1) AND status = 'active'",
        params![authenticated_device_id, if visible { 1 } else { 0 }],
    )?;
    if changed == 0 {
        return Err(DbError::DeviceNotFound);
    }
    Ok(())
}

pub fn get_directory_visibility(
    conn: &Connection,
    authenticated_device_id: &str,
) -> Result<bool, DbError> {
    conn.query_row(
        "SELECT u.directory_visible FROM users u JOIN devices d ON d.user_id = u.user_id WHERE d.device_id = ?1",
        params![authenticated_device_id],
        |row| Ok(row.get::<_, i64>(0)? != 0),
    ).optional()?.ok_or(DbError::DeviceNotFound)
}

pub fn get_public_profile(
    conn: &Connection,
    username: &str,
) -> Result<Option<DirectoryEntry>, DbError> {
    // Phase 1: public profile and directory resolution expose the same
    // minimal fields (SRS §16 GET /v1/profile/public). They may diverge
    // once profile fields (avatar, status text) are added.
    resolve_username(conn, username)
}

// ---------------------------------------------------------------------
// Device keys (SRS §16 POST /v1/devices/keys)
// ---------------------------------------------------------------------

pub fn get_device_identity_public_key(
    conn: &Connection,
    device_id: &str,
) -> Result<String, DbError> {
    conn.query_row(
        "SELECT identity_public_key FROM devices WHERE device_id = ?1",
        params![device_id],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(DbError::DeviceNotFound)
}

pub fn update_device_keys(
    conn: &Connection,
    authenticated_device_id: &str,
    identity_exchange_public: &str,
    signed_prekey_public: &str,
    signed_prekey_signature: &str,
) -> Result<(), DbError> {
    let exists: Option<String> = conn
        .query_row(
            "SELECT device_id FROM devices WHERE device_id = ?1",
            params![authenticated_device_id],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Err(DbError::DeviceNotFound);
    }

    let changed = conn.execute(
        "UPDATE devices
         SET identity_exchange_public = ?2,
             signed_prekey_public = ?3,
             signed_prekey_signature = ?4
         WHERE device_id = ?1",
        params![
            authenticated_device_id,
            identity_exchange_public,
            signed_prekey_public,
            signed_prekey_signature
        ],
    )?;
    if changed == 0 {
        return Err(DbError::DeviceNotFound);
    }
    Ok(())
}

pub struct DevicePreKeyBundle {
    pub device_id: String,
    pub identity_public_key: String,
    pub identity_exchange_public: String,
    pub signed_prekey_public: String,
    pub signed_prekey_signature: String,
}

pub fn get_device_prekey_bundle(
    conn: &Connection,
    device_id: &str,
) -> Result<DevicePreKeyBundle, DbError> {
    conn.query_row(
        "SELECT device_id, identity_public_key, identity_exchange_public, signed_prekey_public, signed_prekey_signature
         FROM devices WHERE device_id = ?1",
        params![device_id],
        |row| {
            Ok(DevicePreKeyBundle {
                device_id: row.get(0)?,
                identity_public_key: row.get(1)?,
                identity_exchange_public: row.get(2)?.unwrap_or_default(),
                signed_prekey_public: row.get(3)?.unwrap_or_default(),
                signed_prekey_signature: row.get(4)?.unwrap_or_default(),
            })
        },
    )
    .optional()?
    .ok_or(DbError::DeviceNotFound)
}

// ---------------------------------------------------------------------
// One-time prekeys (SRS §6/§23)
// ---------------------------------------------------------------------

pub struct OneTimePreKeyRecord {
    pub prekey_id: String,
    pub public_key: String,
    pub signature: String,
}

pub fn publish_one_time_prekeys(
    conn: &Connection,
    device_id: &str,
    entries: &[(String, String, String)],
) -> Result<usize, DbError> {
    let exists: Option<String> = conn
        .query_row(
            "SELECT device_id FROM devices WHERE device_id = ?1",
            params![device_id],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Err(DbError::DeviceNotFound);
    }
    let tx = conn.unchecked_transaction()?;
    let mut count = 0;
    for (prekey_id, public_key, signature) in entries {
        count += tx.execute(
            "INSERT OR IGNORE INTO one_time_prekeys (prekey_id, device_id, public_key, signature, created_at, claimed_at)\
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![prekey_id, device_id, public_key, signature, now()],
        )?;
    }
    tx.commit()?;
    Ok(count)
}

pub fn claim_one_time_prekey(
    conn: &Connection,
    device_id: &str,
) -> Result<Option<OneTimePreKeyRecord>, DbError> {
    let tx = conn.unchecked_transaction()?;
    let candidate: Option<(String, String, String)> = tx
        .query_row(
            "SELECT prekey_id, public_key, signature FROM one_time_prekeys\
             WHERE device_id = ?1 AND claimed_at IS NULL ORDER BY created_at ASC LIMIT 1",
            params![device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((prekey_id, public_key, signature)) = candidate else {
        tx.commit()?;
        return Ok(None);
    };
    let changed = tx.execute(
        "UPDATE one_time_prekeys SET claimed_at = ?2\
         WHERE prekey_id = ?1 AND device_id = ?3 AND claimed_at IS NULL",
        params![prekey_id, now(), device_id],
    )?;
    tx.commit()?;
    if changed == 1 {
        Ok(Some(OneTimePreKeyRecord { prekey_id, public_key, signature }))
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------
// Maintenance (SRS §17/§18 bounded retention)
// ---------------------------------------------------------------------
pub fn reap_expired(conn: &Connection) -> Result<(), DbError> {
    let now_ts = now();
    conn.execute("DELETE FROM message_envelopes WHERE expires_at <= ?1", params![now_ts])?;
    conn.execute("DELETE FROM attachments WHERE expires_at <= ?1", params![now_ts])?;
    conn.execute("DELETE FROM auth_challenges WHERE expires_at <= ?1", params![now_ts])?;
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now_ts])?;
    Ok(())
}

// ---------------------------------------------------------------------
// Messaging (SRS §8, §16, §17)
// ---------------------------------------------------------------------

pub struct QueuedEnvelope {
    pub message_id: String,
    pub sender_device_id: String,
    pub ciphertext_blob: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
    pub protocol_version: u16,
}

/// Default queued-message TTL (SRS §8 "Expiration: Server MUST support
/// per-message TTL with conservative default retention").
pub const DEFAULT_MESSAGE_TTL_SECONDS: i64 = 14 * 24 * 3600;

/// Enqueues an opaque ciphertext envelope for later pickup. The server
/// never sees plaintext — `ciphertext_blob` is exactly what the sender's
/// crypto layer (`upm-core`, once implemented) produced.
pub fn enqueue_message(conn: &Connection, envelope: &MessageEnvelope) -> Result<String, DbError> {
    let message_id = envelope.message_id.to_hex();
    let sender_device_id = envelope.sender_device_id.to_hex();
    let recipient_device_id = envelope.recipient_device_id.to_hex();
    let created_at = envelope.server_timestamp as i64;
    let expires_at = envelope.expires_at as i64;
    if expires_at <= created_at {
        return Err(DbError::InvalidEnvelope);
    }

    let device_exists: Option<String> = conn
        .query_row(
            "SELECT device_id FROM devices WHERE device_id = ?1",
            params![recipient_device_id],
            |row| row.get(0),
        )
        .optional()?;
    if device_exists.is_none() {
        return Err(DbError::DeviceNotFound);
    }

    let sender_exists: Option<String> = conn
        .query_row(
            "SELECT device_id FROM devices WHERE device_id = ?1",
            params![sender_device_id],
            |row| row.get(0),
        )
        .optional()?;
    if sender_exists.is_none() {
        return Err(DbError::DeviceNotFound);
    }

    if let Some(existing) = conn
        .query_row(
            "SELECT sender_device_id, recipient_device_id, protocol_version, ciphertext_blob FROM message_envelopes WHERE message_id = ?1",
            params![message_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)? as u16, row.get::<_, Vec<u8>>(3)?)),
        )
        .optional()?
    {
        if existing.0 == sender_device_id
            && existing.1 == recipient_device_id
            && existing.2 == envelope.protocol_version.0
            && existing.3 == envelope.ciphertext
        {
            return Ok(message_id);
        }
        return Err(DbError::InvalidEnvelope);
    }
    let device_queue: i64 = conn.query_row(
        "SELECT COUNT(*) FROM message_envelopes WHERE recipient_device_id = ?1 AND delivery_state = 'queued'",
        params![recipient_device_id],
        |row| row.get(0),
    )?;
    let global_queue: i64 = conn.query_row(
        "SELECT COUNT(*) FROM message_envelopes WHERE delivery_state = 'queued'",
        [],
        |row| row.get(0),
    )?;
    if device_queue >= 10_000 || global_queue >= 100_000 {
        return Err(DbError::QueueQuotaExceeded);
    }

    conn.execute(
        "INSERT INTO message_envelopes
            (message_id, sender_device_id, recipient_device_id, ciphertext_blob, created_at, expires_at, delivery_state, protocol_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7)",
        params![
            message_id,
            sender_device_id,
            recipient_device_id,
            envelope.ciphertext,
            created_at,
            expires_at,
            envelope.protocol_version.0 as i64
        ],
    )?;
    Ok(message_id)
}

/// Fetches queued, unexpired envelopes for a device. Expired rows are
/// opportunistically reaped here rather than requiring a separate cron —
/// acceptable for the small single-node deployment this SRS targets.
pub fn pull_messages(conn: &Connection, device_id: &str) -> Result<Vec<QueuedEnvelope>, DbError> {
    let now_ts = now();
    conn.execute(
        "DELETE FROM message_envelopes WHERE expires_at < ?1",
        params![now_ts],
    )?;

    let mut stmt = conn.prepare(
        "SELECT message_id, sender_device_id, ciphertext_blob, created_at, expires_at, protocol_version
         FROM message_envelopes
         WHERE recipient_device_id = ?1 AND delivery_state = 'queued'
         ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map(params![device_id], |row| {
        Ok(QueuedEnvelope {
            message_id: row.get(0)?,
            sender_device_id: row.get(1)?,
            ciphertext_blob: row.get(2)?,
            created_at: row.get(3)?,
            expires_at: row.get(4)?,
            protocol_version: row.get::<_, i64>(5)? as u16,
        })
    })?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Acknowledges delivery. Per SRS §8, this deletes the server-side queued
/// ciphertext — it MUST NOT be represented as cryptographic erasure from
/// already-delivered endpoints, only as "the server no longer holds it".
pub fn ack_messages(
    conn: &Connection,
    authenticated_device_id: &str,
    message_ids: &[String],
) -> Result<usize, DbError> {
    let mut count = 0;
    for id in message_ids {
        count += conn.execute(
            "DELETE FROM message_envelopes
             WHERE message_id = ?1 AND recipient_device_id = ?2",
            params![id, authenticated_device_id],
        )?;
    }
    Ok(count)
}

// ---------------------------------------------------------------------
// Attachments (SRS §9, §16)
// ---------------------------------------------------------------------

fn hash_capability(capability: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(capability.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn attachment_capability_matches(record: &AttachmentRecord, capability: &str) -> bool {
    use sha2::{Digest, Sha256};
    if record.capability_hash.is_empty() {
        return false;
    }
    let digest = Sha256::digest(capability.as_bytes());
    let candidate: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    candidate == record.capability_hash
}

pub const DEFAULT_ATTACHMENT_TTL_SECONDS: i64 = 30 * 24 * 3600;

pub struct AttachmentSlot {
    pub attachment_id: String,
    pub storage_key: String,
    pub capability: String,
}

/// Creates an upload slot. This only records opaque metadata (size,
/// storage key). The encrypted blob is written separately by the HTTP API;
/// the server never interprets its contents.
pub fn create_attachment(
    conn: &Connection,
    owner_device_id: &str,
    opaque_size: i64,
) -> Result<AttachmentSlot, DbError> {
    let exists: Option<String> = conn
        .query_row(
            "SELECT device_id FROM devices WHERE device_id = ?1",
            params![owner_device_id],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Err(DbError::DeviceNotFound);
    }
    let attachment_id = random_hex(16);
    let storage_key = random_hex(24);
    let capability = random_hex(32);
    let capability_hash = hash_capability(&capability);
    let expires_at = now() + DEFAULT_ATTACHMENT_TTL_SECONDS;

    conn.execute(
        "INSERT INTO attachments (attachment_id, owner_message_id, owner_device_id, opaque_size, storage_key, capability_hash, expires_at)
         VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![attachment_id, owner_device_id, opaque_size, storage_key, capability_hash, expires_at],
    )?;
    Ok(AttachmentSlot {
        attachment_id,
        storage_key,
        capability,
    })
}

pub struct AttachmentRecord {
    pub attachment_id: String,
    pub owner_device_id: String,
    pub opaque_size: i64,
    pub storage_key: String,
    pub capability_hash: String,
    pub expires_at: i64,
    pub uploaded: bool,
}

pub fn get_attachment(conn: &Connection, attachment_id: &str) -> Result<Option<AttachmentRecord>, DbError> {
    Ok(conn.query_row(
        "SELECT attachment_id, owner_device_id, opaque_size, storage_key, capability_hash, expires_at, uploaded_at\
         FROM attachments WHERE attachment_id = ?1",
        params![attachment_id],
        |row| Ok(AttachmentRecord {
            attachment_id: row.get(0)?,
            owner_device_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            opaque_size: row.get(2)?,
            storage_key: row.get(3)?,
            expires_at: row.get(4)?,
            uploaded: row.get::<_, Option<i64>>(5)?.is_some(),
        }),
    ).optional()?)
}

pub fn mark_attachment_uploaded(
    conn: &Connection,
    attachment_id: &str,
    owner_device_id: &str,
) -> Result<bool, DbError> {
    Ok(conn.execute(
        "UPDATE attachments SET uploaded_at = ?3\
         WHERE attachment_id = ?1 AND owner_device_id = ?2 AND uploaded_at IS NULL",
        params![attachment_id, owner_device_id, now()],
    )? > 0)
}

pub fn delete_attachment(
    conn: &Connection,
    owner_device_id: &str,
    attachment_id: &str,
) -> Result<bool, DbError> {
    let affected = conn.execute(
        "DELETE FROM attachments WHERE attachment_id = ?1 AND owner_device_id = ?2",
        params![attachment_id, owner_device_id],
    )?;
    Ok(affected > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn register_then_resolve_roundtrip() {
        let conn = mem_db();
        let acc = register_account(&conn, "max", "pubkey-base64").unwrap();
        assert!(!acc.user_id.is_empty());
        assert_eq!(acc.upm_id.len(), 14); // "XXXX-XXXX-XXXX"

        let entry = resolve_username(&conn, "MAX")
            .unwrap()
            .expect("case-insensitive resolve");
        assert_eq!(entry.username, "max");
        assert_eq!(entry.identity_public_key, "pubkey-base64");
    }

    #[test]
    fn directory_visibility_can_hide_and_restore_lookup() {
        let conn = mem_db();
        let acc = register_account(&conn, "alice", "k").unwrap();
        assert!(resolve_username(&conn, "alice").unwrap().is_some());
        set_directory_visibility(&conn, &acc.device_id, false).unwrap();
        assert!(!get_directory_visibility(&conn, &acc.device_id).unwrap());
        assert!(resolve_username(&conn, "alice").unwrap().is_none());
        set_directory_visibility(&conn, &acc.device_id, true).unwrap();
        assert!(resolve_username(&conn, "alice").unwrap().is_some());
    }

    #[test]
    fn duplicate_username_rejected() {
        let conn = mem_db();
        register_account(&conn, "max", "k1").unwrap();
        let err = register_account(&conn, "Max", "k2").unwrap_err();
        assert!(matches!(err, DbError::UsernameTaken));
    }

    #[test]
    fn message_enqueue_pull_ack_lifecycle() {
        let conn = mem_db();
        let acc = register_account(&conn, "alice", "k").unwrap();
        let msg_id = enqueue_message(&conn, &MessageEnvelope {
            protocol_version: ProtocolVersion::CURRENT,
            message_id: upm_protocol::MessageId::from_hex("00112233445566778899AABBCCDDEEFF").unwrap(),
            sender_device_id: upm_protocol::DeviceId::from_hex(&acc.device_id).unwrap(),
            recipient_device_id: upm_protocol::DeviceId::from_hex(&acc.device_id).unwrap(),
            ciphertext: b"opaque-ciphertext".to_vec(),
            server_timestamp: now() as u64,
            expires_at: (now() + 3600) as u64,
        }).unwrap();

        let pulled = pull_messages(&conn, &acc.device_id).unwrap();
        assert_eq!(pulled.len(), 1);
        assert_eq!(pulled[0].message_id, msg_id);
        assert_eq!(pulled[0].ciphertext_blob, b"opaque-ciphertext");

        let acked = ack_messages(&conn, &acc.device_id, &[msg_id]).unwrap();
        assert_eq!(acked, 1);
        assert!(pull_messages(&conn, &acc.device_id).unwrap().is_empty());
    }

    #[test]
    fn ack_cannot_delete_another_devices_message() {
        let conn = mem_db();
        let alice = register_account(&conn, "alice", "k1").unwrap();
        let bob = register_account(&conn, "bob", "k2").unwrap();
        let msg_id = enqueue_message(
            &conn,
            &MessageEnvelope {
                protocol_version: ProtocolVersion::CURRENT,
                message_id: upm_protocol::MessageId::from_hex("00112233445566778899AABBCCDDEEFF").unwrap(),
                sender_device_id: upm_protocol::DeviceId::from_hex(&alice.device_id).unwrap(),
                recipient_device_id: upm_protocol::DeviceId::from_hex(&bob.device_id).unwrap(),
                ciphertext: b"opaque-ciphertext".to_vec(),
                server_timestamp: now() as u64,
                expires_at: (now() + 3600) as u64,
            },
        )
        .unwrap();

        assert_eq!(ack_messages(&conn, &alice.device_id, &[msg_id.clone()]).unwrap(), 0);
        assert_eq!(pull_messages(&conn, &bob.device_id).unwrap().len(), 1);
        assert_eq!(ack_messages(&conn, &bob.device_id, &[msg_id]).unwrap(), 1);
    }

    #[test]
    fn device_key_refresh_is_bound_to_device() {
        let conn = mem_db();
        let acc = register_account(&conn, "alice", "ed-key").unwrap();
        update_device_keys(&conn, &acc.device_id, "x" , "spk", "sig").unwrap();
        let stored: (String, String, String) = conn
            .query_row(
                "SELECT identity_exchange_public, signed_prekey_public, signed_prekey_signature FROM devices WHERE device_id = ?1",
                params![acc.device_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored, ("x".into(), "spk".into(), "sig".into()));
    }

    #[test]
    fn expired_messages_are_not_pulled() {
        let conn = mem_db();
        let acc = register_account(&conn, "bob", "k").unwrap();
        let envelope = MessageEnvelope {
            protocol_version: ProtocolVersion::CURRENT,
            message_id: upm_protocol::MessageId::from_hex("00112233445566778899AABBCCDDEEFF").unwrap(),
            sender_device_id: upm_protocol::DeviceId::from_hex(&acc.device_id).unwrap(),
            recipient_device_id: upm_protocol::DeviceId::from_hex(&acc.device_id).unwrap(),
            ciphertext: b"stale".to_vec(),
            server_timestamp: now() as u64,
            expires_at: (now() - 1) as u64,
        };
        enqueue_message(&conn, &envelope).unwrap();
        assert!(pull_messages(&conn, &acc.device_id).unwrap().is_empty());
    }

    #[test]
    fn enqueue_to_unknown_device_fails_closed() {
        let conn = mem_db();
        let sender = register_account(&conn, "alice", "k").unwrap();
        let err = enqueue_message(&conn, &MessageEnvelope {
            protocol_version: ProtocolVersion::CURRENT,
            message_id: upm_protocol::MessageId::from_hex("00112233445566778899AABBCCDDEEFF").unwrap(),
            sender_device_id: upm_protocol::DeviceId::from_hex(&sender.device_id).unwrap(),
            recipient_device_id: upm_protocol::DeviceId([0u8; 16]),
            ciphertext: b"x".to_vec(),
            server_timestamp: now() as u64,
            expires_at: (now() + 3600) as u64,
        }).unwrap_err();
        assert!(matches!(err, DbError::DeviceNotFound));
    }

    #[test]
    fn attachment_slot_lifecycle() {
        let conn = mem_db();
        let acc = register_account(&conn, "alice", "k").unwrap();
        let slot = create_attachment(&conn, &acc.device_id, 1024).unwrap();
        let record = get_attachment(&conn, &slot.attachment_id).unwrap().unwrap();
        assert!(attachment_capability_matches(&record, &slot.capability));
        assert!(!attachment_capability_matches(&record, "wrong-capability"));
        assert!(delete_attachment(&conn, &acc.device_id, &slot.attachment_id).unwrap());
        assert!(!delete_attachment(&conn, &acc.device_id, &slot.attachment_id).unwrap());
    }
}
