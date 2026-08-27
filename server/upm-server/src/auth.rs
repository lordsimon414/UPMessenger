//! Device authentication (closing the Phase 1 gap: previously any caller
//! who knew a `device_id` could send/pull/ack as that device).
//!
//! UPM has no passwords (SRS §7: no phone/email, identity is a key pair).
//! So authentication is a signature challenge against the same Ed25519
//! identity key already stored for the device at registration time:
//!
//!   1. `POST /v1/auth/challenge {device_id}` -> server stores a random,
//!      short-lived nonce for that device and returns it.
//!   2. Client signs the nonce with its identity private key (client-side,
//!      never sent to the server).
//!   3. `POST /v1/auth/verify {device_id, signature_base64}` -> server
//!      verifies the signature with `upm_crypto::verify` against the
//!      device's stored public key, consumes the (one-time) challenge, and
//!      issues an opaque bearer session token.
//!
//! This reuses the exact primitive already defined for message
//! authentication (SRS §6) rather than inventing a second auth scheme.

use crate::util::decode_fixed;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

pub const CHALLENGE_TTL_SECONDS: i64 = 120;
pub const SESSION_TTL_SECONDS: i64 = 30 * 24 * 3600;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("unknown device")]
    UnknownDevice,
    #[error("no active challenge for this device (request one first)")]
    NoChallenge,
    #[error("challenge expired, request a new one")]
    ChallengeExpired,
    #[error("signature does not verify against the device's identity key")]
    InvalidSignature,
    #[error("malformed base64 in signature or stored key material")]
    Malformed,
    #[error("session token is invalid or expired")]
    InvalidSession,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS auth_challenges (
            device_id  TEXT PRIMARY KEY REFERENCES devices(device_id),
            challenge  BLOB NOT NULL,
            expires_at INTEGER NOT NULL
        );
        "#,
    )?;

    let has_plaintext_token: bool = conn
        .prepare("PRAGMA table_info(sessions)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "token");

    if has_plaintext_token {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let migration = (|| -> rusqlite::Result<()> {
            conn.execute_batch(
                "CREATE TABLE sessions_migrated (
                    token_hash TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL REFERENCES devices(device_id),
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )",
            )?;
            let tokens: Vec<(String, String, i64, i64)> = {
                let mut stmt = conn.prepare(
                    "SELECT token, device_id, created_at, expires_at FROM sessions",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()?
            };
            for (token, device_id, created_at, expires_at) in tokens {
                conn.execute(
                    "INSERT INTO sessions_migrated (token_hash, device_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                    params![token_digest(&token), device_id, created_at, expires_at],
                )?;
            }
            conn.execute_batch(
                "DROP TABLE sessions;
                 ALTER TABLE sessions_migrated RENAME TO sessions;
                 CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);",
            )?;
            Ok(())
        })();
        match migration {
            Ok(()) => conn.execute_batch("COMMIT")?,
            Err(err) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(err);
            }
        }
    } else {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                device_id  TEXT NOT NULL REFERENCES devices(device_id),
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);
            "#,
        )?;
    }
    Ok(())
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

fn random_token() -> String {
    random_bytes(32)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn token_digest(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Issues (or replaces) a one-time challenge nonce for `device_id`.
pub fn issue_challenge(conn: &Connection, device_id: &str) -> Result<Vec<u8>, AuthError> {
    let exists: Option<String> = conn
        .query_row(
            "SELECT device_id FROM devices WHERE device_id = ?1",
            params![device_id],
            |r| r.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Err(AuthError::UnknownDevice);
    }

    let challenge = random_bytes(32);
    let expires_at = now() + CHALLENGE_TTL_SECONDS;
    conn.execute(
        "INSERT INTO auth_challenges (device_id, challenge, expires_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(device_id) DO UPDATE SET challenge = excluded.challenge, expires_at = excluded.expires_at",
        params![device_id, challenge, expires_at],
    )?;
    Ok(challenge)
}

/// Verifies a signature over the outstanding challenge and, on success,
/// issues a new bearer session token. Fails closed and consumes the
/// challenge on both success and verified failure, so a signature can't be
/// replayed against the same nonce twice.
pub fn verify_and_issue_session(
    conn: &Connection,
    device_id: &str,
    signature_base64: &str,
) -> Result<(String, i64), AuthError> {
    let row: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT challenge, expires_at FROM auth_challenges WHERE device_id = ?1",
            params![device_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (challenge, expires_at) = row.ok_or(AuthError::NoChallenge)?;

    // One-time use: remove immediately regardless of outcome.
    conn.execute(
        "DELETE FROM auth_challenges WHERE device_id = ?1",
        params![device_id],
    )?;

    if now() > expires_at {
        return Err(AuthError::ChallengeExpired);
    }

    let identity_public_key_b64: Option<String> = conn
        .query_row(
            "SELECT identity_public_key FROM devices WHERE device_id = ?1",
            params![device_id],
            |r| r.get(0),
        )
        .optional()?;
    let identity_public_key_b64 = identity_public_key_b64.ok_or(AuthError::UnknownDevice)?;

    let public_key: [u8; 32] =
        decode_fixed(&identity_public_key_b64).ok_or(AuthError::Malformed)?;
    let signature: [u8; 64] = decode_fixed(signature_base64).ok_or(AuthError::Malformed)?;

    upm_crypto::verify(&public_key, &challenge, &signature)
        .map_err(|_| AuthError::InvalidSignature)?;

    let token = random_token();
    let created_at = now();
    let session_expires_at = created_at + SESSION_TTL_SECONDS;
    let token_hash = token_digest(&token);
    conn.execute(
        "INSERT INTO sessions (token_hash, device_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash, device_id, created_at, session_expires_at],
    )?;
    Ok((token, session_expires_at))
}

/// Resolves a bearer token to the device it authenticates, failing closed
/// on anything expired, unknown, or malformed.
pub fn authenticate(conn: &Connection, token: &str) -> Result<String, AuthError> {
    if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(AuthError::InvalidSession);
    }
    let row: Option<(String, i64)> = conn
        .query_row(
            "SELECT device_id, expires_at FROM sessions WHERE token_hash = ?1",
            params![token_digest(token)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (device_id, expires_at) = row.ok_or(AuthError::InvalidSession)?;
    if now() > expires_at {
        conn.execute("DELETE FROM sessions WHERE token_hash = ?1", params![token_digest(token)])?;
        return Err(AuthError::InvalidSession);
    }
    Ok(device_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::base64_encode;
    use upm_crypto::IdentityKeyPair;

    fn mem_db_with_device() -> (Connection, IdentityKeyPair, String) {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema_for_tests(&conn).unwrap();
        init_schema(&conn).unwrap();

        let kp = IdentityKeyPair::generate();
        let device_id = "test-device".to_string();
        conn.execute(
            "INSERT INTO users (user_id, upm_id, username, username_normalized, created_at) \
             VALUES ('u1','UPM1-UPM1-UPM1','alice','alice',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO devices (device_id, user_id, identity_public_key) VALUES (?1, 'u1', ?2)",
            params![device_id, base64_encode(&kp.public_key())],
        )
        .unwrap();
        (conn, kp, device_id)
    }

    #[test]
    fn full_challenge_response_roundtrip() {
        let (conn, kp, device_id) = mem_db_with_device();
        let challenge = issue_challenge(&conn, &device_id).unwrap();
        let signature = kp.sign(&challenge);
        let (token, _exp) =
            verify_and_issue_session(&conn, &device_id, &base64_encode(&signature)).unwrap();

        let resolved = authenticate(&conn, &token).unwrap();
        assert_eq!(resolved, device_id);
    }

    #[test]
    fn wrong_signature_is_rejected() {
        let (conn, _kp, device_id) = mem_db_with_device();
        issue_challenge(&conn, &device_id).unwrap();
        let bogus_sig = base64_encode(&[0u8; 64]);
        let err = verify_and_issue_session(&conn, &device_id, &bogus_sig).unwrap_err();
        assert!(matches!(err, AuthError::InvalidSignature));
    }

    #[test]
    fn challenge_is_one_time_use() {
        let (conn, kp, device_id) = mem_db_with_device();
        let challenge = issue_challenge(&conn, &device_id).unwrap();
        let signature = base64_encode(&kp.sign(&challenge));
        verify_and_issue_session(&conn, &device_id, &signature).unwrap();

        // Replaying the same signature after the challenge was consumed:
        let err = verify_and_issue_session(&conn, &device_id, &signature).unwrap_err();
        assert!(matches!(err, AuthError::NoChallenge));
    }

    #[test]
    fn session_token_is_stored_only_as_a_hash() {
        let (conn, kp, device_id) = mem_db_with_device();
        let challenge = issue_challenge(&conn, &device_id).unwrap();
        let signature = base64_encode(&kp.sign(&challenge));
        let (token, _) = verify_and_issue_session(&conn, &device_id, &signature).unwrap();

        let plain_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'token'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(plain_count, 0);
        let stored_hash: String = conn
            .query_row("SELECT token_hash FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored_hash, token_digest(&token));
        assert_ne!(stored_hash, token);
    }

    #[test]
    fn unknown_token_fails_closed() {
        let (conn, _kp, _device_id) = mem_db_with_device();
        let err = authenticate(
            &conn,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::InvalidSession));
    }
}
