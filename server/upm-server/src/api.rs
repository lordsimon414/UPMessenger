//! HTTP API surface (SRS §16). Endpoint names/shapes are illustrative
//! contracts per the SRS ("the implementation MAY choose equivalent RPC
//! names provided semantics remain identical") — this is a straightforward
//! Phase 1 realization of them.
//!
//! Every handler returns JSON and never reflects back sensitive input in
//! error messages (SRS §16: "Server errors SHALL avoid reflecting
//! sensitive input").
//!
//! # Authentication
//! Registration, directory resolution and public profile lookups are
//! intentionally open (that's the point of a directory). Everything that
//! acts on behalf of a specific device — sending, pulling, acking,
//! attachment slots, adding a new device key — requires a bearer session
//! token obtained via `/v1/auth/challenge` + `/v1/auth/verify` (see
//! `auth.rs`). Pull/ack are further restricted to the authenticated
//! device's own queue.

use crate::auth::{self, AuthError};
use crate::db::{self, DbError};
use crate::util::{base64_decode, base64_encode, decode_fixed};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response};
use upm_protocol::{DeviceId, MessageEnvelope, MessageId, ProtocolVersion};

pub struct AppState {
    pub db: Mutex<Connection>,
    pub attachment_dir: PathBuf,
    pub ip_limiter: crate::ratelimit::RateLimiter,
    pub register_limiter: crate::ratelimit::RateLimiter,
    pub auth_limiter: crate::ratelimit::RateLimiter,
}

/// Identifies the caller for rate-limiting purposes. Prefers the
/// `CF-Connecting-IP` header set by Cloudflare Tunnel (SRS §10.1's
/// deployment model) since, behind that tunnel, `remote_addr()` is just
/// the tunnel's local connection and doesn't distinguish real clients.
/// Falls back to the raw peer address for direct/local access (e.g. during
/// development, or the `upm-smoke` tool hitting the server directly).
fn client_key(request: &Request) -> String {
    let header = request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("CF-Connecting-IP"))
        .map(|h| h.value.as_str().trim().to_string());
    if let Some(ip) = header {
        if !ip.is_empty() {
            return ip;
        }
    }
    request.remote_addr().map(|a| a.ip().to_string()).unwrap_or_else(|| "unknown".to_string())
}

/// Minimal, dependency-free access log: timestamp (Unix seconds), method,
/// path, status. Deliberately omits query strings, client IP, and body
/// content — those can carry usernames, device IDs, or tokens, and the
/// project's stated metadata-minimization stance (SRS §13) argues against
/// logging more than needed to see the server is behaving. Correlate with
/// `CF-Connecting-IP`/tunnel-level logs if per-client debugging is ever
/// needed for abuse investigation.
fn log_line(method: &Method, path: &str, status: u16) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    println!("{now} {method:?} {path} {status}");
}

pub fn handle(state: &AppState, mut request: Request) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let bearer = extract_bearer(&request);
    let key = client_key(&request);
    let path = url.split('?').next().unwrap_or("");
    let segments: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();

    if !state.ip_limiter.check(&key) {
        log_line(&method, path, 429);
        let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header is valid");
        let response = Response::from_string(error(429, "rate_limited", "too many requests, slow down").1)
            .with_status_code(429).with_header(header);
        let _ = request.respond(response);
        return;
    }

    if segments.len() == 4 && segments[0] == "v1" && segments[1] == "attachments" && segments[3] == "blob" {
        let auth_result = require_auth(state, bearer.as_deref());
        match auth_result {
            Ok(device_id) => {
                let capability = request.headers().iter().find(|h| {
                    h.field.as_str().as_str().eq_ignore_ascii_case("X-UPM-Attachment-Capability")
                }).map(|h| h.value.as_str().trim().to_string());
                let result = match method {
                    Method::Put => handle_attachment_upload(state, &segments[2].to_ascii_uppercase(), &device_id, &mut request),
                    Method::Get => handle_attachment_download(state, &segments[2].to_ascii_uppercase(), &device_id, capability.as_deref()),
                    _ => (405, Vec::new()),
                };
                log_line(&method, path, result.0);
                let response = Response::from_data(result.1).with_status_code(result.0);
                let _ = request.respond(response);
            }
            Err((status, body)) => {
                log_line(&method, path, status);
                let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header is valid");
                let response = Response::from_string(body).with_status_code(status).with_header(header);
                let _ = request.respond(response);
            }
        }
        return;
    }

    const MAX_JSON_BODY_BYTES: u64 = 2 * 1024 * 1024;
    let mut raw_body = Vec::new();
    if request.as_reader().take(MAX_JSON_BODY_BYTES + 1).read_to_end(&mut raw_body).is_err() {
        log_line(&method, path, 400);
        let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header is valid");
        let response = Response::from_string(error(400, "bad_request", "request body could not be read").1)
            .with_status_code(400).with_header(header);
        let _ = request.respond(response);
        return;
    }
    if raw_body.len() as u64 > MAX_JSON_BODY_BYTES {
        log_line(&method, path, 413);
        let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header is valid");
        let response = Response::from_string(error(413, "request_too_large", "request body exceeds limit").1)
            .with_status_code(413).with_header(header);
        let _ = request.respond(response);
        return;
    }
    let body = match String::from_utf8(raw_body) {
        Ok(body) => body,
        Err(_) => {
            log_line(&method, path, 400);
            let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header is valid");
            let response = Response::from_string(error(400, "bad_request", "request body must be UTF-8 JSON").1)
                .with_status_code(400).with_header(header);
            let _ = request.respond(response);
            return;
        }
    };

    let (status, json_body) = route(state, &method, &url, &body, bearer.as_deref(), &key);
    log_line(&method, path, status);

    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header is valid");
    let response = Response::from_string(json_body)
        .with_status_code(status)
        .with_header(header);
    let _ = request.respond(response);
}

fn extract_bearer(request: &Request) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| {
            h.field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("Authorization")
        })
        .and_then(|h| {
            let v = h.value.as_str();
            v.strip_prefix("Bearer ").map(|s| s.trim().to_string())
        })
}

/// Resolves the bearer token (if any) to an authenticated device_id, or an
/// error response ready to return. Handlers that require auth call this
/// first and propagate the `Err` variant directly.
fn require_auth(state: &AppState, bearer: Option<&str>) -> Result<String, (u16, String)> {
    let token = bearer.ok_or_else(|| error(401, "unauthorized", "missing bearer session token"))?;
    let conn = state.db.lock().expect("db mutex poisoned");
    auth::authenticate(&conn, token)
        .map_err(|_| error(401, "unauthorized", "invalid or expired session token"))
}

fn route(
    state: &AppState,
    method: &Method,
    url: &str,
    body: &str,
    bearer: Option<&str>,
    client_key: &str,
) -> (u16, String) {
    let path = url.split('?').next().unwrap_or("");
    let segments: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let seg: Vec<&str> = segments.iter().map(|s| *s).collect();

    match (method, seg.as_slice()) {
        // Open endpoints.
        (Method::Post, ["v1", "account", "register"]) => {
            if !state.register_limiter.check(client_key) {
                return error(429, "rate_limited", "too many registration attempts, try again later");
            }
            handle_register(state, body)
        }
        (Method::Get, ["v1", "directory", "resolve", username]) => handle_resolve(state, username),
        (Method::Get, ["v1", "directory", "resolve-id", upm_id]) => handle_resolve_upm_id(state, upm_id),
        (Method::Get, ["v1", "profile", "public", username]) => {
            handle_public_profile(state, username)
        }
        (Method::Post, ["v1", "auth", "challenge"]) => {
            if !state.auth_limiter.check(&auth_rate_limit_key(body)) {
                return error(429, "rate_limited", "too many auth attempts, try again later");
            }
            handle_auth_challenge(state, body)
        }
        (Method::Post, ["v1", "auth", "verify"]) => {
            if !state.auth_limiter.check(&auth_rate_limit_key(body)) {
                return error(429, "rate_limited", "too many auth attempts, try again later");
            }
            handle_auth_verify(state, body)
        }
        (Method::Delete, ["v1", "auth", "session"]) => match require_auth(state, bearer) {
            Ok(_) => handle_logout(state, bearer.unwrap_or("")),
            Err(e) => e,
        },
        (Method::Post, ["v1", "profile", "privacy"]) => match require_auth(state, bearer) {
            Ok(device) => handle_profile_privacy(state, body, &device),
            Err(e) => e,
        },

        // Authenticated endpoints.
        (Method::Get, ["v1", "devices", "keys", device_id]) => handle_get_device_keys(state, device_id),
        (Method::Post, ["v1", "devices", "keys"]) => match require_auth(state, bearer) {
            Ok(authenticated_device) => handle_publish_keys(state, body, &authenticated_device),
            Err(e) => e,
        },
        (Method::Post, ["v1", "devices", "prekeys"]) => match require_auth(state, bearer) {
            Ok(authenticated_device) => handle_publish_one_time_prekeys(state, body, &authenticated_device),
            Err(e) => e,
        },
        (Method::Post, ["v1", "devices", "prekeys", "claim"]) => match require_auth(state, bearer) {
            Ok(_authenticated_device) => handle_claim_one_time_prekey(state, body),
            Err(e) => e,
        },
        (Method::Post, ["v1", "messages", "send"]) => match require_auth(state, bearer) {
            Ok(sender_device) => handle_send(state, body, &sender_device),
            Err(e) => e,
        },
        (Method::Get, ["v1", "messages", "pull"]) => match require_auth(state, bearer) {
            Ok(authenticated_device) => handle_pull(state, url, &authenticated_device),
            Err(e) => e,
        },
        (Method::Post, ["v1", "messages", "ack"]) => match require_auth(state, bearer) {
            Ok(authenticated_device) => handle_ack(state, body, &authenticated_device),
            Err(e) => e,
        },
        (Method::Post, ["v1", "attachments", "create"]) => match require_auth(state, bearer) {
            Ok(authenticated_device) => handle_attachment_create(state, body, &authenticated_device),
            Err(e) => e,
        },
        (Method::Delete, ["v1", "attachments", id]) => match require_auth(state, bearer) {
            Ok(authenticated_device) => handle_attachment_delete(state, id, &authenticated_device),
            Err(e) => e,
        },

        _ => error(404, "not_found", "no such endpoint"),
    }
}

/// Extracts `device_id` from an auth-challenge/verify JSON body for
/// rate-limit keying, without needing to fully typed-parse the request
/// twice. Malformed bodies still get *a* key (so they're bucketed and
/// rate-limited together) rather than bypassing the limiter outright.
fn auth_rate_limit_key(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("device_id").and_then(|d| d.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| "malformed".to_string())
}

fn error(status: u16, code: &str, message: &str) -> (u16, String) {
    (
        status,
        json!({ "error": { "code": code, "message": message } }).to_string(),
    )
}

fn ok(status: u16, body: serde_json::Value) -> (u16, String) {
    (status, body.to_string())
}

fn query_param<'a>(url: &'a str, key: &str) -> Option<&'a str> {
    let query = url.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some(key) {
            return it.next();
        }
    }
    None
}

/// Validates that a client-supplied string is a base64-encoded 32-byte
/// Ed25519 public key before it's ever stored (SRS §6 boundary discipline:
/// garbage keys should fail loudly at the edge, not silently at first use).
fn valid_public_key(candidate: &str) -> bool {
    decode_fixed::<32>(candidate).is_some()
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------
// POST /v1/account/register — AC-01
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    identity_public_key: String,
}

fn handle_register(state: &AppState, body: &str) -> (u16, String) {
    let req: RegisterRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid registration payload"),
    };

    if req.username.len() < 3 || req.username.len() > 32 {
        return error(400, "invalid_username", "username must be 3-32 characters");
    }
    if !valid_public_key(&req.identity_public_key) {
        return error(
            400,
            "invalid_key",
            "identity_public_key must be a base64-encoded 32-byte Ed25519 key",
        );
    }

    let conn = state.db.lock().expect("db mutex poisoned");
    match db::register_account(&conn, &req.username, &req.identity_public_key) {
        Ok(acc) => ok(
            201,
            json!({ "user_id": acc.user_id, "upm_id": acc.upm_id, "device_id": acc.device_id }),
        ),
        Err(DbError::UsernameTaken) => {
            error(409, "username_taken", "username is already registered")
        }
        Err(_) => error(500, "internal_error", "registration failed"),
    }
}

// ---------------------------------------------------------------------
// GET /v1/directory/resolve/{username} — AC-02
// ---------------------------------------------------------------------

fn handle_resolve(state: &AppState, username: &str) -> (u16, String) {
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::resolve_username(&conn, username) {
        Ok(Some(entry)) => ok(
            200,
            json!({ "upm_id": entry.upm_id, "username": entry.username, "device_id": entry.device_id, "identity_public_key": entry.identity_public_key }),
        ),
        Ok(None) => error(404, "not_found", "no such username"),
        Err(_) => error(500, "internal_error", "resolve failed"),
    }
}
fn handle_resolve_upm_id(state: &AppState, upm_id: &str) -> (u16, String) {
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::resolve_upm_id(&conn, upm_id) {
        Ok(Some(entry)) => ok(
            200,
            json!({ "upm_id": entry.upm_id, "username": entry.username, "device_id": entry.device_id, "identity_public_key": entry.identity_public_key }),
        ),
        Ok(None) => error(404, "not_found", "no such UPM ID"),
        Err(_) => error(500, "internal_error", "resolve failed"),
    }
}


// ---------------------------------------------------------------------
// POST /v1/auth/challenge, POST /v1/auth/verify
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct ChallengeRequest {
    device_id: String,
}

fn handle_auth_challenge(state: &AppState, body: &str) -> (u16, String) {
    let req: ChallengeRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid challenge payload"),
    };

    let conn = state.db.lock().expect("db mutex poisoned");
    match auth::issue_challenge(&conn, &req.device_id) {
        Ok(challenge) => ok(
            200,
            json!({ "challenge_base64": base64_encode(&challenge), "ttl_seconds": auth::CHALLENGE_TTL_SECONDS }),
        ),
        Err(AuthError::UnknownDevice) => error(404, "device_not_found", "unknown device_id"),
        Err(_) => error(500, "internal_error", "challenge issuance failed"),
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    device_id: String,
    signature_base64: String,
}

fn handle_auth_verify(state: &AppState, body: &str) -> (u16, String) {
    let req: VerifyRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid verify payload"),
    };

    let conn = state.db.lock().expect("db mutex poisoned");
    match auth::verify_and_issue_session(&conn, &req.device_id, &req.signature_base64) {
        Ok((token, expires_at)) => ok(
            200,
            json!({ "session_token": token, "expires_at": expires_at }),
        ),
        Err(AuthError::InvalidSignature) => {
            error(401, "invalid_signature", "signature does not verify")
        }
        Err(AuthError::NoChallenge) => error(400, "no_challenge", "request a challenge first"),
        Err(AuthError::ChallengeExpired) => error(
            400,
            "challenge_expired",
            "challenge expired, request a new one",
        ),
        Err(AuthError::Malformed) => error(400, "bad_request", "malformed signature or stored key"),
        Err(AuthError::UnknownDevice) => error(404, "device_not_found", "unknown device_id"),
        Err(_) => error(500, "internal_error", "verification failed"),
    }
}

fn handle_logout(state: &AppState, token: &str) -> (u16, String) {
    let conn = state.db.lock().expect("db mutex poisoned");
    match auth::revoke_session(&conn, token) {
        Ok(()) => ok(200, json!({ "logged_out": true })),
        Err(_) => error(401, "unauthorized", "session could not be revoked"),
    }
}

#[derive(Deserialize)]
struct PrivacyRequest { directory_visible: bool }

fn handle_profile_privacy(state: &AppState, body: &str, authenticated_device: &str) -> (u16, String) {
    let req: PrivacyRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid privacy payload"),
    };
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::set_directory_visibility(&conn, authenticated_device, req.directory_visible) {
        Ok(()) => ok(200, json!({ "directory_visible": req.directory_visible })),
        Err(DbError::DeviceNotFound) => error(404, "device_not_found", "authenticated device not found"),
        Err(_) => error(500, "internal_error", "privacy setting update failed"),
    }
}

// ---------------------------------------------------------------------
// POST /v1/devices/keys — refreshes the authenticated device's X3DH bundle.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct PublishKeysRequest {
    identity_exchange_public: String,
    signed_prekey_public: String,
    signed_prekey_signature: String,
}

fn valid_fixed_key(candidate: &str) -> bool {
    decode_fixed::<32>(candidate).is_some()
}

fn valid_signature(candidate: &str) -> bool {
    decode_fixed::<64>(candidate).is_some()
}


fn handle_publish_keys(state: &AppState, body: &str, authenticated_device: &str) -> (u16, String) {
    let req: PublishKeysRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid key payload"),
    };
    if !valid_fixed_key(&req.identity_exchange_public)
        || !valid_fixed_key(&req.signed_prekey_public)
        || !valid_signature(&req.signed_prekey_signature)
    {
        return error(400, "invalid_key_bundle", "invalid X3DH device key material");
    }

    let conn = state.db.lock().expect("db mutex poisoned");
    let identity_public_key = match db::get_device_identity_public_key(&conn, authenticated_device) {
        Ok(key) => key,
        Err(DbError::DeviceNotFound) => return error(404, "device_not_found", "unknown authenticated device"),
        Err(_) => return error(500, "internal_error", "key publication failed"),
    };
    let identity_public_key: [u8; 32] = match decode_fixed(&identity_public_key) {
        Some(key) => key,
        None => return error(500, "internal_error", "stored device identity key is invalid"),
    };
    let identity_exchange_public: [u8; 32] = match decode_fixed(&req.identity_exchange_public) {
        Some(key) => key,
        None => return error(400, "invalid_key_bundle", "invalid X3DH device key material"),
    };
    let signed_prekey_public: [u8; 32] = match decode_fixed(&req.signed_prekey_public) {
        Some(key) => key,
        None => return error(400, "invalid_key_bundle", "invalid X3DH device key material"),
    };
    let signature: [u8; 64] = match decode_fixed(&req.signed_prekey_signature) {
        Some(sig) => sig,
        None => return error(400, "invalid_key_bundle", "invalid X3DH device key material"),
    };
    let mut signed_message = Vec::with_capacity(21 + 32 + 32);
    signed_message.extend_from_slice(b"UPM/v4/signed-prekey/");
    signed_message.extend_from_slice(&identity_exchange_public);
    signed_message.extend_from_slice(&signed_prekey_public);
    if upm_crypto::verify(&identity_public_key, &signed_message, &signature).is_err() {
        return error(400, "invalid_key_bundle", "X3DH prekey signature does not match device identity");
    }

    match db::update_device_keys(
        &conn,
        authenticated_device,
        &req.identity_exchange_public,
        &req.signed_prekey_public,
        &req.signed_prekey_signature,
    ) {
        Ok(()) => ok(200, json!({ "device_id": authenticated_device })),
        Err(DbError::DeviceNotFound) => error(404, "device_not_found", "unknown authenticated device"),
        Err(_) => error(500, "internal_error", "key publication failed"),
    }
}

#[derive(Deserialize)]
struct PublishOneTimePreKeysRequest {
    prekeys: Vec<PublishOneTimePreKeyItem>,
}

#[derive(Deserialize)]
struct PublishOneTimePreKeyItem {
    prekey_id: String,
    public_key: String,
    signature: String,
}

fn handle_publish_one_time_prekeys(state: &AppState, body: &str, authenticated_device: &str) -> (u16, String) {
    let req: PublishOneTimePreKeysRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid one-time prekey payload"),
    };
    if req.prekeys.is_empty() || req.prekeys.len() > 128 {
        return error(400, "invalid_prekeys", "one-time prekey batch size is invalid");
    }
    let conn = state.db.lock().expect("db mutex poisoned");
    let identity_public_key = match db::get_device_identity_public_key(&conn, authenticated_device) {
        Ok(key) => key,
        Err(DbError::DeviceNotFound) => return error(404, "device_not_found", "unknown authenticated device"),
        Err(_) => return error(500, "internal_error", "one-time prekey publication failed"),
    };
    let identity_public_key: [u8; 32] = match decode_fixed(&identity_public_key) {
        Some(key) => key,
        None => return error(500, "internal_error", "stored device identity key is invalid"),
    };
    let mut entries = Vec::with_capacity(req.prekeys.len());
    for item in &req.prekeys {
        let id = match upm_protocol::PreKeyId::from_hex(&item.prekey_id) {
            Some(id) => id,
            None => return error(400, "invalid_prekey", "invalid one-time prekey id"),
        };
        let public_key = match decode_fixed::<32>(&item.public_key) {
            Some(key) => key,
            None => return error(400, "invalid_prekey", "invalid one-time prekey public key"),
        };
        let signature = match decode_fixed::<64>(&item.signature) {
            Some(sig) => sig,
            None => return error(400, "invalid_prekey", "invalid one-time prekey signature"),
        };
        let message = upm_core::handshake::one_time_prekey_signature_message(id, &public_key);
        if upm_crypto::verify(&identity_public_key, &message, &signature).is_err() {
            return error(400, "invalid_prekey", "one-time prekey signature does not match device identity");
        }
        entries.push((item.prekey_id.clone(), item.public_key.clone(), item.signature.clone()));
    }
    match db::publish_one_time_prekeys(&conn, authenticated_device, &entries) {
        Ok(published) => ok(200, json!({ "published": published })),
        Err(DbError::DeviceNotFound) => error(404, "device_not_found", "unknown authenticated device"),
        Err(_) => error(500, "internal_error", "one-time prekey publication failed"),
    }
}

fn handle_claim_one_time_prekey(state: &AppState, body: &str) -> (u16, String) {
    #[derive(Deserialize)]
    struct ClaimRequest { device_id: String }
    let req: ClaimRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid one-time prekey claim payload"),
    };
    let device_id = match DeviceId::from_hex(&req.device_id) {
        Some(id) => id.to_hex(),
        None => return error(400, "invalid_device_id", "device_id must be 16 bytes encoded as 32 hex characters"),
    };
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::claim_one_time_prekey(&conn, &device_id) {
        Ok(Some(record)) => ok(200, json!({
            "available": true,
            "prekey_id": record.prekey_id,
            "public_key": record.public_key,
            "signature": record.signature,
        })),
        Ok(None) => ok(200, json!({ "available": false })),
        Err(DbError::DeviceNotFound) => error(404, "device_not_found", "unknown target device"),
        Err(_) => error(500, "internal_error", "one-time prekey claim failed"),
    }
}

// ---------------------------------------------------------------------
// GET /v1/devices/keys/{device_id} — public X3DH bundle for session setup.
// ---------------------------------------------------------------------

fn handle_get_device_keys(state: &AppState, device_id: &str) -> (u16, String) {
    let parsed = match DeviceId::from_hex(device_id) {
        Some(id) => id,
        None => return error(400, "invalid_device_id", "device_id must be 16 bytes encoded as 32 hex characters"),
    };
    let conn = state.db.lock().expect("db mutex poisoned");
    let bundle = match db::get_device_prekey_bundle(&conn, &parsed.to_hex()) {
        Ok(bundle) => bundle,
        Err(DbError::DeviceNotFound) => return error(404, "device_not_found", "unknown device_id"),
        Err(_) => return error(500, "internal_error", "key lookup failed"),
    };
    if bundle.identity_exchange_public.is_empty()
        || bundle.signed_prekey_public.is_empty()
        || bundle.signed_prekey_signature.is_empty()
    {
        return error(409, "keys_unavailable", "device has not published a complete X3DH key bundle");
    }
    ok(200, json!({
        "device_id": bundle.device_id,
        "identity_public_key": bundle.identity_public_key,
        "identity_exchange_public": bundle.identity_exchange_public,
        "signed_prekey_public": bundle.signed_prekey_public,
        "signed_prekey_signature": bundle.signed_prekey_signature,
    }))
}

// ---------------------------------------------------------------------
// POST /v1/messages/send — AC-03..AC-06 depend on the client-side crypto
// layer; this endpoint only relays the opaque envelope (SRS §8).
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct SendRequest {
    protocol_version: u16,
    message_id: String,
    recipient_device_id: String,
    /// Base64-encoded ciphertext. The server does not and cannot decode
    /// its meaning — only its validity as base64 is checked.
    ciphertext_base64: String,
    ttl_seconds: Option<i64>,
}



fn handle_send(state: &AppState, body: &str, authenticated_sender: &str) -> (u16, String) {
    let req: SendRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid envelope payload"),
    };

    if req.protocol_version != ProtocolVersion::CURRENT.0 {
        return error(426, "unsupported_protocol", "unsupported protocol version");
    }
    let message_id = match MessageId::from_hex(&req.message_id) {
        Some(id) => id,
        None => return error(400, "invalid_message_id", "message_id must be 16 random bytes encoded as 32 hex characters"),
    };
    let recipient_device_id = match DeviceId::from_hex(&req.recipient_device_id) {
        Some(id) => id,
        None => return error(400, "invalid_device_id", "recipient_device_id must be 16 random bytes encoded as 32 hex characters"),
    };

    let ciphertext = match base64_decode(&req.ciphertext_base64) {
        Some(bytes) => bytes,
        None => {
            return error(
                400,
                "bad_ciphertext",
                "ciphertext_base64 is not valid base64",
            )
        }
    };

    let server_timestamp = current_unix_seconds();
    let ttl = req.ttl_seconds.unwrap_or(db::DEFAULT_MESSAGE_TTL_SECONDS);
    if ttl <= 0 || ttl > db::DEFAULT_MESSAGE_TTL_SECONDS {
        return error(400, "invalid_ttl", "ttl_seconds is outside the allowed retention window");
    }
    let sender_device_id = match DeviceId::from_hex(authenticated_sender) {
        Some(id) => id,
        None => return error(500, "internal_error", "authenticated device identity is invalid"),
    };
    let envelope = MessageEnvelope {
        protocol_version: ProtocolVersion(req.protocol_version),
        message_id,
        sender_device_id,
        recipient_device_id,
        ciphertext,
        server_timestamp,
        expires_at: server_timestamp.saturating_add(ttl as u64),
    };

    let conn = state.db.lock().expect("db mutex poisoned");
    let sender_active = conn.query_row(
        "SELECT u.status = 'active' FROM users u JOIN devices d ON d.user_id = u.user_id WHERE d.device_id = ?1",
        rusqlite::params![authenticated_sender],
        |row| row.get::<_, bool>(0),
    ).unwrap_or(false);
    if !sender_active {
        return error(403, "forbidden", "authenticated device is not active");
    }
    match db::enqueue_message(&conn, &envelope) {
        Ok(message_id) => ok(
            202,
            json!({
                "protocol_version": req.protocol_version,
                "message_id": message_id,
                "server_timestamp": server_timestamp,
                "expires_at": envelope.expires_at,
            }),
        ),
        Err(DbError::DeviceNotFound) => {
            error(404, "device_not_found", "unknown recipient_device_id")
        }
        Err(_) => error(500, "internal_error", "send failed"),
    }
}

// ---------------------------------------------------------------------
// GET /v1/messages/pull?device_id=... — restricted to the authenticated
// device's own queue.
// ---------------------------------------------------------------------

fn handle_pull(state: &AppState, url: &str, authenticated_device: &str) -> (u16, String) {
    let requested_device = match query_param(url, "device_id") {
        Some(d) => d,
        None => return error(400, "bad_request", "device_id query parameter is required"),
    };
    if requested_device != authenticated_device {
        return error(403, "forbidden", "cannot pull another device's queue");
    }

    let conn = state.db.lock().expect("db mutex poisoned");
    match db::pull_messages(&conn, authenticated_device) {
        Ok(envelopes) => {
            let items: Vec<_> = envelopes
                .into_iter()
                .map(|e| {
                    json!({
                        "message_id": e.message_id,
                        "sender_device_id": e.sender_device_id,
                        "ciphertext_base64": base64_encode(&e.ciphertext_blob),
                        "created_at": e.created_at,
                        "expires_at": e.expires_at,
                        "protocol_version": e.protocol_version,
                    })
                })
                .collect();
            ok(200, json!({ "envelopes": items }))
        }
        Err(_) => error(500, "internal_error", "pull failed"),
    }
}

// ---------------------------------------------------------------------
// POST /v1/messages/ack — only the authenticated recipient device may
// acknowledge/delete its queued message IDs.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct AckRequest {
    message_ids: Vec<String>,
}

fn handle_ack(state: &AppState, body: &str, authenticated_device: &str) -> (u16, String) {
    let req: AckRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid ack payload"),
    };

    let conn = state.db.lock().expect("db mutex poisoned");
    match db::ack_messages(&conn, authenticated_device, &req.message_ids) {
        Ok(count) => ok(200, json!({ "acknowledged": count })),
        Err(_) => error(500, "internal_error", "ack failed"),
    }
}

// ---------------------------------------------------------------------
// POST /v1/attachments/create, DELETE /v1/attachments/{id} — SRS §9
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateAttachmentRequest {
    opaque_size: i64,
}

/// Server-configured attachment size ceiling (SRS §9: "Initial recommended
/// attachment limit: 100 MB; configurable server-side").
const MAX_ATTACHMENT_BYTES: i64 = 100 * 1024 * 1024;

fn handle_attachment_create(state: &AppState, body: &str, authenticated_device: &str) -> (u16, String) {
    let req: CreateAttachmentRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return error(400, "bad_request", "invalid attachment payload"),
    };

    if req.opaque_size <= 0 || req.opaque_size > MAX_ATTACHMENT_BYTES {
        return error(
            400,
            "attachment_too_large",
            "opaque_size exceeds server limit",
        );
    }

    let conn = state.db.lock().expect("db mutex poisoned");
    match db::create_attachment(&conn, authenticated_device, req.opaque_size) {
        Ok(slot) => ok(
            201,
            json!({ "attachment_id": slot.attachment_id, "capability": slot.capability }),
        ),
        Err(_) => error(500, "internal_error", "attachment slot creation failed"),
    }
}

fn handle_attachment_delete(state: &AppState, attachment_id: &str, authenticated_device: &str) -> (u16, String) {
    let record = {
        let conn = state.db.lock().expect("db mutex poisoned");
        match db::get_attachment(&conn, attachment_id) {
            Ok(Some(record)) => record,
            Ok(None) => return error(404, "not_found", "no such attachment"),
            Err(_) => return error(500, "internal_error", "attachment lookup failed"),
        }
    };
    if record.owner_device_id != authenticated_device {
        return error(403, "forbidden", "attachment does not belong to authenticated device");
    }
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::delete_attachment(&conn, authenticated_device, attachment_id) {
        Ok(true) => {
            let _ = std::fs::remove_file(attachment_path(&state.attachment_dir, &record.storage_key));
            ok(200, json!({ "deleted": true }))
        }
        Ok(false) => error(404, "not_found", "no such attachment"),
        Err(_) => error(500, "internal_error", "attachment deletion failed"),
    }
}

fn attachment_path(root: &Path, storage_key: &str) -> PathBuf {
    root.join(format!("{storage_key}.blob"))
}

fn handle_attachment_upload(
    state: &AppState,
    attachment_id: &str,
    authenticated_device: &str,
    request: &mut Request,
) -> (u16, Vec<u8>) {
    if DeviceId::from_hex(attachment_id).is_none() {
        return (400, b"invalid attachment id".to_vec());
    }
    let record = {
        let conn = state.db.lock().expect("db mutex poisoned");
        match db::get_attachment(&conn, attachment_id) {
            Ok(Some(record)) => record,
            Ok(None) => return (404, b"attachment not found".to_vec()),
            Err(_) => return (500, b"attachment lookup failed".to_vec()),
        }
    };
    if record.owner_device_id != authenticated_device {
        return (403, b"forbidden".to_vec());
    }
    if record.expires_at <= current_unix_seconds() as i64 {
        return (410, b"attachment expired".to_vec());
    }
    let max = record.opaque_size as u64;
    let mut bytes = Vec::new();
    if request.as_reader().take(max.saturating_add(1)).read_to_end(&mut bytes).is_err() {
        return (400, b"attachment upload could not be read".to_vec());
    }
    if bytes.len() as u64 != max {
        return (400, b"attachment size does not match reserved size".to_vec());
    }
    if std::fs::create_dir_all(&state.attachment_dir).is_err() {
        return (500, b"attachment storage unavailable".to_vec());
    }
    let final_path = attachment_path(&state.attachment_dir, &record.storage_key);
    let tmp_path = final_path.with_extension("blob.part");
    if std::fs::write(&tmp_path, &bytes).is_err() || std::fs::rename(&tmp_path, &final_path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return (500, b"attachment storage failed".to_vec());
    }
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::mark_attachment_uploaded(&conn, attachment_id, authenticated_device) {
        Ok(true) => (204, Vec::new()),
        Ok(false) => {
            let _ = std::fs::remove_file(&final_path);
            (404, b"attachment state changed".to_vec())
        }
        Err(_) => {
            let _ = std::fs::remove_file(&final_path);
            (500, b"attachment state update failed".to_vec())
        }
    }
}

fn handle_attachment_download(state: &AppState, attachment_id: &str, _authenticated_device: &str, capability: Option<&str>) -> (u16, Vec<u8>) {
    if DeviceId::from_hex(attachment_id).is_none() {
        return (400, b"invalid attachment id".to_vec());
    }
    let record = {
        let conn = state.db.lock().expect("db mutex poisoned");
        match db::get_attachment(&conn, attachment_id) {
            Ok(Some(record)) => record,
            Ok(None) => return (404, b"attachment not found".to_vec()),
            Err(_) => return (500, b"attachment lookup failed".to_vec()),
        }
    };
    if record.expires_at <= current_unix_seconds() as i64 {
        return (410, b"attachment expired".to_vec());
    }
    let Some(capability) = capability else {
        return (403, b"attachment capability required".to_vec());
    };
    if !db::attachment_capability_matches(&record, capability) {
        return (403, b"invalid attachment capability".to_vec());
    }
    if !record.uploaded {
        return (404, b"attachment blob not available".to_vec());
    }
    let bytes = match std::fs::read(attachment_path(&state.attachment_dir, &record.storage_key)) {
        Ok(bytes) => bytes,
        Err(_) => return (404, b"attachment blob not found".to_vec()),
    };
    if bytes.len() as i64 != record.opaque_size {
        return (500, b"attachment integrity check failed".to_vec());
    }
    (200, bytes)
}

// ---------------------------------------------------------------------
// GET /v1/profile/public/{username}
// ---------------------------------------------------------------------

fn handle_public_profile(state: &AppState, username: &str) -> (u16, String) {
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::get_public_profile(&conn, username) {
        Ok(Some(entry)) => ok(
            200,
            json!({ "username": entry.username, "upm_id": entry.upm_id }),
        ),
        Ok(None) => error(404, "not_found", "no such username"),
        Err(_) => error(500, "internal_error", "profile lookup failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_param_extracts_value() {
        assert_eq!(
            query_param("/v1/messages/pull?device_id=abc123", "device_id"),
            Some("abc123")
        );
        assert_eq!(query_param("/v1/messages/pull", "device_id"), None);
    }

    #[test]
    fn valid_public_key_checks_length() {
        let good = base64_encode(&[1u8; 32]);
        let bad = base64_encode(&[1u8; 20]);
        assert!(valid_public_key(&good));
        assert!(!valid_public_key(&bad));
        assert!(!valid_public_key("not base64 at all!!"));
    }
}
