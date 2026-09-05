use base64::Engine;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use upm_protocol::PreKeyId;

const SERVICE: &str = "UPM";
const ACCOUNT: &str = "local-profile";
const SECRETS_ACCOUNT: &str = "local-secrets";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalProfile {
    pub server_url: String,
    pub username: String,
    pub user_id: Option<String>,
    pub upm_id: Option<String>,
    pub device_id: Option<String>,
    pub session_token: Option<String>,
    pub session_expires_at: Option<i64>,
}

pub fn load() -> LocalProfile {
    let entry = match Entry::new(SERVICE, ACCOUNT) {
        Ok(v) => v,
        Err(_) => return LocalProfile::default(),
    };
    match entry.get_password() {
        Ok(value) => serde_json::from_str(&value).unwrap_or_default(),
        Err(_) => LocalProfile::default(),
    }
}

pub fn save(profile: &LocalProfile) -> Result<(), String> {
    let entry = Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
    let json = serde_json::to_string(profile).map_err(|e| e.to_string())?;
    entry.set_password(&json).map_err(|e| e.to_string())
}

pub fn clear() -> Result<(), String> {
    let entry = Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
    entry.delete_credential().map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredOneTimePreKey {
    pub id: PreKeyId,
    pub private_b64: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalSecrets {
    pub signing_private_b64: String,
    pub exchange_private_b64: String,
    pub signed_prekey_private_b64: String,
    #[serde(default)]
    pub one_time_prekeys: Vec<StoredOneTimePreKey>,
}

fn load_entry(account: &str) -> Option<Entry> {
    Entry::new(SERVICE, account).ok()
}

pub fn load_secrets() -> Option<LocalSecrets> {
    let entry = load_entry(SECRETS_ACCOUNT)?;
    let value = entry.get_password().ok()?;
    serde_json::from_str(&value).ok()
}

pub fn save_secrets(secrets: &LocalSecrets) -> Result<(), String> {
    let entry = Entry::new(SERVICE, SECRETS_ACCOUNT).map_err(|e| e.to_string())?;
    let json = serde_json::to_string(secrets).map_err(|e| e.to_string())?;
    entry.set_password(&json).map_err(|e| e.to_string())
}

pub fn local_secrets_from_bytes(
    signing: [u8; 32],
    exchange: [u8; 32],
    signed_prekey: [u8; 32],
    one_time_prekeys: Vec<(PreKeyId, [u8; 32])>,
) -> LocalSecrets {
    let enc = base64::engine::general_purpose::STANDARD;
    LocalSecrets {
        signing_private_b64: enc.encode(signing),
        exchange_private_b64: enc.encode(exchange),
        signed_prekey_private_b64: enc.encode(signed_prekey),
        one_time_prekeys: one_time_prekeys
            .into_iter()
            .map(|(id, key)| StoredOneTimePreKey {
                id,
                private_b64: enc.encode(key),
            })
            .collect(),
    }
}
