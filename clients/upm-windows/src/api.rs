use base64::Engine;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use upm_protocol::ProtocolVersion;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("server returned HTTP {status}: {message}")]
    Server { status: u16, message: String },
    #[error("invalid server response: {0}")]
    Decode(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct ApiClient {
    base: String,
    http: Client,
}

#[derive(Debug, Clone, Serialize)]
struct RegisterRequest<'a> {
    username: &'a str,
    identity_public_key: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub upm_id: String,
    pub device_id: String,
}

#[derive(Debug, Serialize)]
struct ChallengeRequest<'a> {
    device_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    pub challenge_base64: String,
    pub ttl_seconds: i64,
}

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    device_id: &'a str,
    signature_base64: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct VerifyResponse {
    pub session_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
struct PublishKeysRequest<'a> {
    pub identity_exchange_public: &'a str,
    pub signed_prekey_public: &'a str,
    pub signed_prekey_signature: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DirectoryEntry {
    pub upm_id: String,
    pub username: String,
    pub device_id: String,
    pub identity_public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceKeyBundle {
    pub device_id: String,
    pub identity_public_key: String,
    pub identity_exchange_public: String,
    pub signed_prekey_public: String,
    pub signed_prekey_signature: String,
}

#[derive(Debug, Serialize)]
pub struct SendRequest<'a> {
    pub protocol_version: u16,
    pub message_id: String,
    pub recipient_device_id: String,
    pub ciphertext_base64: &'a str,
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PullEnvelope {
    pub message_id: String,
    pub sender_device_id: String,
    pub ciphertext_base64: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub protocol_version: u16,
}

impl ApiClient {
    pub fn new(base: impl Into<String>) -> Result<Self, ApiError> {
        let mut base = base.into().trim().trim_end_matches('/').to_string();
        if base.is_empty() {
            base = "https://127.0.0.1".into();
        }
        Ok(Self {
            base,
            http: Client::builder().build()?,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn check<T: serde::de::DeserializeOwned>(&self, response: reqwest::blocking::Response) -> Result<T, ApiError> {
        let status = response.status();
        let body = response.text()?;
        if !status.is_success() {
            return Err(ApiError::Server { status: status.as_u16(), message: body });
        }
        Ok(serde_json::from_str(&body)?)
    }

    pub fn register(&self, username: &str, identity_public_key: &str) -> Result<RegisterResponse, ApiError> {
        let response = self.http.post(self.url("/v1/account/register"))
            .json(&RegisterRequest { username, identity_public_key }).send()?;
        self.check(response)
    }

    pub fn challenge(&self, device_id: &str) -> Result<(Vec<u8>, i64), ApiError> {
        let response = self.http.post(self.url("/v1/auth/challenge"))
            .json(&ChallengeRequest { device_id }).send()?;
        let result: ChallengeResponse = self.check(response)?;
        let challenge = base64::engine::general_purpose::STANDARD.decode(result.challenge_base64).map_err(|e| ApiError::Server { status: 500, message: e.to_string() })?;
        Ok((challenge, result.ttl_seconds))
    }

    pub fn verify(&self, device_id: &str, signature_base64: &str) -> Result<VerifyResponse, ApiError> {
        let response = self.http.post(self.url("/v1/auth/verify"))
            .json(&VerifyRequest { device_id, signature_base64 }).send()?;
        self.check(response)
    }

    pub fn publish_keys(&self, token: &str, exchange: &str, signed_prekey: &str, signature: &str) -> Result<(), ApiError> {
        let response = self.http.post(self.url("/v1/devices/keys"))
            .bearer_auth(token)
            .json(&PublishKeysRequest { identity_exchange_public: exchange, signed_prekey_public: signed_prekey, signed_prekey_signature: signature })
            .send()?;
        let _: serde_json::Value = self.check(response)?;
        Ok(())
    }


    pub fn device_keys(&self, device_id: &str) -> Result<DeviceKeyBundle, ApiError> {
        let path = format!("/v1/devices/keys/{}", urlencoding::encode(device_id));
        let response = self.http.get(self.url(&path)).send()?;
        self.check(response)
    }

    pub fn resolve_username(&self, username: &str) -> Result<DirectoryEntry, ApiError> {
        let path = format!("/v1/directory/resolve/{}", urlencoding::encode(username));
        let response = self.http.get(self.url(&path)).send()?;
        self.check(response)
    }

    pub fn pull(&self, token: &str, device_id: &str) -> Result<Vec<PullEnvelope>, ApiError> {
        let path = format!("/v1/messages/pull?device_id={}", urlencoding::encode(device_id));
        let response = self.http.get(self.url(&path)).bearer_auth(token).send()?;
        #[derive(Deserialize)] struct Wrapper { envelopes: Vec<PullEnvelope> }
        Ok(self.check::<Wrapper>(response)?.envelopes)
    }

    pub fn ack(&self, token: &str, ids: &[String]) -> Result<usize, ApiError> {
        #[derive(Serialize)] struct Ack<'a> { message_ids: &'a [String] }
        #[derive(Deserialize)] struct ResultBody { acknowledged: usize }
        let response = self.http.post(self.url("/v1/messages/ack"))
            .bearer_auth(token).json(&Ack { message_ids: ids }).send()?;
        Ok(self.check::<ResultBody>(response)?.acknowledged)
    }

    pub fn send(&self, token: &str, request: &SendRequest<'_>) -> Result<(), ApiError> {
        let response = self.http.post(self.url("/v1/messages/send"))
            .bearer_auth(token).json(request).send()?;
        let _: serde_json::Value = self.check(response)?;
        Ok(())
    }

    pub fn send_envelope(
        &self,
        token: &str,
        envelope: &upm_protocol::MessageEnvelope,
    ) -> Result<(), ApiError> {
        let ciphertext_base64 = base64::engine::general_purpose::STANDARD.encode(&envelope.ciphertext);
        let request = SendRequest {
            protocol_version: envelope.protocol_version.0,
            message_id: envelope.message_id.to_hex(),
            recipient_device_id: envelope.recipient_device_id.to_hex(),
            ciphertext_base64: &ciphertext_base64,
            ttl_seconds: None,
        };
        self.send(token, &request)
    }
}

