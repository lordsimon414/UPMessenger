use base64::Engine;
use reqwest::blocking::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};

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
            base = "http://127.0.0.1:8787".into();
        }
        let parsed = Url::parse(&base).map_err(|e| ApiError::Server {
            status: 0,
            message: format!("invalid server URL: {e}"),
        })?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(ApiError::Server {
                    status: 0,
                    message: format!("unsupported server URL scheme: {other}"),
                });
            }
        }
        if parsed.host_str().is_none() {
            return Err(ApiError::Server {
                status: 0,
                message: "server URL has no host".into(),
            });
        }
        let http = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        Ok(Self { base, http })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn check<T: serde::de::DeserializeOwned>(&self, response: reqwest::blocking::Response) -> Result<T, ApiError> {
        let status = response.status();
        let body = response.text()?;
        if !status.is_success() {
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).map(str::to_owned))
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| body.lines().next().unwrap_or("request failed").trim().to_string());
            return Err(ApiError::Server { status: status.as_u16(), message });
        }
        Ok(serde_json::from_str(&body)?)
    }

    pub fn register(&self, username: &str, identity_public_key: &str) -> Result<RegisterResponse, ApiError> {
        let username = username.trim();
        let response = self.http.post(self.url("/v1/account/register"))
            .json(&RegisterRequest { username, identity_public_key }).send()?;
        self.check(response)
    }

    pub fn health(&self) -> Result<(), ApiError> {
        let response = self.http.get(self.url("/v1/health")).send()?;
        let _: serde_json::Value = self.check(response)?;
        Ok(())
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

    pub fn logout(&self, token: &str) -> Result<(), ApiError> {
        let response = self.http.delete(self.url("/v1/auth/session"))
            .bearer_auth(token).send()?;
        let _: serde_json::Value = self.check(response)?;
        Ok(())
    }

    pub fn set_directory_visibility(&self, token: &str, visible: bool) -> Result<(), ApiError> {
        #[derive(Serialize)] struct Body { directory_visible: bool }
        let response = self.http.post(self.url("/v1/profile/privacy"))
            .bearer_auth(token).json(&Body { directory_visible: visible }).send()?;
        let _: serde_json::Value = self.check(response)?;
        Ok(())
    }

    pub fn publish_keys(&self, token: &str, exchange: &str, signed_prekey: &str, signature: &str) -> Result<(), ApiError> {
        let response = self.http.post(self.url("/v1/devices/keys"))
            .bearer_auth(token)
            .json(&PublishKeysRequest { identity_exchange_public: exchange, signed_prekey_public: signed_prekey, signed_prekey_signature: signature })
            .send()?;
        let _: serde_json::Value = self.check(response)?;
        Ok(())
    }


    pub fn publish_one_time_prekeys(
        &self,
        token: &str,
        prekeys: &[(String, String, String)],
    ) -> Result<usize, ApiError> {
        #[derive(Serialize)]
        struct Item<'a> { prekey_id: &'a str, public_key: &'a str, signature: &'a str }
        #[derive(Serialize)]
        struct Body<'a> { prekeys: Vec<Item<'a>> }
        #[derive(Deserialize)]
        struct ResponseBody { published: usize }
        let items = prekeys.iter().map(|(id, public_key, signature)| Item {
            prekey_id: id,
            public_key,
            signature,
        }).collect();
        let response = self.http.post(self.url("/v1/devices/prekeys"))
            .bearer_auth(token)
            .json(&Body { prekeys: items })
            .send()?;
        Ok(self.check::<ResponseBody>(response)?.published)
    }

    pub fn claim_one_time_prekey(
        &self,
        token: &str,
        device_id: &str,
    ) -> Result<Option<(String, String, String)>, ApiError> {
        #[derive(Serialize)]
        struct RequestBody<'a> { device_id: &'a str }
        #[derive(Deserialize)]
        struct ResponseBody {
            available: bool,
            prekey_id: Option<String>,
            public_key: Option<String>,
            signature: Option<String>,
        }
        let response = self.http.post(self.url("/v1/devices/prekeys/claim"))
            .bearer_auth(token)
            .json(&RequestBody { device_id })
            .send()?;
        let body: ResponseBody = self.check(response)?;
        if !body.available { return Ok(None); }
        Ok(Some((
            body.prekey_id.ok_or_else(|| ApiError::Server { status: 500, message: "server returned incomplete prekey".into() })?,
            body.public_key.ok_or_else(|| ApiError::Server { status: 500, message: "server returned incomplete prekey".into() })?,
            body.signature.ok_or_else(|| ApiError::Server { status: 500, message: "server returned incomplete prekey".into() })?,
        )))
    }

    pub fn create_attachment(&self, token: &str, opaque_size: i64) -> Result<(String, String), ApiError> {
        #[derive(Serialize)] struct Body { opaque_size: i64 }
        #[derive(Deserialize)] struct ResponseBody { attachment_id: String, capability: String }
        let response = self.http.post(self.url("/v1/attachments/create"))
            .bearer_auth(token).json(&Body { opaque_size }).send()?;
        let result = self.check::<ResponseBody>(response)?;
        Ok((result.attachment_id, result.capability))
    }

    pub fn upload_attachment_blob(&self, token: &str, attachment_id: &str, blob: &[u8]) -> Result<(), ApiError> {
        let path = format!("/v1/attachments/{}/blob", urlencoding::encode(attachment_id));
        let response = self.http.put(self.url(&path)).bearer_auth(token).body(blob.to_vec()).send()?;
        if !response.status().is_success() {
            return Err(ApiError::Server { status: response.status().as_u16(), message: response.text().unwrap_or_default() });
        }
        Ok(())
    }

    pub fn download_attachment_blob(&self, token: &str, attachment_id: &str, capability: &str) -> Result<Vec<u8>, ApiError> {
        let path = format!("/v1/attachments/{}/blob", urlencoding::encode(attachment_id));
        let response = self.http.get(self.url(&path)).bearer_auth(token)
            .header("X-UPM-Attachment-Capability", capability)
            .send()?;
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError::Server { status: status.as_u16(), message: response.text().unwrap_or_default() });
        }
        Ok(response.bytes()?.to_vec())
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

    pub fn resolve_upm_id(&self, upm_id: &str) -> Result<DirectoryEntry, ApiError> {
        let path = format!("/v1/directory/resolve-id/{}", urlencoding::encode(upm_id));
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

