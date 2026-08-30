use base64::Engine;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;
use upm_crypto::IdentityKeyPair;

#[derive(Debug, Serialize)]
struct Register<'a> { username: &'a str, identity_public_key: String }
#[derive(Debug, Deserialize)]
struct Registered { user_id: String, upm_id: String, device_id: String }
#[derive(Debug, Serialize)]
struct Challenge<'a> { device_id: &'a str }
#[derive(Debug, Deserialize)]
struct ChallengeReply { challenge_base64: String }
#[derive(Debug, Serialize)]
struct Verify<'a> { device_id: &'a str, signature_base64: String }
#[derive(Debug, Deserialize)]
struct VerifyReply { session_token: String }
#[derive(Debug, Serialize)]
struct SendBody<'a> { protocol_version: u16, message_id: String, recipient_device_id: &'a str, ciphertext_base64: String }
#[derive(Debug, Deserialize)]
struct PullReply { envelopes: Vec<Envelope> }
#[derive(Debug, Deserialize)]
struct Envelope { message_id: String, sender_device_id: String, ciphertext_base64: String, protocol_version: u16 }
#[derive(Debug, Serialize)]
struct Ack<'a> { message_ids: &'a [String] }

fn url(base: &str, path: &str) -> String { format!("{}{}", base.trim_end_matches('/'), path) }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:8787".into());
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

    client.get(url(&base, "/v1/health")).send()?.error_for_status()?;

    let suffix = rand::random::<u32>();
    let alice_username = format!("smoke-alice-{suffix}");
    let bob_username = format!("smoke-bob-{suffix}");
    let alice_kp = IdentityKeyPair::generate();
    let bob_kp = IdentityKeyPair::generate();
    let alice = register(&client, &base, &alice_username, &alice_kp)?;
    let bob = register(&client, &base, &bob_username, &bob_kp)?;

    // Account creation must reject a duplicate username instead of
    // silently creating a second identity under the same name.
    let duplicate_kp = IdentityKeyPair::generate();
    let duplicate_response = client
        .post(url(&base, "/v1/account/register"))
        .json(&Register { username: &alice_username, identity_public_key: base64::engine::general_purpose::STANDARD.encode(duplicate_kp.public_key()) })
        .send()?;
    if duplicate_response.status().as_u16() != 409 {
        return Err(format!("duplicate username was not rejected: {}", duplicate_response.status()).into());
    }

    let alice_token = login(&client, &base, &alice.device_id, &alice_kp)?;
    let bob_token = login(&client, &base, &bob.device_id, &bob_kp)?;

    // A second login must also work: challenge nonces are one-shot, but
    // clients should be able to authenticate again after a restart/logout.
    let alice_token2 = login(&client, &base, &alice.device_id, &alice_kp)?;
    let logout_response = client
        .delete(url(&base, "/v1/auth/session"))
        .bearer_auth(&alice_token2)
        .send()?;
    logout_response.error_for_status()?;
    let alice_token = login(&client, &base, &alice.device_id, &alice_kp)?;

    let message_id = format!("{:032X}", rand::random::<u128>());
    let plaintext_marker = format!("UPM-SMOKE-{}", rand::random::<u64>());
    let ciphertext = base64::engine::general_purpose::STANDARD.encode(plaintext_marker.as_bytes());
    let body = SendBody { protocol_version: upm_protocol::ProtocolVersion::CURRENT.0, message_id: message_id.clone(), recipient_device_id: &bob.device_id, ciphertext_base64: ciphertext };
    let response = client.post(url(&base, "/v1/messages/send")).bearer_auth(&alice_token).json(&body).send()?;
    if !response.status().is_success() { return Err(format!("send failed: {}", response.status()).into()); }

    let pull: PullReply = client.get(url(&base, &format!("/v1/messages/pull?device_id={}", bob.device_id))).bearer_auth(&bob_token).send()?.json()?;
    let found = pull.envelopes.iter().find(|e| e.message_id == message_id).ok_or("message not found in recipient queue")?;
    if found.sender_device_id != alice.device_id || found.protocol_version != upm_protocol::ProtocolVersion::CURRENT.0 { return Err("envelope identity/version mismatch".into()); }
    let decoded = base64::engine::general_purpose::STANDARD.decode(&found.ciphertext_base64)?;
    if decoded != plaintext_marker.as_bytes() { return Err("opaque payload roundtrip mismatch".into()); }

    let ack_body = Ack { message_ids: &[message_id.clone()] };
    let response = client.post(url(&base, "/v1/messages/ack")).bearer_auth(&alice_token).json(&ack_body).send()?;
    let wrong_device_ack: serde_json::Value = response.json()?;
    if wrong_device_ack.get("acknowledged").and_then(|v| v.as_u64()) != Some(0) { return Err("cross-device ACK was incorrectly accepted".into()); }

    let ack_body = Ack { message_ids: &[message_id] };
    let response = client.post(url(&base, "/v1/messages/ack")).bearer_auth(&bob_token).json(&ack_body).send()?;
    if !response.status().is_success() { return Err(format!("ack failed: {}", response.status()).into()); }

    println!("Health endpoint: OK");
    println!("Account creation: OK");
    println!("Duplicate username rejection: OK");
    println!("Challenge-response login: OK");
    println!("Logout + relogin: OK");
    println!("UPM smoke test PASSED");
    println!("Alice: @{} / {}", alice.upm_id, alice.device_id);
    println!("Bob:   @{} / {}", bob.upm_id, bob.device_id);
    println!("Transport envelope send/pull/ack: OK");
    println!("Note: this test intentionally uses an opaque marker, not a real E2EE session.");
    Ok(())
}

fn register(client: &Client, base: &str, username: &str, kp: &IdentityKeyPair) -> Result<Registered, Box<dyn std::error::Error>> {
    let body = Register { username, identity_public_key: base64::engine::general_purpose::STANDARD.encode(kp.public_key()) };
    let response = client.post(url(base, "/v1/account/register")).json(&body).send()?;
    if !response.status().is_success() { return Err(format!("register {username} failed: {}", response.status()).into()); }
    Ok(response.json()?)
}

fn login(client: &Client, base: &str, device_id: &str, kp: &IdentityKeyPair) -> Result<String, Box<dyn std::error::Error>> {
    let response: ChallengeReply = client.post(url(base, "/v1/auth/challenge")).json(&Challenge { device_id }).send()?.error_for_status()?.json()?;
    let challenge = base64::engine::general_purpose::STANDARD.decode(response.challenge_base64)?;
    let signature = kp.sign(&challenge);
    let response: VerifyReply = client.post(url(base, "/v1/auth/verify")).json(&Verify { device_id, signature_base64: base64::engine::general_purpose::STANDARD.encode(signature) }).send()?.error_for_status()?.json()?;
    Ok(response.session_token)
}
