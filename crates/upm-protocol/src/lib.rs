//! Wire format and protocol-version negotiation for UPM.
//!
//! SRS references:
//! - §6 Cryptography and protocol requirements: normative note on
//!   crypto-agility — the application MUST expose a versioned protocol
//!   identifier so algorithms can be migrated without silently changing
//!   message interpretation.
//! - §16 API and protocol surface: all API payloads SHALL be schema-versioned.
//! - §19 Build/release: every client release MUST declare a protocol
//!   compatibility range.
//! - AC-12: protocol/version mismatches fail safely and clearly.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// A single protocol version. UPM does not use semver for the wire protocol
/// — each bump is a discrete, explicitly migrated revision (SRS §6, §19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// The current protocol version implemented by this crate.
    /// Bump this — and record a migration note — whenever the wire format
    /// or cryptographic suite changes in an incompatible way. v4 binds the
    /// X3DH-style bootstrap to individual prekey identifiers and adds typed
    /// envelopes with sender-device binding.
    /// individual prekey identifiers while retaining typed envelopes.
    pub const CURRENT: ProtocolVersion = ProtocolVersion(4);
}

/// Inclusive range of protocol versions a client or server build supports.
/// Every release MUST declare one (SRS §19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityRange {
    pub min: ProtocolVersion,
    pub max: ProtocolVersion,
}

impl CompatibilityRange {
    pub fn contains(&self, v: ProtocolVersion) -> bool {
        v >= self.min && v <= self.max
    }

    /// This build's compatibility range. Foundation phase: only CURRENT.
    pub fn this_build() -> Self {
        CompatibilityRange {
            min: ProtocolVersion::CURRENT,
            max: ProtocolVersion::CURRENT,
        }
    }
}

#[derive(Debug, Error)]
pub enum NegotiationError {
    #[error("no overlapping protocol version: local {local:?}, peer {peer:?}")]
    NoOverlap {
        local: CompatibilityRange,
        peer: CompatibilityRange,
    },
}

/// Negotiate the highest protocol version both sides support.
/// Per AC-12, mismatches MUST fail safely and clearly — never silently
/// downgrade to an unversioned or partially-understood format.
pub fn negotiate(
    local: CompatibilityRange,
    peer: CompatibilityRange,
) -> Result<ProtocolVersion, NegotiationError> {
    let max_common = local.max.min(peer.max);
    let min_common = local.min.max(peer.min);
    if min_common <= max_common {
        Ok(max_common)
    } else {
        Err(NegotiationError::NoOverlap { local, peer })
    }
}

/// Opaque ciphertext envelope as relayed/stored by the server (SRS §8, §15).
/// The server MUST NOT be able to derive plaintext from these fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub protocol_version: ProtocolVersion,
    pub message_id: MessageId,
    pub sender_device_id: DeviceId,
    pub recipient_device_id: DeviceId,
    /// Authenticated ciphertext produced by upm-core. Opaque to this crate.
    pub ciphertext: Vec<u8>,
    /// Server-side queueing timestamp only — NOT cryptographic truth (SRS §8).
    pub server_timestamp: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PreKeyId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub [u8; 16]);

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn decode_hex_16(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

impl MessageId {
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        let mut rng = rand::thread_rng();
        rand::RngCore::fill_bytes(&mut rng, &mut bytes);
        Self(bytes)
    }

    pub fn from_hex(value: &str) -> Option<Self> {
        decode_hex_16(value).map(Self)
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl PreKeyId {
    pub fn from_hex(value: &str) -> Option<Self> {
        decode_hex_16(value).map(Self)
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl DeviceId {
    pub fn from_hex(value: &str) -> Option<Self> {
        decode_hex_16(value).map(Self)
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl Serialize for MessageId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for MessageId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        MessageId::from_hex(&value)
            .ok_or_else(|| serde::de::Error::custom("message_id must be exactly 16 bytes encoded as 32 hex characters"))
    }
}

impl Serialize for DeviceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        DeviceId::from_hex(&value)
            .ok_or_else(|| serde::de::Error::custom("device_id must be exactly 16 bytes encoded as 32 hex characters"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_succeeds_on_overlap() {
        let local = CompatibilityRange {
            min: ProtocolVersion(1),
            max: ProtocolVersion(2),
        };
        let peer = CompatibilityRange {
            min: ProtocolVersion(2),
            max: ProtocolVersion(3),
        };
        assert_eq!(negotiate(local, peer).unwrap(), ProtocolVersion(2));
    }

    #[test]
    fn negotiation_fails_closed_without_overlap() {
        let local = CompatibilityRange {
            min: ProtocolVersion(1),
            max: ProtocolVersion(1),
        };
        let peer = CompatibilityRange {
            min: ProtocolVersion(2),
            max: ProtocolVersion(2),
        };
        assert!(negotiate(local, peer).is_err());
    }

    #[test]
    fn ids_roundtrip_as_hex_strings() {
        let env = MessageEnvelope {
            protocol_version: ProtocolVersion::CURRENT,
            message_id: MessageId([1u8; 16]),
            sender_device_id: DeviceId([3u8; 16]),
            recipient_device_id: DeviceId([2u8; 16]),
            ciphertext: vec![9, 9, 9],
            server_timestamp: 1,
            expires_at: 2,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("01010101010101010101010101010101"));
        assert!(json.contains("02020202020202020202020202020202"));
        let back: MessageEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message_id, env.message_id);
        assert_eq!(back.sender_device_id, env.sender_device_id);
        assert_eq!(back.recipient_device_id, env.recipient_device_id);
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let env = MessageEnvelope {
            protocol_version: ProtocolVersion::CURRENT,
            message_id: MessageId([1u8; 16]),
            sender_device_id: DeviceId([3u8; 16]),
            recipient_device_id: DeviceId([2u8; 16]),
            ciphertext: vec![9, 9, 9],
            server_timestamp: 1_735_000_000,
            expires_at: 1_735_600_000,
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: MessageEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message_id, env.message_id);
        assert_eq!(back.sender_device_id, env.sender_device_id);
        assert_eq!(back.ciphertext, env.ciphertext);
    }
}
