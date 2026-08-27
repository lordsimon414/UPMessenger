//! Minimal dependency-free base64 (standard alphabet, with padding).
//! Kept local and tiny rather than pulling in another crate whose MSRV
//! might not match this build's Rust 1.75 toolchain constraint.

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    if clean.iter().any(|&b| val(b).is_none()) {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Decodes and validates an exact-length key/signature field. Used for
/// Ed25519 public keys (32 bytes) and signatures (64 bytes) so malformed
/// input is rejected before it ever reaches `upm-crypto`.
pub fn decode_fixed<const N: usize>(base64: &str) -> Option<[u8; N]> {
    let bytes = base64_decode(base64)?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let data = b"opaque ciphertext bytes \x00\x01\xff";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_rejects_invalid_input() {
        assert!(base64_decode("not-valid-base64!!").is_none());
    }

    #[test]
    fn decode_fixed_enforces_length() {
        let thirty_two = base64_encode(&[7u8; 32]);
        assert!(decode_fixed::<32>(&thirty_two).is_some());
        assert!(decode_fixed::<64>(&thirty_two).is_none());
    }
}
