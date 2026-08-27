# Threat model (extract from SRS §5)

Full detail lives in `UPM_SRS_v1_1.docx`. This file is the quick-reference
version engineers should have open while writing code.

## Assumed attacker capabilities

- Observe or manipulate network traffic.
- Compromise or inspect the UPM server.
- Obtain a stolen local backup/database copy.
- Attempt to impersonate a user/device.

**Explicitly out of scope:** a fully compromised endpoint. Malware with
control over a device can read content before encryption or after
decryption. Security UI must never imply otherwise.

## Threat → response matrix

| Threat | UPM response |
|---|---|
| Network eavesdropping | TLS 1.3 transport + application-layer E2EE |
| Malicious/compromised server | Server stores/relays ciphertext only; MUST NOT hold decryption keys |
| Server database theft | Message/attachment payloads encrypted/opaque at rest |
| Message tampering | AEAD authentication; invalid ciphertext MUST be rejected |
| User/device impersonation | Authenticated device keys, explicit key-change handling |
| Replay / duplicate delivery | Message IDs, ratchet state, replay protection |
| Metadata collection | No content analytics; bounded operational fields; short retention |
| Local device loss | Platform secure storage (Keychain/Keystore) for long-lived keys |
| Endpoint compromise | Out of scope; UI SHALL NOT imply it is prevented |

## Security principle

Minimize custom cryptography. Compose established, maintained primitives
and protocol components — never invent new algorithms or protocols
(SEC-02 in the SRS requirement index). This is why `upm-crypto` only wraps
`ed25519-dalek`, `x25519-dalek`, `hkdf`, `chacha20poly1305`, and why the
ratchet in `upm-core` must be built against a reviewed design, not
invented from scratch.

## Fail-closed requirements engineers must not weaken

- Crypto failures MUST fail closed — no automatic plaintext fallback (SRS §8).
- Key agreement MUST reject non-contributory / all-zero shared secrets (SRS §6).
- Protocol/version mismatches MUST fail safely and clearly, never silently
  downgrade (AC-12).
- No feature may silently fall back from E2EE to server-readable plaintext
  (AC-13).
