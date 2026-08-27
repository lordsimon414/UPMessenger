# UPM development changelog

## Next — continued Phase 3 / hardening pass

- Added recipient-bound attachment capabilities. The server stores a SHA-256 digest of the capability and requires the capability for blob download; the capability is delivered inside the E2EE attachment payload.
- Added explicit session logout/revocation.
- Added account-level directory visibility control for username/UPM-ID discovery.
- Added startup cleanup for expired message envelopes, attachments, auth challenges, and sessions.
- Added a transport smoke-test binary (`upm-smoke`) covering registration, Ed25519 authentication, opaque send/pull/ack, protocol-version handling, and cross-device ACK rejection.
- Added initial Android, iOS, and Web typed API/platform boundary scaffolds; these are not yet production client implementations.
- Updated security review and build notes.

## Previous — Phase 0–3

See `docs/ROADMAP.md` and `docs/SECURITY_REVIEW.md` for the detailed implementation and security history.
