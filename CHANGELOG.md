# UPM development changelog

## Next — beta-readiness pass

- Restored the CI pipeline (`.github/workflows/ci.yml`), which had gone missing entirely; reformatted the whole workspace and fixed 12 real clippy warnings so the restored pipeline actually starts green rather than immediately failing on pre-existing drift.
- Closed a real gap where the Windows client's "Discoverable in directory" checkbox always reset to a default on login instead of reflecting what was actually set server-side (added `GET /v1/profile/privacy`).
- Added a Windows service wrapper (`upm-server install`/`uninstall`), sharing the same server logic as console mode; reports status to the Service Control Manager and shuts down cleanly on a Stop/Shutdown control instead of a hard kill.
- Added concurrent request handling (a worker-thread pool, default 8) with per-request panic isolation, replacing the earlier single-threaded accept loop.
- Added a periodic background sweep: expired messages/attachments/auth-challenges/sessions plus their orphaned attachment blob files are cleaned up on an interval (not just at startup), and the SQLite WAL is checkpointed to keep it from growing unbounded.
- Added rate limiting: a coarse per-client-IP limiter on every request, plus tighter endpoint-specific limits on registration and auth challenge/verify (keyed by device ID, not IP).
- Added a per-device cumulative attachment storage quota (500 MB), independent of the existing per-upload size cap.
- Added a local-only admin dashboard (`admin.rs`, separate port from the main API, rejects any non-loopback request) with account/queue/storage stats and the ability to delete a stale test account — directly solving the beta-testing pain point where losing local device state left a username permanently stuck as "taken."
- Added a beta deployment guide (`docs/BETA_DEPLOYMENT.md`) for exposing the server via Cloudflare Tunnel, with explicit emphasis on never tunneling the admin port.
- Added a safety-number display (Windows client) — a symmetric, deterministic combination of both parties' identity keys, meant to be compared over an independent channel to catch a first-contact impersonation that TOFU pinning alone can't.
- Replaced ad-hoc, string-searched, or raw-JSON client error messages with `friendly_message(&ApiError)`, matching on actual HTTP status and structured error code — covers username-taken, protocol-version mismatch, rate-limiting, quota, expired session, and unreachable-server-vs-malformed-response cases.
- Verified restart/crash persistence: closing and reopening the database (including a real `SIGKILL` of the running server) does not lose data.
- Fixed a privacy-log gap where several routes leaked usernames/device/attachment IDs embedded in the URL path (not just query strings) into the access log, despite the log's stated design intent; added path normalization and a live verification.
- Ran a focused cryptographic protocol review (`docs/SECURITY_REVIEW.md`) of the handshake, ratchet, and server auth; addressed its three findings (missing out-of-band identity verification — see the safety number above; unprovable one-time-prekey omission — now surfaced visibly instead of silently; an alarmist error message for a benign long-offline-gap scenario).

## Previous — continued Phase 3 / hardening pass

- Added recipient-bound attachment capabilities. The server stores a SHA-256 digest of the capability and requires the capability for blob download; the capability is delivered inside the E2EE attachment payload.
- Added explicit session logout/revocation.
- Added account-level directory visibility control for username/UPM-ID discovery.
- Added startup cleanup for expired message envelopes, attachments, auth challenges, and sessions.
- Added a transport smoke-test binary (`upm-smoke`) covering registration, Ed25519 authentication, opaque send/pull/ack, protocol-version handling, and cross-device ACK rejection.
- Added initial Android, iOS, and Web typed API/platform boundary scaffolds; these are not yet production client implementations.
- Updated security review and build notes.

## Previous — Phase 0–3

See `docs/ROADMAP.md` and `docs/SECURITY_REVIEW.md` for the detailed implementation and security history.
