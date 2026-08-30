# UPM login and account-creation debugging

## Expected local setup

Development defaults are:

- server: `http://127.0.0.1:8787`
- database: `upm.sqlite3`
- client: Windows desktop app

Start the server first, then start the Windows client. In the client, press **Connect**. The server panel performs `GET /v1/health`; a successful check shows `Connected`.

## Account creation flow

1. Enter a username (3–32 characters, no spaces/control characters).
2. Press **Register**.
3. The client sends the local Ed25519 public key; no private key is sent.
4. The server returns `user_id`, `upm_id`, and `device_id`.
5. The client immediately performs challenge/response login.
6. After login, the client publishes its X3DH bundle and one-time prekeys.

If registration returns HTTP 409, the username is already registered. Use another username or **New account** in the client.

## Login flow

Login is key-based, not password-based:

`device_id -> challenge -> Ed25519 signature -> session token`

A `404 device_not_found` means the locally saved device does not exist on the currently selected server. This commonly happens after switching to a new/reset server database. The client now reports that condition clearly instead of leaving an old local account looking valid.

A `401 invalid_signature` means the current local identity key does not match the public key stored for that device. Do not delete or replace keys blindly; use **New account** when the device identity is intentionally being reset.

## Repeatable smoke test

With the server running:

```powershell
cargo run -p upm-smoke -- http://127.0.0.1:8787
```

The smoke test covers health, registration, duplicate-user rejection, challenge-response login, logout/relogin, message queue send/pull/ack, and the cross-device ACK protection.
