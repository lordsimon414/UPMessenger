# Beta deployment: getting off localhost

This is the missing step between "it works on my machine" and "beta testers
can actually connect." It follows the deployment model this project has
assumed from the start (SRS §10.1): the server never listens on a public
interface directly — it binds to localhost only, and a Cloudflare Tunnel
gives it a public HTTPS URL without opening any inbound port on your
machine or router.

**Two separate things get exposed, and they must not share a tunnel:**
the main API (what the client talks to) and the local admin dashboard
(`admin.rs`, `/admin`). Only the main API is ever meant to leave your
machine. If you accidentally point a tunnel at the admin port, anyone on
the internet could delete accounts — see the warning banner on the
dashboard itself, and treat this document's port separation as
non-negotiable, not a suggestion.

## 1. Start the server as usual

```bash
UPM_BIND=127.0.0.1:8787 \
UPM_ADMIN_BIND=127.0.0.1:8788 \
UPM_DB_PATH=upm.sqlite3 \
UPM_ATTACHMENT_DIR=upm-attachments \
./upm-server
```

Nothing here changes for a beta — the server still only listens on
loopback. What changes is what sits in front of it.

## 2. Install cloudflared

Windows: download the installer from Cloudflare's `cloudflared` releases
page and run it, or `winget install --id Cloudflare.cloudflared`.
Verify with:

```powershell
cloudflared --version
```

## 3. Quick option: a free, temporary "Try Cloudflare" tunnel

Good for a first smoke test with a couple of beta testers, not for a
tunnel you want to keep stable across restarts (the URL changes every time
you start it).

```powershell
cloudflared tunnel --url http://127.0.0.1:8787
```

This prints a `https://<random-name>.trycloudflare.com` URL — that's what
goes in the Windows client's "Server" field (`https://<random-name>.trycloudflare.com`,
no port). Leave this process running for as long as beta testers need
access; closing it drops the tunnel.

**Do not run a second `cloudflared` process pointed at port 8788 (the
admin port).** If you want to check the dashboard while testing, do it
locally on the server machine at `http://127.0.0.1:8788/admin` — never
give that URL to anyone else, and never tunnel it.

## 4. Stable option: a named tunnel with your own domain

Better once you have real beta testers and want a URL that doesn't change
every restart. Requires a domain added to a (free) Cloudflare account.

```powershell
cloudflared tunnel login
cloudflared tunnel create upm-beta
```

This creates a tunnel and a credentials file (path printed by the
command — remember it for the config below). Add a DNS record pointing
your chosen hostname at the tunnel:

```powershell
cloudflared tunnel route dns upm-beta upm.yourdomain.com
```

Create a config file (e.g. `C:\Users\you\.cloudflared\config.yml`):

```yaml
tunnel: upm-beta
credentials-file: C:\Users\you\.cloudflared\<tunnel-id>.json

ingress:
  - hostname: upm.yourdomain.com
    service: http://127.0.0.1:8787
  - service: http_status:404
```

Note there is only **one** ingress rule pointing at a service — the admin
port (8788) has no entry here at all, which is exactly the point: nothing
in this config can ever route external traffic to it.

Run it:

```powershell
cloudflared tunnel run upm-beta
```

Beta testers now use `https://upm.yourdomain.com` as the server URL —
stable across restarts of both the server and the tunnel.

### Running the tunnel as a service too

`cloudflared` has its own service-install command, independent of
`upm-server`'s (see `docs/ROADMAP.md` for that one):

```powershell
cloudflared service install
```

This registers `cloudflared` itself as a Windows service using whichever
config file you last set up, so the tunnel survives a reboot the same way
`upm-server install` does for the server.

## 5. Before inviting beta testers, sanity-check the whole path

From a machine that is **not** on your local network (a phone on mobile
data works well), open the Windows client, set the server URL to your
tunnel's `https://` address, and walk through: register → log in →
resolve another test account → send a message → confirm it's received.
This is the same manual test you've already been doing against
`127.0.0.1` — the only thing that should be different is the URL.

Then, from your own machine, confirm the admin dashboard is
**unreachable** the same way:

```powershell
curl https://upm.yourdomain.com/admin
```

This must fail (connection refused, or a 404 from whatever's on that
hostname/port — anything except the dashboard). If it somehow succeeds,
stop and fix the tunnel config before telling anyone the server URL —
see `admin.rs`'s module docs for why this specific mistake is serious
(unauthenticated account deletion).

## 6. What beta testers need to be told

- The server URL (the `https://...` one, never `127.0.0.1`).
- That there is no password recovery: if they lose their device/app data,
  their old username is stuck until you (the operator) delete it via the
  local dashboard — this is expected, not a bug (see
  `docs/SECURITY_REVIEW.md` for why).
- That this is beta software: `docs/SECURITY_REVIEW.md`'s "still
  outstanding" list (no independent cryptographic audit yet, no
  safety-number verification prompt in the UI yet, etc.) applies to them
  too.

## Operational reminders once real traffic starts

- Watch the access log (stdout) for a lot of `429` responses — that's the
  rate limiter doing its job, but a sustained flood is worth
  investigating (see `ratelimit.rs`).
- The admin dashboard's stats page (`http://127.0.0.1:8788/admin`, on the
  server machine only) is the quickest way to see account/queue/storage
  growth without touching the database directly.
- `UPM_SWEEP_INTERVAL_SECONDS` (default 300) controls how often expired
  messages/attachments get cleaned up and the WAL gets checkpointed — the
  defaults are fine for a small beta, no action needed.
