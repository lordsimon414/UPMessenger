//! Local admin dashboard (beta-testing convenience, SRS §10 operator
//! tooling — not part of the client-facing protocol surface at all).
//!
//! # Critical deployment rule
//! This listens on a **separate port** from the main API (`UPM_ADMIN_BIND`,
//! default `127.0.0.1:8788`) specifically so it can never accidentally end
//! up reachable through whatever gets forwarded by a Cloudflare Tunnel or
//! reverse proxy (SRS §10.1's public-exposure path only ever targets the
//! main API port). **Never point a tunnel or port-forward at the admin
//! port.** As defense in depth on top of that operational rule, every
//! request here is also rejected unless it comes from the loopback
//! interface (`127.0.0.1`/`::1`) — see `is_loopback`.
//!
//! Everything here is either read-only aggregate stats/listings (no
//! message content, no key material) or the one destructive action this
//! exists for: deleting a stale test account so its username can be
//! reclaimed after local device state was lost during testing — a beta
//! workflow need, not a feature end users should have access to.

use crate::api::AppState;
use crate::db::{self, DbError};
use serde_json::json;
use std::net::IpAddr;
use tiny_http::{Header, Method, Request, Response};

fn is_loopback(request: &Request) -> bool {
    match request.remote_addr() {
        Some(addr) => match addr.ip() {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        },
        // No peer address at all (e.g. a non-TCP listener in some
        // environments) — fail closed rather than assume local.
        None => false,
    }
}

pub fn handle(state: &AppState, request: Request) {
    if !is_loopback(&request) {
        let header = Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..])
            .expect("static header is valid");
        let response = Response::from_string("admin dashboard is only reachable from localhost")
            .with_status_code(403)
            .with_header(header);
        let _ = request.respond(response);
        return;
    }

    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("");
    let segments: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let seg: Vec<&str> = segments.to_vec();

    let (status, content_type, body): (u16, &str, Vec<u8>) = match (&method, seg.as_slice()) {
        (Method::Get, []) | (Method::Get, ["admin"]) => (
            200,
            "text/html; charset=utf-8",
            render_dashboard(state).into_bytes(),
        ),
        (Method::Get, ["admin", "api", "stats"]) => json_response(admin_stats_json(state)),
        (Method::Get, ["admin", "api", "accounts"]) => json_response(admin_accounts_json(state)),
        (Method::Post, ["admin", "api", "accounts", username, "delete"]) => {
            json_response(admin_delete_account_json(state, username))
        }
        _ => (404, "text/plain", b"not found".to_vec()),
    };

    let header = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
        .expect("static header is valid");
    let response = Response::from_data(body)
        .with_status_code(status)
        .with_header(header);
    let _ = request.respond(response);
}

fn json_response(result: (u16, serde_json::Value)) -> (u16, &'static str, Vec<u8>) {
    (
        result.0,
        "application/json",
        result.1.to_string().into_bytes(),
    )
}

fn admin_stats_json(state: &AppState) -> (u16, serde_json::Value) {
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::admin_stats(&conn) {
        Ok(stats) => (200, serde_json::to_value(stats).unwrap_or(json!({}))),
        Err(e) => (500, json!({ "error": e.to_string() })),
    }
}

fn admin_accounts_json(state: &AppState) -> (u16, serde_json::Value) {
    let conn = state.db.lock().expect("db mutex poisoned");
    match db::admin_list_accounts(&conn) {
        Ok(accounts) => (200, json!({ "accounts": accounts })),
        Err(e) => (500, json!({ "error": e.to_string() })),
    }
}

fn admin_delete_account_json(state: &AppState, username: &str) -> (u16, serde_json::Value) {
    let storage_keys = {
        let conn = state.db.lock().expect("db mutex poisoned");
        match db::admin_delete_account(&conn, username) {
            Ok(keys) => keys,
            Err(DbError::UserNotFound) => return (404, json!({ "error": "no such account" })),
            Err(e) => return (500, json!({ "error": e.to_string() })),
        }
    };
    for storage_key in storage_keys {
        let path = state.attachment_dir.join(format!("{storage_key}.blob"));
        let _ = std::fs::remove_file(path); // best-effort; missing file is fine
    }
    (200, json!({ "deleted": username }))
}

fn render_dashboard(state: &AppState) -> String {
    let stats = {
        let conn = state.db.lock().expect("db mutex poisoned");
        db::admin_stats(&conn).ok()
    };
    let accounts = {
        let conn = state.db.lock().expect("db mutex poisoned");
        db::admin_list_accounts(&conn).unwrap_or_default()
    };

    let stats_html = match &stats {
        Some(s) => format!(
            "<div class=\"stats\">\
                <div class=\"stat\"><div class=\"n\">{}</div><div class=\"l\">accounts</div></div>\
                <div class=\"stat\"><div class=\"n\">{}</div><div class=\"l\">devices</div></div>\
                <div class=\"stat\"><div class=\"n\">{}</div><div class=\"l\">queued messages</div></div>\
                <div class=\"stat\"><div class=\"n\">{}</div><div class=\"l\">attachments ({} MB)</div></div>\
             </div>",
            s.account_count,
            s.device_count,
            s.queued_message_count,
            s.attachment_count,
            s.attachment_bytes_total / (1024 * 1024),
        ),
        None => "<p>Could not load stats.</p>".to_string(),
    };

    let rows: String = accounts.iter().fold(String::new(), |mut out, a| {
        use std::fmt::Write;
        let _ = write!(
            out,
            "<tr>\
                <td>{username}</td><td>{upm_id}</td><td>{devices}</td><td>{visible}</td>\
                <td><button onclick=\"deleteAccount('{username}')\">Delete</button></td>\
             </tr>",
            username = html_escape(&a.username),
            upm_id = html_escape(&a.upm_id),
            devices = a.device_count,
            visible = if a.directory_visible { "yes" } else { "no" },
        );
        out
    });

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>UPM server — local admin</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #222; }}
  h1 {{ font-size: 1.3rem; }}
  .warn {{ background: #fff3cd; border: 1px solid #ffe69c; padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1.5rem; }}
  .stats {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat {{ background: #f4f4f5; border-radius: 8px; padding: 0.75rem 1.25rem; text-align: center; }}
  .stat .n {{ font-size: 1.5rem; font-weight: 700; }}
  .stat .l {{ font-size: 0.8rem; color: #666; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #e5e5e5; font-size: 0.9rem; }}
  button {{ background: #b03a3a; color: white; border: none; border-radius: 4px; padding: 0.3rem 0.7rem; cursor: pointer; }}
  button:hover {{ background: #8f2e2e; }}
</style>
</head>
<body>
<h1>UPM server — local admin dashboard</h1>
<div class="warn">This page only works when opened on the server machine itself (localhost) — it is not, and must never be, exposed through the Cloudflare Tunnel or any reverse proxy. Deleting an account is irreversible.</div>
{stats_html}
<h2>Accounts</h2>
<table>
  <thead><tr><th>Username</th><th>UPM ID</th><th>Devices</th><th>Directory-visible</th><th></th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<script>
function deleteAccount(username) {{
  if (!confirm("Delete account '" + username + "' and everything it owns? This cannot be undone.")) return;
  fetch("/admin/api/accounts/" + encodeURIComponent(username) + "/delete", {{ method: "POST" }})
    .then(() => location.reload())
    .catch((e) => alert("Delete failed: " + e));
}}
</script>
</body>
</html>"#
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_neutralizes_markup() {
        assert_eq!(
            html_escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(
            html_escape("a & b \"quoted\""),
            "a &amp; b &quot;quoted&quot;"
        );
    }
}
