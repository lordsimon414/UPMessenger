//! UPM delivery server — Phase 1 (SRS §10).
//!
//! Binds to localhost only. Public/TLS exposure is intentionally NOT this
//! binary's job: SRS §10.1 puts the server behind a Cloudflare Tunnel
//! (`cloudflared`) with no open inbound ports, so TLS termination and
//! public routing happen at the tunnel edge. Running this server directly
//! reachable from the internet without such a tunnel (or an equivalent
//! reverse proxy) would violate that network-isolation requirement.

mod api;
mod auth;
mod db;
mod util;

use api::AppState;
use std::sync::Mutex;
use tiny_http::Server;

fn main() {
    let bind_addr = std::env::var("UPM_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let db_path = std::env::var("UPM_DB_PATH").unwrap_or_else(|_| "upm.sqlite3".to_string());

    let conn = db::open(&db_path).expect("failed to open/initialize SQLite database");
    let state = AppState {
        db: Mutex::new(conn),
    };

    let server = Server::http(&bind_addr).expect("failed to bind HTTP listener");
    println!("upm-server listening on http://{bind_addr} (db: {db_path})");
    println!(
        "Reminder: expose this only via a tunnel/reverse proxy that terminates TLS (SRS §10.1)."
    );

    for request in server.incoming_requests() {
        // Phase 1: handle requests sequentially against a single SQLite
        // connection behind a mutex. This is fine at the scale this SRS
        // targets (small/medium single-server deployment); revisit with a
        // connection pool + worker threads if the queue backs up.
        api::handle(&state, request);
    }
}
