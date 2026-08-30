//! UPM delivery server (SRS §10).
//!
//! Binds to localhost only. Public/TLS exposure is intentionally NOT this
//! binary's job: SRS §10.1 puts the server behind a Cloudflare Tunnel
//! (`cloudflared`) with no open inbound ports, so TLS termination and
//! public routing happen at the tunnel edge. Running this server directly
//! reachable from the internet without such a tunnel (or an equivalent
//! reverse proxy) would violate that network-isolation requirement.
//!
//! # Running
//! - `upm-server` (no arguments): runs interactively in the current
//!   console — unchanged from earlier phases, and still how you'd run
//!   this during development on any platform.
//! - `upm-server install` / `upm-server uninstall` (Windows only):
//!   registers/removes this binary as a Windows service (automatic
//!   start), so it runs in the background without a logged-in session.
//! - When Windows' Service Control Manager launches this binary (after
//!   `install` + `sc start`), it's detected automatically — no special
//!   argument needed — and it runs as a proper service: reporting status
//!   to the SCM and shutting down cleanly on a Stop/Shutdown control
//!   instead of being hard-killed.

mod api;
mod auth;
mod db;
mod ratelimit;
#[cfg(windows)]
mod service;
mod util;

use api::AppState;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tiny_http::Server;

/// Number of worker threads handling requests concurrently. Each worker
/// pulls from the shared `tiny_http::Server` queue (a supported, documented
/// pattern — `Server` is `Sync`). Concurrency also gives panic isolation
/// for free: a panic inside `api::handle` (e.g. an unexpected-input bug we
/// haven't caught yet) unwinds only that worker's stack, not the whole
/// process, as long as we catch it at the top of the loop below — a single
/// bad request should degrade nothing beyond itself.
fn worker_count() -> usize {
    std::env::var("UPM_WORKER_THREADS").ok().and_then(|s| s.parse().ok()).filter(|n| *n > 0).unwrap_or(8)
}

/// How often the background sweep (expired messages/attachments/sessions,
/// orphaned attachment blob files, WAL checkpoint) runs.
fn sweep_interval() -> Duration {
    let secs = std::env::var("UPM_SWEEP_INTERVAL_SECONDS").ok().and_then(|s| s.parse().ok()).filter(|n| *n > 0).unwrap_or(300);
    Duration::from_secs(secs)
}

/// Everything needed to run the server, built but not yet serving
/// requests. Shared setup between console mode and the Windows service
/// entry point so the two can never drift apart.
pub struct ServerParts {
    state: Arc<AppState>,
    server: Arc<Server>,
    workers: usize,
}

/// Binds the listener and constructs `AppState` from the same environment
/// variables as before (`UPM_BIND`, `UPM_DB_PATH`, `UPM_ATTACHMENT_DIR`,
/// `UPM_WORKER_THREADS`). Panics on unrecoverable setup failure (bad bind
/// address, unwritable DB path) — there's no sensible way to run a
/// half-initialized server, in a console or as a service.
pub fn build_server() -> ServerParts {
    let bind_addr = std::env::var("UPM_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let db_path = std::env::var("UPM_DB_PATH").unwrap_or_else(|_| "upm.sqlite3".to_string());

    let conn = db::open(&db_path).expect("failed to open/initialize SQLite database");
    let attachment_dir: PathBuf =
        std::env::var("UPM_ATTACHMENT_DIR").unwrap_or_else(|_| "upm-attachments".to_string()).into();
    std::fs::create_dir_all(&attachment_dir).expect("failed to create attachment storage directory");
    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        attachment_dir,
        // Coarse guard on every request: 120 requests / 10s per client key.
        ip_limiter: ratelimit::RateLimiter::new(120, 10),
        // Registration is comparatively rare in normal use: 5 / 5 min per client key.
        register_limiter: ratelimit::RateLimiter::new(5, 300),
        // Auth challenge/verify keyed by device_id: 20 attempts / 5 min.
        // Generous enough for normal reconnects/retries, tight enough to
        // blunt a signature-guessing or resource-exhaustion attempt
        // against one account.
        auth_limiter: ratelimit::RateLimiter::new(20, 300),
    });

    let server = Arc::new(Server::http(&bind_addr).expect("failed to bind HTTP listener"));
    let workers = worker_count();
    println!("upm-server listening on http://{bind_addr} (db: {db_path}, {workers} worker threads)");
    println!("Reminder: expose this only via a tunnel/reverse proxy that terminates TLS (SRS §10.1).");

    ServerParts { state, server, workers }
}

/// Runs the accept loop and background sweep until `shutdown` becomes
/// `true`, then wakes and joins every worker thread, joins the sweep
/// thread, does one final WAL checkpoint, and returns. Used identically
/// by console mode (where nothing ever sets `shutdown`, so this simply
/// runs forever until the process is killed — the same behavior as
/// before this refactor) and by the Windows service entry point (where
/// the service control handler sets `shutdown` on a Stop/Shutdown
/// control, giving a clean stop instead of a hard kill).
pub fn run_server(parts: ServerParts, shutdown: Arc<AtomicBool>) {
    run_sweep(&parts.state); // clean up anything left over from a previous run before serving traffic

    let sweep_state = Arc::clone(&parts.state);
    let sweep_shutdown = Arc::clone(&shutdown);
    let sweep_interval_dur = sweep_interval();
    let sweep_handle = std::thread::spawn(move || {
        // Sleep in short ticks rather than one long sleep, so a shutdown
        // request doesn't have to wait out the whole interval.
        let tick = Duration::from_millis(500).min(sweep_interval_dur);
        let mut elapsed = Duration::ZERO;
        while !sweep_shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(tick);
            elapsed += tick;
            if elapsed >= sweep_interval_dur {
                elapsed = Duration::ZERO;
                run_sweep(&sweep_state);
            }
        }
    });

    let mut handles = Vec::with_capacity(parts.workers);
    for _ in 0..parts.workers {
        let server = Arc::clone(&parts.server);
        let state = Arc::clone(&parts.state);
        handles.push(std::thread::spawn(move || loop {
            match server.recv() {
                Ok(request) => {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        api::handle(&state, request);
                    }));
                    if outcome.is_err() {
                        eprintln!("upm-server: a request handler panicked; this worker keeps serving new requests");
                    }
                }
                Err(e) => {
                    eprintln!("upm-server: listener unblocked ({e}), worker thread exiting");
                    break;
                }
            }
        }));
    }

    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }

    println!("upm-server: shutdown requested, stopping worker threads...");
    // unblock() only wakes ONE thread blocked in recv() per call, so call
    // it once per worker to make sure all of them wake up and exit.
    for _ in 0..parts.workers {
        parts.server.unblock();
    }
    for handle in handles {
        let _ = handle.join();
    }
    let _ = sweep_handle.join();

    if let Ok(conn) = parts.state.db.lock() {
        if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
            eprintln!("upm-server: final WAL checkpoint failed: {e}");
        }
    }
    println!("upm-server: stopped cleanly");
}

/// Deletes expired DB rows (messages, attachments, auth challenges,
/// sessions) and the attachment blob files that go with them, then
/// checkpoints the WAL so it doesn't grow without bound under sustained
/// write load. Runs once at startup and then on `UPM_SWEEP_INTERVAL_SECONDS`.
fn run_sweep(state: &AppState) {
    let expired_storage_keys = {
        let conn = state.db.lock().expect("db mutex poisoned");
        match db::reap_expired_with_attachment_keys(&conn) {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("upm-server: sweep failed to reap expired rows: {e}");
                Vec::new()
            }
        }
    };
    for storage_key in expired_storage_keys {
        let path = state.attachment_dir.join(format!("{storage_key}.blob"));
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("upm-server: failed to remove expired attachment blob {path:?}: {e}");
            }
        }
    }

    let conn = state.db.lock().expect("db mutex poisoned");
    if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
        eprintln!("upm-server: WAL checkpoint failed: {e}");
    }
}

/// Runs forever in the current console until the process is killed —
/// identical behavior to every earlier phase of this project. `shutdown`
/// is never set by anything in this mode, so `run_server`'s wait loop
/// simply spins (harmlessly, at a 200ms poll) until an external kill.
fn run_console() {
    let parts = build_server();
    let shutdown = Arc::new(AtomicBool::new(false));
    run_server(parts, shutdown);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("install") => {
            #[cfg(windows)]
            {
                if let Err(e) = service::install() {
                    eprintln!("Failed to install the Windows service: {e:?}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                eprintln!("Windows service install is only available on Windows.");
                std::process::exit(1);
            }
        }
        Some("uninstall") => {
            #[cfg(windows)]
            {
                if let Err(e) = service::uninstall() {
                    eprintln!("Failed to uninstall the Windows service: {e:?}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                eprintln!("Windows service uninstall is only available on Windows.");
                std::process::exit(1);
            }
        }
        Some(other) => {
            eprintln!("Unknown argument: {other}");
            eprintln!("Usage: upm-server [install|uninstall]");
            std::process::exit(1);
        }
        None => {
            #[cfg(windows)]
            {
                // Launched directly (double-click, a dev's terminal, `cargo
                // run`) rather than by the Service Control Manager:
                // service_dispatcher::start fails immediately in that case
                // (there's no SCM control pipe to attach to), so fall back
                // to running interactively — exactly like every earlier
                // phase of this project.
                if service::try_run_as_service().is_err() {
                    run_console();
                }
            }
            #[cfg(not(windows))]
            {
                run_console();
            }
        }
    }
}
