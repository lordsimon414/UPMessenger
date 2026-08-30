//! Windows Service wrapper (SRS §10 target platform).
//!
//! This module is only compiled on Windows (`main.rs` gates it behind
//! `#[cfg(windows)] mod service;`), so it never affects the Linux build
//! this project's CI runs, nor `upm-smoke`/the other crates.
//!
//! Three entry points, called from `main.rs`:
//! - `install()` — registers this executable with the Service Control
//!   Manager (SCM) as an automatic-start service.
//! - `uninstall()` — stops (if running) and removes it.
//! - `try_run_as_service()` — attempts to hand control to the SCM's
//!   service dispatcher. This only succeeds when the process was actually
//!   launched *by* the SCM (after `install` + `sc start` or a reboot);
//!   launched any other way (a dev's terminal, double-click), it fails
//!   immediately, and `main.rs` falls back to `run_console()`.
//!
//! The actual server logic (`build_server`/`run_server` in `main.rs`) is
//! shared between console mode and service mode — this module only adds
//! the SCM bookkeeping (status reporting, responding to Stop/Shutdown)
//! around a call into that same shared code, so the two modes can't drift
//! apart into different server behavior.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "UpmServer";
const SERVICE_DISPLAY_NAME: &str = "UPM Messenger Server";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Attempts to start the SCM service dispatcher. Blocks for the lifetime
/// of the service when it succeeds (i.e. when the SCM really did launch
/// this process); returns quickly with an error otherwise, which is the
/// signal `main.rs` uses to fall back to console mode.
pub fn try_run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// The FFI-facing entry point the SCM actually calls. `windows-service`
/// requires this exact `Vec<OsString> -> ()` shape (see
/// `define_windows_service!` above) — real error handling happens one
/// layer down, in `run_service`, since this function has nowhere to
/// report a `Result` to.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("upm-server: service failed: {e:?}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_for_handler = Arc::clone(&shutdown);

    let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                shutdown_for_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Same setup and accept/sweep loop as console mode (`run_console` in
    // main.rs) — the only difference is that `shutdown` here is actually
    // wired to something (the SCM control handler above) that can flip it
    // to true, giving a clean stop instead of a hard kill.
    let parts = crate::build_server();
    crate::run_server(parts, shutdown);

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

/// Registers this executable as an automatic-start Windows service. Must
/// be run once, elevated (as Administrator) — SCM registration itself
/// requires that privilege regardless of what account the service will
/// later run under.
pub fn install() -> windows_service::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let exe_path = std::env::current_exe().expect("failed to determine the current executable's path");

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        // None => run as LocalSystem. SRS §10 has no requirement for a
        // dedicated service account; revisit if that changes (a
        // least-privilege virtual service account would be the next
        // hardening step here).
        account_name: None,
        account_password: None,
    };

    let service = service_manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    // Cosmetic (shows up in services.msc) — if this specific call doesn't
    // compile against whatever windows-service version actually resolves,
    // it's safe to just delete this one line; everything else still works.
    let _ = service.set_description("UPM end-to-end encrypted messenger delivery server (SRS §10).");

    println!("Service '{SERVICE_NAME}' installed with automatic start.");
    println!("Start it now with: sc start {SERVICE_NAME}");
    println!("(Configure UPM_BIND / UPM_DB_PATH / UPM_ATTACHMENT_DIR etc. as system environment");
    println!(" variables before starting — a service has no inherited shell environment.)");
    Ok(())
}

/// Stops (if running) and removes the service registration. Also
/// requires an elevated prompt.
pub fn uninstall() -> windows_service::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager.open_service(SERVICE_NAME, service_access)?;

    let status = service.query_status()?;
    if status.current_state != ServiceState::Stopped {
        service.stop()?;
        // Give the running instance a moment to actually exit (it's doing
        // the same graceful shutdown as a Ctrl+C in console mode would,
        // if console mode had that wired up) before deleting it out from
        // under itself.
        std::thread::sleep(Duration::from_secs(2));
    }
    service.delete()?;

    println!("Service '{SERVICE_NAME}' uninstalled.");
    Ok(())
}
