#![cfg_attr(windows, windows_subsystem = "windows")]

mod api;
mod app;
mod identity;
mod local_store;
mod storage;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("UPM"),
        ..Default::default()
    };

    eframe::run_native(
        "UPM",
        options,
        Box::new(|cc| Ok(Box::new(app::UpmApp::new(cc)))),
    )
}
