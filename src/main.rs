#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod io;
mod model;
mod pages;
mod ssh;
mod ufw;
mod worker;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 740.0])
            .with_min_inner_size([880.0, 560.0])
            .with_title(app::APP_NAME),
        ..Default::default()
    };
    eframe::run_native(
        app::APP_NAME,
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
