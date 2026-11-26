//! Kubedog — a desktop Kubernetes client (eframe/egui).
//! A desktop Kubernetes client.

// Windows, release builds: a windowed program, so no console window opens behind it.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
// The settings file is written with one json! of many fields.
#![recursion_limit = "256"]

mod app;
mod kube;
mod logo;
mod logparse;
mod menu;
mod resources;
mod theme;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // A windowed program on Windows has nowhere to print; borrow the console it was started from, if any.
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn AttachConsole(process: u32) -> i32;
        }
        // SAFETY: a plain system call without pointers; failing (no console) is fine.
        unsafe { AttachConsole(u32::MAX) }; // ATTACH_PARENT_PROCESS
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("kubedog {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let screenshot = args
        .iter()
        .position(|a| a == "--screenshot")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Kubedog")
        .with_inner_size(window_size())
        .with_min_inner_size([900.0, 560.0])
        // macOS: content runs under a transparent title bar.
        .with_fullsize_content_view(true)
        .with_titlebar_shown(false)
        .with_title_shown(false)
        // The Dock and window icon (assets/icons).
        .with_icon(std::sync::Arc::new({
            let (size, rgba) = logo::rgba(512);
            egui::IconData { rgba, width: size, height: size }
        }));
    if screenshot.is_some() {
        // A check must never steal focus from what the person is doing.
        viewport = viewport.with_active(false);
        #[cfg(target_os = "windows")]
        {
            viewport = viewport.with_window_level(egui::WindowLevel::AlwaysOnBottom);
        }
    }
    let mut options = eframe::NativeOptions {
        viewport,
        // Reopen at the size and place it was closed at (a screenshot always uses the fixed size).
        persist_window: screenshot.is_none(),
        ..Default::default()
    };
    #[cfg(target_os = "macos")]
    if screenshot.is_some() {
        options.event_loop_builder = Some(Box::new(|builder| {
            use winit::platform::macos::EventLoopBuilderExtMacOS;
            builder.with_activate_ignoring_other_apps(false);
        }));
    }

    eframe::run_native(
        "kubedog",
        options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            // The menu bar (not in screenshot mode: a check leaves the person's menus alone).
            #[cfg(target_os = "macos")]
            if screenshot.is_none() || std::env::var("KUBEDOG_SHOT_MENU").is_ok() {
                menu::install(cc.egui_ctx.clone());
            }
            Ok(Box::new(app::KubedogApp::new(
                cc.egui_ctx.clone(),
                screenshot,
            )))
        }),
    )
}

/// 1440×900, or KUBEDOG_SHOT_SIZE=WxH (a test aid for screenshots of bigger windows).
fn window_size() -> [f32; 2] {
    std::env::var("KUBEDOG_SHOT_SIZE")
        .ok()
        .and_then(|v| {
            let (w, h) = v.split_once('x')?;
            Some([w.trim().parse().ok()?, h.trim().parse().ok()?])
        })
        .unwrap_or([1440.0, 900.0])
}
