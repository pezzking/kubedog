//! The macOS menu bar: Kubedog, Edit, View, Go, Window and Help, with the usual shortcuts.
//! Menu choices are queued here and handled by the window (`KubedogApp::raw_input_hook`
//! for editing, `KubedogApp::menu_commands` for the rest).

#[cfg(target_os = "macos")]
mod mac {
    use muda::accelerator::{Accelerator, Code, Modifiers};
    use muda::{AboutMetadata, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
    use std::sync::Mutex;

    static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// Pages on the Go menu: (id, label). The window maps the ids to pages.
    pub const GO_PAGES: [(&str, &str); 9] = [
        ("go:cluster", "Cluster Overview"),
        ("go:workloads", "Workloads Overview"),
        ("go:nodes", "Nodes"),
        ("go:pods", "Pods"),
        ("go:deployments", "Deployments"),
        ("go:services", "Services"),
        ("go:events", "Events"),
        ("go:helm", "Helm Releases"),
        ("go:settings", "Settings"),
    ];

    fn item(id: &str, text: &str, acc: Option<Accelerator>) -> MenuItem {
        MenuItem::with_id(id, text, true, acc)
    }

    fn cmd(code: Code) -> Option<Accelerator> {
        Some(Accelerator::new(Some(Modifiers::SUPER), code))
    }

    fn cmd_shift(code: Code) -> Option<Accelerator> {
        Some(Accelerator::new(Some(Modifiers::SUPER | Modifiers::SHIFT), code))
    }

    /// Build the menu bar and route its choices to the window. Call once, on the main thread.
    pub fn install(ctx: eframe::egui::Context) {
        let sep = || PredefinedMenuItem::separator();
        let about = AboutMetadata {
            name: Some("Kubedog".into()),
            version: Some(env!("CARGO_PKG_VERSION").into()),
            comments: Some("A desktop app for your Kubernetes clusters.".into()),
            ..Default::default()
        };
        let app = Submenu::with_items(
            "Kubedog",
            true,
            &[
                &PredefinedMenuItem::about(Some("About Kubedog"), Some(about)),
                &sep(),
                &item("settings", "Settings…", cmd(Code::Comma)),
                &item("switch", "Switch Clusters…", cmd_shift(Code::KeyO)),
                &sep(),
                &PredefinedMenuItem::services(None),
                &sep(),
                &PredefinedMenuItem::hide(Some("Hide Kubedog")),
                &PredefinedMenuItem::hide_others(None),
                &PredefinedMenuItem::show_all(None),
                &sep(),
                &PredefinedMenuItem::quit(Some("Quit Kubedog")),
            ],
        );
        let edit = Submenu::with_items(
            "Edit",
            true,
            &[
                &item("undo", "Undo", cmd(Code::KeyZ)),
                &item("redo", "Redo", cmd_shift(Code::KeyZ)),
                &sep(),
                &item("cut", "Cut", cmd(Code::KeyX)),
                &item("copy", "Copy", cmd(Code::KeyC)),
                &item("paste", "Paste", cmd(Code::KeyV)),
                &item("selectall", "Select All", cmd(Code::KeyA)),
                &sep(),
                &item("find", "Filter…", cmd(Code::KeyF)),
            ],
        );
        let view = Submenu::with_items(
            "View",
            true,
            &[
                &item("refresh", "Refresh", cmd(Code::KeyR)),
                &item("columns", "Columns…", None),
                &sep(),
                &item("zoomreset", "Actual Size", cmd(Code::Digit0)),
                &item("zoomin", "Zoom In", cmd(Code::Equal)),
                &item("zoomout", "Zoom Out", cmd(Code::Minus)),
                &sep(),
                &item("terminal", "Show or Hide Terminal", cmd(Code::KeyJ)),
                &sep(),
                &PredefinedMenuItem::fullscreen(Some("Enter Full Screen")),
            ],
        );
        let go_items: Vec<MenuItem> = GO_PAGES.iter().map(|(id, label)| item(id, label, None)).collect();
        let back = item("back", "Back", cmd(Code::BracketLeft));
        let forward = item("forward", "Forward", cmd(Code::BracketRight));
        let s1 = sep();
        let mut go_refs: Vec<&dyn muda::IsMenuItem> = vec![&back, &forward, &s1];
        for g in &go_items {
            go_refs.push(g);
        }
        let go = Submenu::with_items("Go", true, &go_refs);
        let window = Submenu::with_items(
            "Window",
            true,
            &[
                &PredefinedMenuItem::minimize(None),
                &PredefinedMenuItem::maximize(Some("Zoom")),
                &sep(),
                &PredefinedMenuItem::bring_all_to_front(None),
            ],
        );
        let help = Submenu::with_items("Help", true, &[&item("shortcuts", "Keyboard Shortcuts", cmd(Code::Slash))]);
        let (Ok(app), Ok(edit), Ok(view), Ok(go), Ok(window), Ok(help)) = (app, edit, view, go, window, help) else {
            eprintln!("menu bar could not be built");
            return;
        };
        let menu = Menu::new();
        if menu.append_items(&[&app, &edit, &view, &go, &window, &help]).is_err() {
            eprintln!("menu bar could not be built");
            return;
        }
        menu.init_for_nsapp();
        window.set_as_windows_menu_for_nsapp();
        help.set_as_help_menu_for_nsapp();
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            if let Ok(mut q) = EVENTS.lock() {
                q.push(e.id.0.clone());
            }
            ctx.request_repaint();
        }));
        // Test aid (KUBEDOG_SHOT_MENU=1 with --screenshot): list what was built.
        if std::env::var("KUBEDOG_SHOT_MENU").is_ok() {
            for top in menu.items() {
                if let Some(sm) = top.as_submenu() {
                    let names: Vec<String> = sm
                        .items()
                        .iter()
                        .map(|i| match i {
                            muda::MenuItemKind::MenuItem(m) => m.text(),
                            muda::MenuItemKind::Predefined(p) => if p.text().is_empty() { "—".into() } else { p.text() },
                            _ => "?".into(),
                        })
                        .collect();
                    eprintln!("menu {}: {}", sm.text(), names.join(" | "));
                }
            }
        }
        // The menu bar lives as long as the app.
        std::mem::forget((menu, app, edit, view, go, window, help, go_items, back, forward));
    }

    pub fn take() -> Vec<String> {
        EVENTS.lock().map(|mut q| std::mem::take(&mut *q)).unwrap_or_default()
    }
}

#[cfg(target_os = "macos")]
pub use mac::{install, take};

#[cfg(not(target_os = "macos"))]
pub fn take() -> Vec<String> {
    vec![]
}
