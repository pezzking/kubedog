//! The Settings page: a list of sections on the left, one section on the right.
//! Everything here is Kubedog's own; kubeconfig files are only changed from the
//! Kubeconfig files section, and only when asked.

use super::*;

/// Section names, in the order they're listed.
pub(super) const SECTIONS: [(&str, &str); 11] = [
    ("General", "⚙"),
    ("Clusters", "◆"),
    ("Kubeconfig files", "⛁"),
    ("Sidebar", "☰"),
    ("Superpowers", "⚡"),
    ("Special monitoring", "◎"),
    ("AI", "✨"),
    ("Terminal", ">_"),
    ("Logs", "≡"),
    ("Shortcuts", "⌘"),
    ("About", "ℹ"),
];

impl KubedogApp {
    pub(super) fn settings_view(&mut self, ui: &mut Ui) {
        self.header(ui, false, None, false);
        self.settings_body(ui);
    }

    /// Settings from the start page, before any cluster is open: a way back instead of the top bar.
    pub(super) fn settings_at_start(&mut self, ui: &mut Ui) {
        ui.add_space(u(30.0));
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            if button(ui, "‹  Back to the clusters", false, false) || (ui.input(|i| i.key_pressed(Key::Escape)) && self.dialog.is_none() && !ui.ctx().memory(|m| m.focused().is_some())) {
                self.start_settings = false;
            }
        });
        ui.add_space(6.0);
        ui.separator();
        self.settings_body(ui);
    }

    fn settings_body(&mut self, ui: &mut Ui) {
        if self.screenshot.is_some() {
            if let Ok(want) = std::env::var("KUBEDOG_SHOT_SETTINGS") {
                if let Some(s) = SECTIONS.iter().find(|s| s.0.eq_ignore_ascii_case(&want) || s.0.to_lowercase().starts_with(&want.to_lowercase())) {
                    self.settings_section = s.0;
                }
            }
        }
        let area = ui.available_rect_before_wrap();
        let left = egui::Rect::from_min_size(area.min, egui::vec2(u(200.0), area.height()));
        let right = egui::Rect::from_min_max(egui::pos2(left.right() + 1.0, area.top()), area.max);
        ui.painter().vline(left.right(), area.y_range(), Stroke::new(1.0, BORDER_SUBTLE()));

        ui.scope_builder(egui::UiBuilder::new().max_rect(left.shrink2(egui::vec2(10.0, 0.0))), |ui| {
            ui.add_space(10.0);
            ui.label(RichText::new("Settings").size(z(20.0)).color(TEXT_DEFAULT()));
            ui.add_space(12.0);
            for (name, icon) in SECTIONS {
                let on = self.settings_section == name;
                let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(32.0)), Sense::click());
                let p = ui.painter();
                if on {
                    p.rect_filled(r, CornerRadius::same(6), BG_SELECTED());
                    p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(3.0, r.height())), CornerRadius::same(2), PRIMARY_TEXT());
                } else if resp.hovered() {
                    p.rect_filled(r, CornerRadius::same(6), BG_HOVER());
                }
                p.text(r.left_center() + egui::vec2(20.0, 0.0), egui::Align2::CENTER_CENTER, icon, FontId::proportional(z(13.0)), TEXT_SUBTLE());
                p.text(r.left_center() + egui::vec2(38.0, 0.0), egui::Align2::LEFT_CENTER, name, FontId::proportional(z(14.5)), if on { TEXT_DEFAULT() } else { TEXT_MUTED() });
                if resp.clicked() {
                    self.settings_section = name;
                }
                ui.add_space(2.0);
            }
        });

        ui.scope_builder(egui::UiBuilder::new().max_rect(right.shrink2(egui::vec2(28.0, 0.0))), |ui| {
            egui::ScrollArea::vertical().id_salt("settings-pane").auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(12.0);
                match self.settings_section {
                    "Clusters" => self.settings_clusters(ui),
                    "Kubeconfig files" => {
                        title(ui, "Kubeconfig files", "Where Kubedog finds your clusters. It starts with the same files kubectl uses.");
                        self.kubeconfig_files_card(ui);
                    }
                    "Sidebar" => self.settings_sidebar(ui),
                    "Superpowers" => self.settings_powers(ui),
                    "Special monitoring" => self.settings_monitoring(ui),
                    "AI" => self.settings_ai(ui),
                    "Terminal" => self.settings_terminal(ui),
                    "Logs" => self.settings_logs(ui),
                    "Shortcuts" => settings_shortcuts(ui),
                    "About" => self.settings_about(ui),
                    _ => self.settings_general(ui),
                }
                ui.add_space(24.0);
            });
        });
    }

    fn settings_general(&mut self, ui: &mut Ui) {
        title(ui, "General", "How Kubedog looks, how it starts and how often it reads your clusters.");
        let mut changed = false;
        card(ui, |ui| {
            heading(ui, "Theme");
            hint(ui, "The background. Auto follows your system: light by day, dark by night, or however you've set it.");
            ui.add_space(8.0);
            let accent = crate::theme::ACCENTS.iter().find(|a| a.id == self.prefs.accent).unwrap_or(&crate::theme::ACCENTS[0]);
            ui.horizontal_wrapped(|ui| {
                for (id, label) in crate::theme::THEMES {
                    let on = self.prefs.theme == id;
                    if theme_preview(ui, id, accent, label, on).clicked() && !on {
                        self.prefs.theme = id.to_string();
                        self.apply_theme();
                        changed = true;
                    }
                    ui.add_space(10.0);
                }
            });
            ui.add_space(14.0);
            heading(ui, "Colour");
            hint(ui, "Names, links, buttons and highlights, in any theme.");
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                for a in &crate::theme::ACCENTS {
                    let on = self.prefs.accent == a.id;
                    if accent_chip(ui, a, on).clicked() && !on {
                        self.prefs.accent = a.id.to_string();
                        self.apply_theme();
                        changed = true;
                    }
                }
            });
            ui.add_space(14.0);
            heading(ui, "Font");
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                for (id, label) in crate::theme::FONTS {
                    let on = self.prefs.font == id;
                    if pick_chip(ui, label, FontId::new(z(14.0), crate::theme::font_family(id)), on).clicked() && !on {
                        self.prefs.font = id.to_string();
                        self.apply_font();
                        changed = true;
                    }
                }
            });
            ui.add_space(14.0);
            heading(ui, "Text size");
            hint(ui, "For the whole app. Logs have their own size in Logs, and ⌘+ and ⌘- zoom everything.");
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                for n in crate::theme::TEXT_SIZES {
                    let on = self.prefs.text_size == n;
                    let label = if n == crate::theme::NORMAL_TEXT { format!("{n} (normal)") } else { n.to_string() };
                    if pick_chip(ui, &label, FontId::proportional(z(14.0)), on).clicked() && !on {
                        self.prefs.text_size = n;
                        self.apply_theme();
                        self.list_cache = None;
                        changed = true;
                    }
                }
            });
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            heading(ui, "When Kubedog opens");
            changed |= option(ui, &mut self.prefs.startup, "reconnect", "Continue where I left off", "Opens the clusters you had open, on the page and namespace you were on, at the same zoom and window size. If a cluster can't be reached, its page says so.");
            changed |= option(ui, &mut self.prefs.startup, "start", "Show the start page", "Pick the clusters to open each time.");
            ui.add_space(8.0);
            row(ui, "First page after connecting", |ui| {
                let cur = FIRST_PAGES.iter().find(|f| f.0 == self.prefs.first_page).map(|f| f.1).unwrap_or("Pods");
                egui::ComboBox::from_id_salt("first-page").selected_text(cur).width(200.0).show_ui(ui, |ui| {
                    for (v, label) in FIRST_PAGES {
                        changed |= ui.selectable_value(&mut self.prefs.first_page, v.to_string(), label).changed();
                    }
                });
            });
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            heading(ui, "Refresh");
            row(ui, "Lists", |ui| {
                egui::ComboBox::from_id_salt("refresh").selected_text(secs(self.prefs.refresh_secs)).width(200.0).show_ui(ui, |ui| {
                    for v in REFRESH_CHOICES {
                        changed |= ui.selectable_value(&mut self.prefs.refresh_secs, v, secs(v)).changed();
                    }
                });
            });
            hint(ui, "How often the page you're on is read again. Shorter is more up to date but asks the cluster more often.");
            ui.add_space(6.0);
            row(ui, "CPU and memory", |ui| {
                egui::ComboBox::from_id_salt("metrics").selected_text(secs(self.prefs.metrics_secs)).width(200.0).show_ui(ui, |ui| {
                    for v in METRICS_CHOICES {
                        changed |= ui.selectable_value(&mut self.prefs.metrics_secs, v, secs(v)).changed();
                    }
                });
            });
            hint(ui, "Usage comes from the cluster's metrics server (kubectl top), which itself updates about every 15 seconds.");
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            heading(ui, "Filter");
            changed |= ui.checkbox(&mut self.prefs.shared_filter, "Keep the filter when moving between pages").changed();
            hint(ui, "The 🔗 next to the filter box. On: what you type stays as you change pages, and Nodes keeps a filter of its own. Off: each page starts empty.");
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            heading(ui, "Starred namespaces");
            if self.prefs.starred_namespaces.is_empty() {
                hint(ui, "None yet. Star a namespace with ☆ in the namespace picker or on the Namespaces page.");
            }
            let mut remove: Option<String> = None;
            for ns in &self.prefs.starred_namespaces {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("★").color(WARNING()));
                    ui.label(RichText::new(ns).color(TEXT_DEFAULT()));
                    if ui.small_button("Unstar").clicked() {
                        remove = Some(ns.clone());
                    }
                });
            }
            if let Some(n) = remove {
                self.toggle_star(&n);
            }
        });
        if changed {
            self.save();
        }
        self.settings_backup(ui);
    }

    fn settings_clusters(&mut self, ui: &mut Ui) {
        title(
            ui,
            "Clusters",
            "Give clusters a shorter name and a colour, and choose their order on the start page. For an account that may only see some namespaces, list them under Namespaces (* matches anything); Kubedog then reads only those. This is kept by Kubedog; your kubeconfig files aren't changed.",
        );
        // Every context, in the start page's order.
        let mut names: Vec<String> = self.contexts.iter().map(|c| c.name.clone()).collect();
        names.dedup();
        let order = self.prefs.ctx_order.clone();
        names.sort_by_key(|n| order.iter().position(|o| o == n).unwrap_or(usize::MAX));
        let mut changed = false;
        let mut swap: Option<(usize, usize)> = None;
        card(ui, |ui| {
            heading(ui, "Protection");
            hint(ui, "Every cluster starts protected when Kubedog opens: nothing in it can be changed until changes are allowed with its lock, for that session. Here a cluster can start with changes allowed instead. Changes still ask before they're done.");
            ui.add_space(8.0);
            let was = self.prefs.open_all;
            ui.radio_value(&mut self.prefs.open_all, false, "Start protected, except the clusters ticked below (recommended)");
            ui.radio_value(&mut self.prefs.open_all, true, "Every cluster starts with changes allowed");
            if was != self.prefs.open_all {
                changed = true;
                if self.prefs.open_all {
                    // Open clusters follow at once.
                    for c in self.active.clone() {
                        self.unlocked.insert(c);
                    }
                }
            }
        });
        ui.add_space(12.0);
        card(ui, |ui| {
            if names.is_empty() {
                hint(ui, "No clusters found. Add a kubeconfig file in Kubeconfig files.");
            }
            let n = names.len();
            for (i, name) in names.iter().enumerate() {
                let info = self.contexts.iter().find(|c| &c.name == name).cloned();
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        if ui.add_enabled(i > 0, egui::Button::new(RichText::new("▲").size(z(9.0))).frame(false)).on_hover_text("Move up").clicked() {
                            swap = Some((i, i - 1));
                        }
                        if ui.add_enabled(i + 1 < n, egui::Button::new(RichText::new("▼").size(z(9.0))).frame(false)).on_hover_text("Move down").clicked() {
                            swap = Some((i, i + 1));
                        }
                    });
                    let (r, _) = ui.allocate_exact_size(egui::vec2(30.0, 30.0), Sense::hover());
                    ctx_mark(ui.painter(), r, name);
                    ui.vertical(|ui| {
                        ui.set_width(320.0);
                        ui.add(egui::Label::new(RichText::new(name).size(z(13.5)).color(TEXT_DEFAULT())).truncate());
                        let host = info.as_ref().map(|c| c.server.trim_start_matches("https://").to_string()).unwrap_or_default();
                        ui.add(egui::Label::new(RichText::new(host).size(z(11.5)).color(TEXT_SUBTLE())).truncate());
                    });
                    let mut alias = self.prefs.ctx_alias.get(name).cloned().unwrap_or_default();
                    if ui.add(egui::TextEdit::singleline(&mut alias).hint_text("Short name").char_limit(MAX_CLUSTER_NAME).desired_width(200.0)).changed() {
                        if alias.trim().is_empty() {
                            self.prefs.ctx_alias.remove(name);
                        } else {
                            self.prefs.ctx_alias.insert(name.clone(), alias);
                        }
                        changed = true;
                    }
                    ui.add_space(8.0);
                    let cur = context_color_index(name);
                    for (ci, col) in CTX_PALETTE.iter().enumerate() {
                        let (r, resp) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), Sense::click());
                        ui.painter().circle_filled(r.center(), 7.0, *col);
                        if ci == cur {
                            ui.painter().circle_stroke(r.center(), 9.0, Stroke::new(1.5, TEXT_DEFAULT()));
                        }
                        if resp.on_hover_text("Use this colour").clicked() {
                            self.prefs.ctx_color.insert(name.clone(), ci);
                            changed = true;
                        }
                    }
                    if self.prefs.ctx_color.contains_key(name) && ui.small_button("Reset").on_hover_text("Back to its own colour").clicked() {
                        self.prefs.ctx_color.remove(name);
                        changed = true;
                    }
                });
                ui.horizontal(|ui| {
                    ui.add_space(38.0);
                    ui.vertical(|ui| self.namespaces_field(ui, name, false));
                });
                ui.horizontal(|ui| {
                    ui.add_space(38.0);
                    let mut open = self.prefs.open_all || self.prefs.open_at_start.contains(name);
                    let r = ui.add_enabled(!self.prefs.open_all, egui::Checkbox::new(&mut open, RichText::new("Changes allowed from the start").size(z(13.0)).color(TEXT_MUTED())));
                    if r.on_disabled_hover_text("Every cluster starts with changes allowed (above)").changed() {
                        self.prefs.open_at_start.retain(|c| c != name);
                        if open {
                            self.prefs.open_at_start.push(name.clone());
                            if self.active.contains(name) {
                                self.unlocked.insert(name.clone());
                            }
                        }
                        changed = true;
                    }
                });
                if i + 1 < n {
                    ui.add_space(4.0);
                    ui.separator();
                    ui.add_space(4.0);
                }
            }
        });
        if let Some((a, b)) = swap {
            names.swap(a, b);
            self.prefs.ctx_order = names.clone();
            changed = true;
        }

        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Groups").size(z(17.0)).color(TEXT_DEFAULT()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, "+ New group", false, false) {
                    let contexts = if self.connected { self.active.clone() } else { vec![] };
                    self.prefs.groups.push(Group { name: format!("Group {}", self.prefs.groups.len() + 1), contexts });
                    changed = true;
                }
            });
        });
        hint(ui, "A group opens several clusters at once, from the start page or with ⌃1 to ⌃9 for the first nine. A new group starts with the clusters you have open.");
        ui.add_space(6.0);
        if self.prefs.groups.is_empty() {
            Frame::new().stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(8)).inner_margin(Margin::same(24)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("No groups yet").size(z(15.0)).color(TEXT_DEFAULT()));
                    hint(ui, "Make one here, or pick two or more clusters on the start page and save them as a group.");
                });
            });
        }
        let mut delete: Option<usize> = None;
        let mut open: Option<usize> = None;
        let mut moved: Option<(usize, usize)> = None;
        let ng = self.prefs.groups.len();
        for gi in 0..ng {
            ui.add_space(8.0);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    if gi < 9 {
                        keycap(ui, &format!("⌃{}", gi + 1));
                    }
                    let g = &mut self.prefs.groups[gi];
                    changed |= ui.add(egui::TextEdit::singleline(&mut g.name).desired_width(220.0)).changed();
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if button(ui, "Delete", false, false) {
                            delete = Some(gi);
                        }
                        if button(ui, "Open", true, false) {
                            open = Some(gi);
                        }
                        if gi + 1 < ng && ui.add(egui::Button::new("▼").frame(false)).on_hover_text("Move down").clicked() {
                            moved = Some((gi, gi + 1));
                        }
                        if gi > 0 && ui.add(egui::Button::new("▲").frame(false)).on_hover_text("Move up").clicked() {
                            moved = Some((gi, gi - 1));
                        }
                    });
                });
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    for name in &names {
                        let g = &mut self.prefs.groups[gi];
                        let mut on = g.contexts.contains(name);
                        if ui.checkbox(&mut on, ctx_label(name)).changed() {
                            if on {
                                g.contexts.push(name.clone());
                            } else {
                                g.contexts.retain(|c| c != name);
                            }
                            changed = true;
                        }
                    }
                    // Contexts no longer in any file are kept, so the group works again if they come back.
                    let gone = self.prefs.groups[gi].contexts.iter().filter(|c| !names.contains(c)).count();
                    if gone > 0 {
                        ui.label(RichText::new(format!("+ {gone} not in your files")).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                    }
                });
            });
        }
        if let Some((a, b)) = moved {
            self.prefs.groups.swap(a, b);
            changed = true;
        }
        if let Some(i) = delete {
            self.prefs.groups.remove(i);
            changed = true;
        }
        if changed {
            self.save();
        }
        if let Some(i) = open {
            self.open_group(i);
        }
    }

    fn settings_terminal(&mut self, ui: &mut Ui) {
        title(ui, "Terminal", "Where “Shell” and “>_” open.");
        card(ui, |ui| {
            let mut changed = false;
            for (id, label, _) in terminal::APPS {
                let have = terminal::installed(id);
                ui.add_enabled_ui(have, |ui| {
                    let r = ui.radio_value(&mut self.prefs.terminal, id.to_string(), *label);
                    changed |= r.changed();
                    if !have {
                        r.on_disabled_hover_text("Not installed on this Mac");
                    }
                });
                if *id == "builtin" {
                    ui.indent("builtin-hint", |ui| hint(ui, "Docks at the bottom of the window. ⌘J shows or hides it; while it has focus, keys go to the shell."));
                }
            }
            if changed {
                self.prefs.terminal_chosen = true;
                self.save();
            }
        });
        self.settings_shell(ui);
    }

    fn settings_logs(&mut self, ui: &mut Ui) {
        title(ui, "Logs", "How pod and container logs are shown. The choices below are where a new log view starts; you can still change them while reading.");
        let mut changed = false;
        card(ui, |ui| {
            row(ui, "Text size", |ui| {
                changed |= ui.add(egui::Slider::new(&mut self.prefs.log_size, 9.0..=20.0).step_by(1.0).fixed_decimals(0).suffix(" pt")).changed();
            });
            row(ui, "Start with", |ui| {
                egui::ComboBox::from_id_salt("log-since").selected_text(self.prefs.log_since.clone()).width(140.0).show_ui(ui, |ui| {
                    for s in SINCE_CHOICES {
                        changed |= ui.selectable_value(&mut self.prefs.log_since, s.to_string(), s).changed();
                    }
                });
            });
            ui.add_space(4.0);
            changed |= ui.checkbox(&mut self.prefs.log_wrap, "Wrap long lines").changed();
            changed |= ui.checkbox(&mut self.prefs.log_timestamps, "Show time stamps").changed();
            ui.add_space(10.0);
            Frame::new().fill(BG_DEFAULT()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let ts = if self.prefs.log_timestamps { "2026-11-20T09:14:02Z " } else { "" };
                for (text, level) in [
                    ("level=info msg=\"listening\" port=8080", Level::Info),
                    ("level=warn msg=\"slow reply from upstream\" took=2.4s", Level::Warn),
                    ("level=error msg=\"connection refused\" retry=3", Level::Error),
                ] {
                    ui.label(RichText::new(format!("{ts}{text}")).monospace().size(self.prefs.log_size).color(level_color(level)));
                }
            });
        });
        if changed {
            self.log_prefs.wrap = self.prefs.log_wrap;
            self.log_prefs.timestamps = self.prefs.log_timestamps;
            if let Some(since) = SINCE_CHOICES.iter().copied().find(|x| *x == self.prefs.log_since) {
                self.log_prefs.since = since;
            }
            self.save();
        }
    }

    fn settings_about(&mut self, ui: &mut Ui) {
        let (r, _) = ui.allocate_exact_size(egui::vec2(96.0, 96.0), Sense::hover());
        app_mark(ui.painter(), r);
        ui.add_space(6.0);
        title(ui, "Kubedog", "Talks to your clusters through kubectl.");
        card(ui, |ui| {
            kv(ui, "Version", env!("CARGO_PKG_VERSION"));
            match &self.kubectl.wsl {
                Some(w) => {
                    kv(ui, "kubectl", format!("{} in {} (WSL)", w.kubectl, w.linux));
                    kv(ui, "helm", if w.helm.is_empty() { format!("not installed in {} (Helm page is empty)", w.linux) } else { format!("{} in {} (WSL)", w.helm, w.linux) });
                    kv(ui, "Kubeconfig", format!("{} in {} (WSL)", w.kubeconfig.join(", "), w.linux));
                }
                None => {
                    kv(ui, "kubectl", self.kubectl.bin.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "not found".into()));
                    kv(ui, "helm", self.kubectl.helm.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "not found (Helm page is empty)".into()));
                }
            }
            kv(ui, "Settings file", prefs_path().map(|p| clusters::short_path(&p.to_string_lossy())).unwrap_or_default());
            kv(ui, "Thanks to", "PathViz by Ivan Velichko (MIT licence): parts of the packet decoder began there; see THIRD-PARTY.md");
        });
        self.settings_update(ui);
    }
}

fn settings_shortcuts(ui: &mut Ui) {
    title(ui, "Shortcuts", "Keys work when you're not typing in a box.");
    let section = |ui: &mut Ui, name: &str, rows: &[(&[&str], &str)]| {
        card(ui, |ui| {
            heading(ui, name);
            for (keys, what) in rows {
                ui.horizontal(|ui| {
                    ui.set_min_height(26.0);
                    ui.allocate_ui_with_layout(egui::vec2(150.0, 24.0), Layout::left_to_right(Align::Center), |ui| {
                        ui.set_min_width(150.0);
                        for k in keys.iter() {
                            keycap(ui, k);
                        }
                    });
                    ui.label(RichText::new(*what).color(TEXT_DEFAULT()));
                });
            }
        });
        ui.add_space(10.0);
    };
    section(
        ui,
        "Anywhere",
        &[
            (&["⌘K"], "Search pages and objects"),
            (&["⌘F"], "Go to the filter box"),
            (&["⌘A"], "Tick everything a list shows (⌘-click one, ⇧-click a range, Esc clears)"),
            (&["⌘R"], "Refresh now"),
            (if cfg!(target_os = "macos") { &["⌘[", "⌘←"] } else { &["Alt←"] }, "Back, as in a browser: from an object to its list, else to where you came from; also the mouse's back button"),
            (if cfg!(target_os = "macos") { &["⌘]", "⌘→"] } else { &["Alt→"] }, "Forward; also the mouse's forward button"),
            (&["⌘J"], "Show or hide the built-in terminal"),
            (&["⌃1-9"], "Open a cluster group"),
            (&["⌘="], "Zoom in"),
            (&["⌘-"], "Zoom out"),
            (&["⌘0"], "Actual size"),
            (&["Esc"], "Close the object you're looking at"),
        ],
    );
    let go: Vec<(String, &str)> = GO_KEYS.iter().map(|(k, _, label)| (k.symbol_or_name().to_string(), *label)).collect();
    card(ui, |ui| {
        heading(ui, "Go to (press G, then the letter)");
        for (k, label) in &go {
            ui.horizontal(|ui| {
                ui.set_min_height(26.0);
                ui.allocate_ui_with_layout(egui::vec2(150.0, 24.0), Layout::left_to_right(Align::Center), |ui| {
                    ui.set_min_width(150.0);
                    keycap(ui, "G");
                    keycap(ui, k);
                });
                ui.label(RichText::new(*label).color(TEXT_DEFAULT()));
            });
        }
    });
    ui.add_space(10.0);
    section(
        ui,
        "On an object's page",
        &[
            (&["L"], "Logs"),
            (&["E"], "YAML"),
            (&["R"], "Restart (asks first)"),
            (&["S"], "Scale (asks first)"),
            (&["⌘⌫"], "Delete (asks first)"),
        ],
    );
    section(
        ui,
        "Start page",
        &[
            (&["↑", "↓"], "Move through the clusters"),
            (&["Space"], "Pick or unpick a cluster"),
            (&["Enter"], "Connect"),
            (&["⌘A"], "Pick all"),
        ],
    );
}

fn keycap(ui: &mut Ui, k: &str) {
    Frame::new()
        .fill(BG_MUTED())
        .stroke(Stroke::new(1.0, BORDER_DEFAULT()))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(6, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(k).size(z(12.5)).color(TEXT_MUTED()));
        });
}

pub(super) fn title(ui: &mut Ui, t: &str, sub: &str) {
    ui.label(RichText::new(t).size(z(20.0)).color(TEXT_DEFAULT()));
    ui.add_space(2.0);
    ui.add(egui::Label::new(RichText::new(sub).size(z(13.0)).color(TEXT_SUBTLE())).wrap());
    ui.add_space(12.0);
}

fn heading(ui: &mut Ui, t: &str) {
    ui.label(RichText::new(t).size(z(15.0)).strong().color(TEXT_DEFAULT()));
    ui.add_space(4.0);
}

pub(super) fn hint(ui: &mut Ui, t: &str) {
    ui.add(egui::Label::new(RichText::new(t).size(z(12.5)).color(TEXT_SUBTLE())).wrap());
}

fn row(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(egui::vec2(220.0, 22.0), Layout::left_to_right(Align::Center), |ui| {
            ui.set_min_width(220.0);
            ui.label(RichText::new(label).color(TEXT_MUTED()));
        });
        add(ui);
    });
}

/// A radio choice with a line of explanation under it. Returns whether it was picked now.
fn option(ui: &mut Ui, cur: &mut String, value: &str, label: &str, sub: &str) -> bool {
    let r = ui.radio_value(cur, value.to_string(), RichText::new(label).color(TEXT_DEFAULT()));
    ui.indent(value, |ui| hint(ui, sub));
    ui.add_space(4.0);
    r.changed()
}

fn secs(v: u64) -> String {
    if v >= 60 {
        format!("{} minute{}", v / 60, if v >= 120 { "s" } else { "" })
    } else {
        format!("{v} seconds")
    }
}

/// A small picture of a theme in the chosen colour. Auto is half dark, half light.
fn theme_preview(ui: &mut Ui, id: &str, accent: &crate::theme::Accent, label: &str, on: bool) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(170.0, 128.0), Sense::click());
    let shot = egui::Rect::from_min_size(r.min, egui::vec2(r.width(), 100.0));
    if id == "auto" {
        let mid = shot.center().x;
        let clip = ui.clip_rect();
        paint_theme(&ui.painter().with_clip_rect(clip.intersect(egui::Rect::from_min_max(shot.min, egui::pos2(mid, shot.bottom())))), shot, "dark", accent);
        paint_theme(&ui.painter().with_clip_rect(clip.intersect(egui::Rect::from_min_max(egui::pos2(mid, shot.top()), shot.max))), shot, "light", accent);
    } else {
        paint_theme(ui.painter(), shot, id, accent);
    }
    let painter = ui.painter();
    painter.rect_stroke(shot, CornerRadius::same(8), Stroke::new(if on { 2.5 } else { 1.0 }, if on { PRIMARY_TEXT() } else { BORDER_DEFAULT() }), egui::StrokeKind::Outside);
    painter.text(egui::pos2(r.center().x, r.bottom() - 10.0), egui::Align2::CENTER_CENTER, if on { format!("✓ {label}") } else { label.to_string() }, FontId::proportional(z(13.5)), if on { TEXT_DEFAULT() } else { TEXT_MUTED() });
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// A sidebar, a card with lines of text and a button, in a theme's colours.
fn paint_theme(painter: &egui::Painter, shot: egui::Rect, theme: &str, accent: &crate::theme::Accent) {
    let p = crate::theme::palette_of(theme);
    let t = accent.tint(theme);
    painter.rect_filled(shot, CornerRadius::same(8), p.bg_default);
    let side = egui::Rect::from_min_size(shot.min, egui::vec2(46.0, shot.height()));
    painter.rect_filled(side, CornerRadius { nw: 8, sw: 8, ne: 0, se: 0 }, p.bg_subtle);
    for i in 0..4 {
        let y = shot.top() + 16.0 + i as f32 * 14.0;
        painter.rect_filled(egui::Rect::from_min_size(egui::pos2(shot.left() + 8.0, y), egui::vec2(28.0, 5.0)), CornerRadius::same(2), if i == 1 { p.bg_selected } else { p.text_subtle });
    }
    let card = egui::Rect::from_min_max(egui::pos2(side.right() + 10.0, shot.top() + 12.0), egui::pos2(shot.right() - 10.0, shot.bottom() - 12.0));
    painter.rect_filled(card, CornerRadius::same(5), p.bg_card);
    painter.rect_stroke(card, CornerRadius::same(5), Stroke::new(1.0, p.border_subtle), egui::StrokeKind::Inside);
    for (i, (w, col)) in [(50.0, t.primary_text), (58.0, p.text_default), (42.0, p.text_subtle), (36.0, t.primary_text)].iter().enumerate() {
        let y = card.top() + 10.0 + i as f32 * 14.0;
        painter.rect_filled(egui::Rect::from_min_size(egui::pos2(card.left() + 8.0, y), egui::vec2(*w, 5.0)), CornerRadius::same(2), *col);
        if i < 3 {
            painter.rect_filled(egui::Rect::from_min_size(egui::pos2(card.right() - 26.0, y), egui::vec2(16.0, 5.0)), CornerRadius::same(2), p.success);
        }
    }
    painter.rect_filled(egui::Rect::from_min_size(egui::pos2(card.right() - 40.0, card.bottom() - 20.0), egui::vec2(32.0, 11.0)), CornerRadius::same(3), t.primary);
}

/// One choice among several, as a rounded button.
fn pick_chip(ui: &mut Ui, label: &str, font: FontId, on: bool) -> egui::Response {
    let g = ui.painter().layout_no_wrap(label.to_string(), font, if on { PRIMARY_TEXT() } else { TEXT_DEFAULT() });
    let (r, resp) = ui.allocate_exact_size(egui::vec2(g.size().x + 30.0, u(32.0)), Sense::click());
    let p = ui.painter();
    if on {
        p.rect_filled(r, CornerRadius::same(16), PRIMARY().gamma_multiply(0.18));
    } else if resp.hovered() {
        p.rect_filled(r, CornerRadius::same(16), BG_HOVER());
    }
    p.rect_stroke(r, CornerRadius::same(16), Stroke::new(if on { 2.0 } else { 1.0 }, if on { PRIMARY_TEXT() } else { BORDER_DEFAULT() }), egui::StrokeKind::Inside);
    p.galley(egui::pos2(r.left() + 15.0, r.center().y - g.size().y / 2.0), g, TEXT_DEFAULT());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// One colour to pick: a dot and its name, in the shade the current theme uses.
fn accent_chip(ui: &mut Ui, a: &crate::theme::Accent, on: bool) -> egui::Response {
    let t = a.tint(crate::theme::theme_name());
    let g = ui.painter().layout_no_wrap(a.label.to_string(), FontId::proportional(z(13.5)), t.primary_text);
    let (r, resp) = ui.allocate_exact_size(egui::vec2(g.size().x + 46.0, u(32.0)), Sense::click());
    let p = ui.painter();
    if on {
        p.rect_filled(r, CornerRadius::same(16), t.primary.gamma_multiply(0.18));
    } else if resp.hovered() {
        p.rect_filled(r, CornerRadius::same(16), BG_HOVER());
    }
    p.rect_stroke(r, CornerRadius::same(16), Stroke::new(if on { 2.0 } else { 1.0 }, if on { t.primary_text } else { BORDER_DEFAULT() }), egui::StrokeKind::Inside);
    let dot = egui::pos2(r.left() + 18.0, r.center().y);
    p.circle_filled(dot, 8.0, t.primary);
    if on {
        let s = Stroke::new(1.8, Color32::WHITE);
        p.line_segment([dot + egui::vec2(-3.6, 0.2), dot + egui::vec2(-0.9, 2.9)], s);
        p.line_segment([dot + egui::vec2(-0.9, 2.9), dot + egui::vec2(3.9, -2.9)], s);
    }
    p.galley(egui::pos2(r.left() + 32.0, r.center().y - g.size().y / 2.0), g, t.primary_text);
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}
