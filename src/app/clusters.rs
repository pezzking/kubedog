//! Clusters and kubeconfig files (a Kubedog addition): the start page that lists every
//! context in one column with details beside it, and managing which kubeconfig files are read.
//! Kubedog reads the files the person lists, adds pasted kubeconfigs as files of its own,
//! hides contexts without touching any file, and only deletes a context from a file after
//! an explicit confirmation.

use super::*;

impl KubedogApp {
    /// The files to read when nothing was configured yet: the environment's or ~/.kube/config.
    pub(super) fn default_kubeconfigs() -> Vec<KubeFile> {
        let from_env = std::env::var("KUBEDOGCONFIG").ok().filter(|s| !s.is_empty()).or_else(|| std::env::var("KUBECONFIG").ok().filter(|s| !s.is_empty()));
        let paths: Vec<String> = match from_env {
            Some(list) => list.split(kube::LIST_SEP).filter(|p| !p.is_empty()).map(String::from).collect(),
            None => kube::home().map(|h| vec![h.join(".kube").join("config").to_string_lossy().to_string()]).unwrap_or_default(),
        };
        paths.into_iter().map(|path| KubeFile { path, enabled: true, managed: false }).collect()
    }

    /// Point kubectl at the enabled files (in order).
    pub(super) fn apply_kubeconfigs(&mut self) {
        if self.prefs.kubeconfigs.is_empty() {
            self.prefs.kubeconfigs = Self::default_kubeconfigs();
        }
        let enabled: Vec<String> = self.prefs.kubeconfigs.iter().filter(|f| f.enabled).map(|f| f.path.clone()).collect();
        self.kubectl.kubeconfig = Some(enabled.join(&kube::LIST_SEP.to_string()));
    }

    fn managed_dir() -> Option<std::path::PathBuf> {
        kube::data_dir().map(|d| d.join("kubeconfigs"))
    }

    /// Read every enabled kubeconfig file on its own, so each context knows where it came from.
    pub(super) fn load_contexts_from_files(&mut self) {
        if self.demo {
            return;
        }
        self.apply_kubeconfigs();
        self.contexts_loading = true;
        // Through a Linux in WSL: its own kubeconfig, by its own paths.
        let files: Vec<String> = match &self.kubectl.wsl {
            Some(w) => w.kubeconfig.clone(),
            None => self.prefs.kubeconfigs.iter().filter(|f| f.enabled).map(|f| f.path.clone()).collect(),
        };
        let k = self.kubectl.clone();
        let tx = self.tx.clone();
        let ctx = self.egui_ctx.clone();
        std::thread::spawn(move || {
            let mut all: Vec<ContextInfo> = vec![];
            let mut current: Option<String> = None;
            let mut errors: Vec<String> = vec![];
            for f in &files {
                let r = k.run(&["config".into(), "view".into(), "-o".into(), "json".into(), "--kubeconfig".into(), f.clone()]);
                match r.and_then(|j| kube::parse_contexts(&j)) {
                    Ok((list, cur)) => {
                        if current.is_none() {
                            current = cur;
                        }
                        for mut c in list {
                            if !all.iter().any(|x| x.name == c.name) {
                                c.source = f.clone();
                                all.push(c);
                            }
                        }
                    }
                    Err(e) => errors.push(format!("{}: {}", short_path(f), truncate(&e, 160))),
                }
            }
            let _ = tx.send(Msg::Text { key: "ctxerrors".into(), result: Ok(errors.join("\n")) });
            let res = if files.is_empty() { Err("No kubeconfig file is switched on. Add or enable one on the right.".to_string()) } else { Ok((all, current)) };
            let _ = tx.send(Msg::Contexts(res));
            ctx.request_repaint();
        });
    }

    /// Handle the replies this page asked for. Returns true when the message was ours.
    pub(super) fn on_cluster_text(&mut self, key: &str, result: &Result<String, String>) -> bool {
        if key == "ctxerrors" {
            self.file_errors = result.as_ref().ok().filter(|s| !s.is_empty()).cloned();
            return true;
        }
        if key == "wslapp" {
            self.on_wsl_app(result);
            return true;
        }
        if key == "pickfile" {
            if let Ok(p) = result {
                let p = p.trim().to_string();
                if !p.is_empty() {
                    self.add_file_path = p;
                }
            }
            return true;
        }
        if let Some(c) = key.strip_prefix("ping|") {
            let r = result.clone().map(|j| {
                let v: Value = serde_json::from_str(&j).unwrap_or_default();
                v["serverVersion"]["gitVersion"].as_str().map(|s| format!("reachable · Kubernetes {s}")).unwrap_or_else(|| "reachable".into())
            });
            self.pings.insert(c.to_string(), (false, r));
            return true;
        }
        if let Some(c) = key.strip_prefix("ctxdel|") {
            match result {
                Ok(_) => self.toast(format!("Deleted context {c} from its file"), false),
                Err(e) => self.toast(format!("Couldn't delete {c}: {e}"), true),
            }
            self.load_contexts_from_files();
            return true;
        }
        false
    }

    fn ping(&mut self, ctx: &str) {
        self.pings.insert(ctx.to_string(), (true, Ok(String::new())));
        let key = format!("ping|{ctx}");
        let args = vec!["--context".into(), ctx.to_string(), "version".into(), "-o".into(), "json".into(), "--request-timeout=8s".into()];
        self.spawn(move |k| Msg::Text { key, result: k.run(&args) });
    }

    fn browse_kubeconfig(&mut self) {
        self.spawn(|_| {
            let out = std::process::Command::new("/usr/bin/osascript")
                .arg("-e")
                .arg("POSIX path of (choose file with prompt \"Choose a kubeconfig file\" default location (path to home folder))")
                .output();
            let r = match out {
                Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
                Ok(_) => Ok(String::new()),
                Err(e) => Err(e.to_string()),
            };
            Msg::Text { key: "pickfile".into(), result: r }
        });
    }

    fn add_kubeconfig_file(&mut self, path: &str) {
        let path = path.trim();
        let path = if let Some(rest) = path.strip_prefix("~/") {
            kube::home().map(|h| h.join(rest).to_string_lossy().to_string()).unwrap_or_else(|| path.to_string())
        } else {
            path.to_string()
        };
        if path.is_empty() {
            return;
        }
        if !std::path::Path::new(&path).is_file() {
            self.toast(format!("{path} isn't a file"), true);
            return;
        }
        if self.prefs.kubeconfigs.iter().any(|f| f.path == path) {
            self.toast("That file is already in the list".into(), true);
            return;
        }
        self.prefs.kubeconfigs.push(KubeFile { path, enabled: true, managed: false });
        self.add_file_path.clear();
        self.save();
        self.load_contexts_from_files();
    }

    /// Save a pasted kubeconfig as a file of Kubedog's own and add it.
    fn add_pasted_cluster(&mut self) {
        let text = self.paste_config.trim().to_string();
        if text.is_empty() {
            return;
        }
        let Some(dir) = Self::managed_dir() else { return };
        if std::fs::create_dir_all(&dir).is_err() {
            self.toast("Couldn't create Kubedog's kubeconfig folder".into(), true);
            return;
        }
        let name: String = self.paste_name.trim().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
        let name = if name.is_empty() { format!("cluster-{}", kube::now_secs()) } else { name };
        let path = dir.join(format!("{name}.yaml"));
        if path.exists() {
            self.toast(format!("A cluster file named {name} already exists"), true);
            return;
        }
        if let Err(e) = std::fs::write(&path, &text) {
            self.toast(format!("Couldn't save: {e}"), true);
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        // Check that kubectl can read it before keeping it.
        let check = self.kubectl.run(&["config".into(), "view".into(), "-o".into(), "json".into(), "--kubeconfig".into(), path.to_string_lossy().to_string()]);
        match check.and_then(|j| kube::parse_contexts(&j)) {
            Ok((list, _)) if !list.is_empty() => {
                self.prefs.kubeconfigs.push(KubeFile { path: path.to_string_lossy().to_string(), enabled: true, managed: true });
                self.paste_config.clear();
                self.paste_name.clear();
                self.paste_open = false;
                self.save();
                self.toast(format!("Added {} context{}", list.len(), if list.len() == 1 { "" } else { "s" }), false);
                self.load_contexts_from_files();
            }
            Ok(_) => {
                let _ = std::fs::remove_file(&path);
                self.toast("That kubeconfig has no contexts".into(), true);
            }
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                self.toast(format!("kubectl can't read it: {}", truncate(&e, 200)), true);
            }
        }
    }

    /// The list of kubeconfig files with switches, plus adding files and pasted clusters.
    pub(super) fn kubeconfig_files_card(&mut self, ui: &mut Ui) {
        card(ui, |ui| {
            ui.label(RichText::new("Kubeconfig files").size(z(15.0)).strong().color(TEXT_DEFAULT()));
            ui.label(RichText::new("Kubedog reads these files in order; switch one off to leave its clusters out.").size(z(12.0)).color(TEXT_SUBTLE()));
            ui.add_space(6.0);
            let mut changed = false;
            let mut remove: Option<usize> = None;
            let files = self.prefs.kubeconfigs.clone();
            for (i, f) in files.iter().enumerate() {
                let n = self.contexts.iter().filter(|c| c.source == f.path).count();
                ui.horizontal(|ui| {
                    let mut on = f.enabled;
                    if ui.checkbox(&mut on, "").on_hover_text("Read this file").changed() {
                        self.prefs.kubeconfigs[i].enabled = on;
                        changed = true;
                    }
                    ui.add(egui::Label::new(RichText::new(short_path(&f.path)).monospace().size(z(12.0)).color(if f.enabled { TEXT_DEFAULT() } else { TEXT_PLACEHOLDER() })).truncate())
                        .on_hover_text(&f.path);
                    if f.managed {
                        chip(ui, "added in Kubedog");
                    }
                    if f.enabled {
                        ui.label(RichText::new(format!("{n} context{}", if n == 1 { "" } else { "s" })).size(z(11.5)).color(TEXT_SUBTLE()));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let tip = if f.managed { "Remove this cluster file (it was added in Kubedog, so the file is deleted)" } else { "Stop reading this file (the file itself is kept)" };
                        if ui.add(egui::Button::new(RichText::new("×").size(z(15.0)).color(TEXT_SUBTLE())).frame(false)).on_hover_text(tip).clicked() {
                            remove = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove {
                let f = self.prefs.kubeconfigs.remove(i);
                if f.managed {
                    let _ = std::fs::remove_file(&f.path);
                }
                changed = true;
            }
            if let Some(e) = &self.file_errors {
                ui.label(RichText::new(e).size(z(12.0)).color(WARNING()));
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.add_file_path).hint_text("Path to a kubeconfig file").desired_width(300.0));
                // The file chooser is macOS's own; elsewhere the path is typed or pasted.
                if cfg!(target_os = "macos") && ui.button("Browse…").clicked() {
                    self.browse_kubeconfig();
                }
                if ui.add_enabled(!self.add_file_path.trim().is_empty(), egui::Button::new("Add file")).clicked() {
                    let p = self.add_file_path.clone();
                    self.add_kubeconfig_file(&p);
                }
            });
            ui.add_space(6.0);
            if !self.paste_open {
                if ui.button("+ Add a cluster by pasting its kubeconfig").clicked() {
                    self.paste_open = true;
                }
            } else {
                ui.label(RichText::new("Paste a kubeconfig (YAML). Kubedog keeps it in its own folder, readable only by you.").size(z(12.0)).color(TEXT_SUBTLE()));
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Name").color(TEXT_SUBTLE()));
                    ui.add(egui::TextEdit::singleline(&mut self.paste_name).hint_text("e.g. staging").desired_width(200.0));
                });
                egui::ScrollArea::vertical().max_height(180.0).id_salt("paste-kc").show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut self.paste_config).code_editor().desired_rows(8).desired_width(f32::INFINITY).hint_text("apiVersion: v1\nkind: Config\nclusters: …"));
                });
                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.paste_config.trim().is_empty(), egui::Button::new(RichText::new("Save cluster").color(Color32::WHITE)).fill(PRIMARY())).clicked() {
                        self.add_pasted_cluster();
                    }
                    if ui.button("Cancel").clicked() {
                        self.paste_open = false;
                    }
                });
            }
            if changed {
                self.save();
                self.load_contexts_from_files();
            }
        });
    }

    /// The first page: every context in one column on the left, details and files on the right.
    /// The "namespaces" box of a cluster: for accounts that may only see some namespaces.
    /// Saved when the box is left (or Enter is pressed); the cluster's lists are read again then.
    pub(super) fn namespaces_field(&mut self, ui: &mut Ui, ctx: &str, with_help: bool) {
        let saved = self.prefs.ctx_namespaces.get(ctx).map(|v| v.join(", ")).unwrap_or_default();
        ui.horizontal(|ui| {
            left_cell(ui, [z(130.0), z(20.0)], egui::Label::new(RichText::new("Namespaces").color(TEXT_SUBTLE())));
            let buf = self.ns_edit.entry(ctx.to_string()).or_insert_with(|| saved.clone());
            let r = ui.add(egui::TextEdit::singleline(buf).hint_text("all (the whole cluster)").desired_width(320.0));
            let text = buf.clone();
            if r.lost_focus() {
                let list = parse_namespace_patterns(&text);
                let changed = self.prefs.ctx_namespaces.get(ctx).cloned().unwrap_or_default() != list;
                self.ns_edit.insert(ctx.to_string(), list.join(", "));
                if changed {
                    if list.is_empty() {
                        self.prefs.ctx_namespaces.remove(ctx);
                    } else {
                        self.prefs.ctx_namespaces.insert(ctx.to_string(), list);
                    }
                    self.save();
                    self.forget_cluster_data(ctx);
                }
            }
        });
        if with_help {
            ui.horizontal(|ui| {
                ui.add_space(z(130.0) + 8.0);
                ui.add(
                    egui::Label::new(
                        RichText::new("Leave empty to use the whole cluster. If your account may only see some namespaces, list them here with commas between; * matches anything (team-a, shop-*). Kubedog then reads only these.")
                            .size(z(11.5))
                            .color(TEXT_PLACEHOLDER()),
                    )
                    .wrap(),
                );
            });
        }
        // After connecting: what the patterns turned into.
        if self.prefs.ctx_namespaces.contains_key(ctx) {
            if let Some(found) = self.namespaces.get(ctx).filter(|n| !n.is_empty()) {
                ui.horizontal(|ui| {
                    ui.add_space(z(130.0) + 8.0);
                    ui.add(egui::Label::new(RichText::new(format!("Reading {}: {}", found.len(), found.join(", "))).size(z(11.5)).color(SUCCESS())).wrap());
                });
            }
        }
    }

    /// Drop what was read from a cluster so it's read again (its namespaces setting changed).
    pub(super) fn forget_cluster_data(&mut self, ctx: &str) {
        self.namespaces.remove(ctx);
        self.lists.retain(|k, _| k.split('|').nth(1) != Some(ctx));
        self.metrics.remove(ctx);
        self.list_cache = None;
        self.ns_filter = None;
        self.ns_multi.clear();
        self.ns_ctx = None;
        if self.connected && self.active.iter().any(|c| c == ctx) {
            self.refresh_current(true);
        }
    }

    /// kubectl isn't on this computer (or wasn't found): what that means and the ways out.
    fn kubectl_missing(&mut self, ui: &mut Ui) {
        let install = if cfg!(windows) {
            "winget install Kubernetes.kubectl"
        } else if cfg!(target_os = "macos") {
            "brew install kubernetes-cli"
        } else {
            "https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/"
        };
        egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
            ui.set_width((ui.available_width() - 4.0).min(520.0));
            if !self.demo {
                ui.label(RichText::new("kubectl wasn't found on this computer").strong().size(z(14.0)));
                ui.add(egui::Label::new(RichText::new("Kubedog reaches your clusters through kubectl, so it needs it to show them.").size(z(12.0)).color(TEXT_SUBTLE())).wrap());
                ui.add_space(6.0);
            }
            ui.label(RichText::new("1. If kubectl (or OpenShift's oc) is on this computer, say where:").size(z(12.0)));
            ui.horizontal(|ui| {
                let hint = if cfg!(windows) { "C:\\...\\kubectl.exe" } else { "/path/to/kubectl" };
                ui.add(egui::TextEdit::singleline(&mut self.kubectl_typed).hint_text(hint).desired_width(300.0));
            });
            ui.add_space(4.0);
            ui.label(RichText::new("2. Or install it (this needs the internet):").size(z(12.0)));
            ui.horizontal(|ui| {
                ui.label(RichText::new(install).monospace().size(z(12.0)));
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(install.to_string());
                }
            });
            if cfg!(windows) {
                ui.add(egui::Label::new(RichText::new("Without internet: Kubedog's installer can bring kubectl along; run it again and leave that box ticked.").size(z(11.0)).color(TEXT_SUBTLE())).wrap());
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Look again").on_hover_text("After installing kubectl or typing its path").clicked() {
                    self.find_kubectl_again();
                }
                if self.demo {
                    if ui.button("Remove the sample cluster").clicked() {
                        self.leave_demo();
                    }
                } else if ui.button("Show a sample cluster").on_hover_text("Made-up data, to look around without a cluster").clicked() {
                    self.enter_demo();
                }
            });
        });
        ui.add_space(8.0);
    }

    pub(super) fn start_page(&mut self, ui: &mut Ui) {
        let top = egui::Rect::from_min_size(ui.max_rect().min, egui::vec2(ui.max_rect().width(), 28.0));
        if ui.interact(top, egui::Id::new("start-drag"), Sense::drag()).drag_started() {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
        let q = self.picker_search.to_lowercase();
        let hidden_n = self.contexts.iter().filter(|c| self.prefs.hidden_contexts.contains(&c.name)).count();
        let ctxs: Vec<ContextInfo> = self
            .contexts
            .iter()
            .filter(|c| self.show_hidden || !self.prefs.hidden_contexts.contains(&c.name))
            .filter(|c| q.is_empty() || c.name.to_lowercase().contains(&q) || ctx_label(&c.name).to_lowercase().contains(&q) || c.server.to_lowercase().contains(&q))
            .cloned()
            .collect();
        // The order picked in Settings; the rest follow as the kubeconfig files list them.
        let mut ctxs = ctxs;
        let order = &self.prefs.ctx_order;
        ctxs.sort_by_key(|c| order.iter().position(|n| n == &c.name).unwrap_or(usize::MAX));
        // Keyboard: ↑↓ move, Space picks, Enter connects, ⌘A picks all.
        let typing = ui.ctx().memory(|m| m.focused().is_some());
        if !ctxs.is_empty() && !typing && self.dialog.is_none() {
            let (u, d, space, enter, all) = ui.input(|i| {
                (
                    i.key_pressed(Key::ArrowUp),
                    i.key_pressed(Key::ArrowDown),
                    i.key_pressed(Key::Space),
                    i.key_pressed(Key::Enter),
                    // ⌘A from the keyboard or from Edit → Select All (which carries its own modifiers).
                    i.events.iter().any(|e| matches!(e, egui::Event::Key { key: Key::A, pressed: true, modifiers, .. } if modifiers.command)),
                )
            });
            let n = ctxs.len();
            let f = self.picker_focus.min(n - 1);
            self.picker_focus = if u { f.saturating_sub(1) } else if d { (f + 1).min(n - 1) } else { f };
            if space {
                let name = ctxs[self.picker_focus].name.clone();
                if !self.picker.remove(&name) {
                    self.picker.insert(name);
                }
            }
            if all {
                if ctxs.iter().all(|c| self.picker.contains(&c.name)) {
                    self.picker.clear();
                } else {
                    self.picker = ctxs.iter().map(|c| c.name.clone()).collect();
                }
            }
            if enter {
                if self.picker.is_empty() {
                    self.picker.insert(ctxs[self.picker_focus].name.clone());
                }
                self.connect();
                return;
            }
        }
        let focused = ctxs.get(self.picker_focus.min(ctxs.len().saturating_sub(1))).cloned();

        let full = ui.available_rect_before_wrap();
        let left_w = (full.width() * 0.36).clamp(340.0, 460.0);
        let left = egui::Rect::from_min_size(full.min, egui::vec2(left_w, full.height()));
        let right = egui::Rect::from_min_max(egui::pos2(left.right(), full.top()), full.max);
        ui.painter().rect_filled(left, CornerRadius::ZERO, BG_SUBTLE());
        ui.painter().vline(left.right(), left.y_range(), Stroke::new(1.0, BORDER_SUBTLE()));

        // ----- left: the list -----
        let mut connect_now = false;
        let mut open_group: Option<usize> = None;
        ui.scope_builder(egui::UiBuilder::new().max_rect(left.shrink2(egui::vec2(30.0, 0.0))), |ui| { base_size(ui, |ui| {
            ui.add_space(34.0);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(48.0, 48.0), Sense::hover());
                app_mark(ui.painter(), r);
                ui.label(RichText::new("Kubedog").size(z(22.0)).strong().color(TEXT_DEFAULT()));
            });
            ui.label(RichText::new("Tick one or more clusters to open").size(z(13.0)).color(TEXT_SUBTLE()));
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                let w = ui.available_width() - 34.0;
                filter_box(ui, &mut self.picker_search, "Search clusters", w);
                if ui.add(egui::Button::new(RichText::new("⟳").size(z(15.0))).frame(false)).on_hover_text("Read the kubeconfig files again").clicked() {
                    self.load_contexts_from_files();
                }
            });
            ui.add_space(10.0);
            if self.contexts_loading {
                ui.spinner();
            }
            if let Some(e) = &self.contexts_error {
                ui.label(RichText::new(e).size(z(12.0)).color(WARNING()));
            }
            if self.kubectl.bin.is_none() {
                self.kubectl_missing(ui);
            }
            // Room under the list for Connect, its hint and (when there are any) the groups row.
            let below = if !self.prefs.groups.is_empty() || self.picker.len() >= 2 { 190.0 } else { 110.0 };
            let list_h = (ui.available_height() - below).max(120.0);
            egui::ScrollArea::vertical().id_salt("ctx-list").max_height(list_h).auto_shrink([false, true]).show(ui, |ui| {
                for (i, c) in ctxs.iter().enumerate() {
                    let on = self.picker.contains(&c.name);
                    let focus = i == self.picker_focus;
                    let hidden = self.prefs.hidden_contexts.contains(&c.name);
                    let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(62.0)), Sense::click());
                    let p = ui.painter();
                    // The block shows which cluster is selected (its details are on the right); the tick alone
                    // shows which ones are picked to open. The two don't follow each other.
                    let fill = if focus { PICKED_BG() } else if resp.hovered() { BG_HOVER() } else { BG_CARD() };
                    p.rect_filled(r, CornerRadius::same(10), fill);
                    p.rect_stroke(r, CornerRadius::same(10), Stroke::new(if focus { 1.5 } else { 1.0 }, if focus { PRIMARY_TEXT() } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
                    p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(4.0, r.height())), CornerRadius { nw: 10, sw: 10, ne: 0, se: 0 }, context_color(&c.name));
                    ctx_mark(p, egui::Rect::from_center_size(r.left_center() + egui::vec2(30.0, 0.0), egui::vec2(30.0, 30.0)), &c.name);
                    let tw = r.width() - 100.0;
                    let name = p.layout_no_wrap(fit(ui, &ctx_label(&c.name), tw, z(14.0)), FontId::proportional(z(14.0)), if hidden { TEXT_PLACEHOLDER() } else { TEXT_DEFAULT() });
                    p.galley(r.left_top() + egui::vec2(54.0, u(10.0)), name, TEXT_DEFAULT());
                    let host = c.server.trim_start_matches("https://").trim_start_matches("http://").to_string();
                    let sub = p.layout_no_wrap(fit(ui, if host.is_empty() { &c.cluster } else { &host }, tw, z(11.5)), FontId::proportional(z(11.5)), TEXT_SUBTLE());
                    p.galley(r.left_top() + egui::vec2(54.0, u(29.0)), sub, TEXT_SUBTLE());
                    let mut bx = r.left() + 54.0;
                    let by = r.top() + u(44.0);
                    let mut badge = |text: &str, col: Color32| {
                        let g = p.layout_no_wrap(text.to_string(), FontId::proportional(z(10.0)), col);
                        let br = egui::Rect::from_min_size(egui::pos2(bx, by), g.size() + egui::vec2(8.0, 1.0));
                        p.rect_filled(br, CornerRadius::same(4), col.gamma_multiply(0.15));
                        p.galley(br.min + egui::vec2(4.0, 0.5), g, col);
                        bx = br.right() + 5.0;
                    };
                    if self.current_context.as_deref() == Some(c.name.as_str()) {
                        badge("current", SUCCESS());
                    }
                    if self.prefs.contexts.contains(&c.name) {
                        badge("last used", INFO());
                    }
                    if hidden {
                        badge("hidden", TEXT_SUBTLE());
                    }
                    if ctx_label(&c.name).chars().count() > MAX_CLUSTER_NAME {
                        badge("needs a short name", WARNING());
                    }
                    let cc = egui::pos2(r.right() - 22.0, r.center().y);
                    if on {
                        p.circle_filled(cc, 9.0, PRIMARY_TEXT());
                        p.line_segment([cc + egui::vec2(-4.0, 0.0), cc + egui::vec2(-1.0, 3.5)], Stroke::new(2.0, BG_DEFAULT()));
                        p.line_segment([cc + egui::vec2(-1.0, 3.5), cc + egui::vec2(4.5, -3.5)], Stroke::new(2.0, BG_DEFAULT()));
                    } else {
                        p.circle_stroke(cc, 8.5, Stroke::new(1.2, if resp.hovered() || focus { TEXT_SUBTLE() } else { BORDER_DEFAULT() }));
                    }
                    let on_circle = resp.hover_pos().map(|pp| pp.x > r.right() - 44.0).unwrap_or(false);
                    if on_circle {
                        p.circle_stroke(cc, 12.0, Stroke::new(1.0, TEXT_SUBTLE()));
                    }
                    if resp.double_clicked() {
                        self.picker.insert(c.name.clone());
                        connect_now = true;
                    } else if resp.clicked() {
                        // A click on the block selects it and shows its details; a click on the circle only
                        // ticks or unticks it, whichever block is selected.
                        if resp.interact_pointer_pos().map(|pp| pp.x > r.right() - 44.0).unwrap_or(false) {
                            if on {
                                self.picker.remove(&c.name);
                            } else {
                                self.picker.insert(c.name.clone());
                            }
                        } else {
                            self.picker_focus = i;
                        }
                    }
                    ui.add_space(8.0);
                }
                if ctxs.is_empty() && !self.contexts_loading {
                    ui.label(RichText::new(if q.is_empty() { "No clusters yet. Add a kubeconfig file on the right." } else { "No cluster matches." }).color(TEXT_SUBTLE()));
                }
            });
            if hidden_n > 0 {
                ui.checkbox(&mut self.show_hidden, format!("Show {hidden_n} hidden"));
            }
            ui.add_space(8.0);
            let n = self.picker.len();
            let enabled = n > 0;
            // What's picked on the left, a compact button on the right.
            ui.horizontal(|ui| {
                ui.set_height(u(38.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if connect_button(ui, enabled).on_hover_text("Open what's picked (Enter)").clicked() {
                        connect_now = true;
                    }
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        let picked: Vec<String> = self.contexts.iter().filter(|c| self.picker.contains(&c.name)).map(|c| ctx_label(&c.name)).collect();
                        let (text, col) = match n {
                            0 => ("Nothing picked yet".to_string(), TEXT_PLACEHOLDER()),
                            1 => (picked.first().cloned().unwrap_or_default(), TEXT_MUTED()),
                            _ => (format!("{n} clusters picked"), TEXT_MUTED()),
                        };
                        let r = ui.add(egui::Label::new(RichText::new(text).size(z(13.5)).color(col)).truncate());
                        if n > 1 {
                            r.on_hover_text(picked.join("\n"));
                        }
                    });
                });
            });
            ui.add_space(6.0);
            ui.label(RichText::new("Click a cluster to select it and see its details · tick its circle (or Space) to pick it for opening · Enter or double-click to connect · ⌘A all").size(z(11.0)).color(TEXT_PLACEHOLDER()));
            // Groups: open several clusters at once (⌃1-9 for the first nine).
            let groups: Vec<(usize, Group, usize)> = self
                .prefs
                .groups
                .iter()
                .enumerate()
                .map(|(i, g)| (i, g.clone(), g.contexts.iter().filter(|n| self.contexts.iter().any(|c| &c.name == *n)).count()))
                .collect();
            if !groups.is_empty() || n >= 2 {
                ui.add_space(14.0);
                ui.label(RichText::new("Groups").size(z(13.0)).color(TEXT_SUBTLE()));
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    for (i, g, have) in &groups {
                        let tip = format!("{}\n{}", g.contexts.iter().map(|c| ctx_label(c)).collect::<Vec<_>>().join("\n"), if *i < 9 { format!("⌃{}", i + 1) } else { String::new() });
                        let r = ui.add_enabled(*have > 0, egui::Button::new(RichText::new(format!("{}  {have}", g.name)).size(z(13.0))).corner_radius(CornerRadius::same(6)));
                        if r.on_hover_text(tip).clicked() {
                            open_group = Some(*i);
                        }
                    }
                    if n >= 2 && ui.add(egui::Button::new(RichText::new("+ Save picked as a group").size(z(12.5)).color(TEXT_SUBTLE())).frame(false)).clicked() {
                        let mut picked: Vec<String> = self.contexts.iter().filter(|c| self.picker.contains(&c.name)).map(|c| c.name.clone()).collect();
                        picked.dedup();
                        let name = format!("Group {}", self.prefs.groups.len() + 1);
                        self.prefs.groups.push(Group { name: name.clone(), contexts: picked });
                        self.save();
                        self.toast(format!("Saved “{name}”. Rename it in Settings → Clusters."), false);
                    }
                });
            }
        }) });
        if let Some(i) = open_group {
            self.open_group(i);
            return;
        }
        if connect_now {
            self.connect();
            return;
        }

        // ----- right: details and files -----
        ui.scope_builder(egui::UiBuilder::new().max_rect(right.shrink2(egui::vec2(40.0, 0.0))), |ui| {
            egui::ScrollArea::vertical().id_salt("start-right").auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(40.0);
                match &focused {
                    None => {
                        ui.label(RichText::new("No cluster selected").size(z(18.0)).color(TEXT_SUBTLE()));
                    }
                    Some(c) => {
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(egui::vec2(40.0, 40.0), Sense::hover());
                            ctx_mark(ui.painter(), r, &c.name);
                            ui.vertical(|ui| {
                                ui.add(egui::Label::new(RichText::new(ctx_label(&c.name)).size(z(19.0)).strong().color(TEXT_DEFAULT())).truncate());
                                ui.label(RichText::new(&c.server).size(z(12.5)).color(TEXT_SUBTLE()));
                            });
                        });
                        ui.add_space(10.0);
                        card(ui, |ui| {
                            // Rename: a display name kept by Kubedog (kubectl still uses the real one).
                            ui.horizontal(|ui| {
                                left_cell(ui, [z(130.0), z(20.0)], egui::Label::new(RichText::new("Display name").color(TEXT_SUBTLE())));
                                let mut alias = self.prefs.ctx_alias.get(&c.name).cloned().unwrap_or_default();
                                let r = ui.add(egui::TextEdit::singleline(&mut alias).hint_text("a short name").char_limit(MAX_CLUSTER_NAME).desired_width(200.0));
                                if r.changed() {
                                    if alias.trim().is_empty() {
                                        self.prefs.ctx_alias.remove(&c.name);
                                    } else {
                                        self.prefs.ctx_alias.insert(c.name.clone(), alias);
                                    }
                                    self.save();
                                }
                                if self.prefs.ctx_alias.contains_key(&c.name) && ui.small_button("Use the kubeconfig name").clicked() {
                                    self.prefs.ctx_alias.remove(&c.name);
                                    self.save();
                                }
                            });
                            if ctx_label(&c.name) != c.name {
                                kv(ui, "Context", c.name.clone());
                            }
                            kv(ui, "Cluster", c.cluster.clone());
                            kv(ui, "User", c.user.clone());
                            kv(ui, "Namespace", if c.namespace.is_empty() { "default".to_string() } else { c.namespace.clone() });
                            kv(ui, "File", short_path(&c.source));
                            ui.add_space(4.0);
                            self.namespaces_field(ui, &c.name.clone(), true);
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                let picked = self.picker.contains(&c.name);
                                if button(ui, if picked { "Picked ✓" } else { "Pick" }, !picked, false) {
                                    if picked {
                                        self.picker.remove(&c.name);
                                    } else {
                                        self.picker.insert(c.name.clone());
                                    }
                                }
                                if button(ui, "Test connection", false, false) {
                                    self.ping(&c.name);
                                }
                                let hidden = self.prefs.hidden_contexts.contains(&c.name);
                                if button(ui, if hidden { "Show in list" } else { "Hide from list" }, false, false) {
                                    if hidden {
                                        self.prefs.hidden_contexts.retain(|n| n != &c.name);
                                    } else {
                                        self.prefs.hidden_contexts.push(c.name.clone());
                                        self.picker.remove(&c.name);
                                    }
                                    self.save();
                                }
                                if button(ui, "Delete…", false, false) {
                                    self.dialog = Some(Dialog::DeleteContext { name: c.name.clone(), file: c.source.clone() });
                                }
                            });
                            match self.pings.get(&c.name) {
                                Some((true, _)) => {
                                    ui.horizontal(|ui| {
                                        ui.spinner();
                                        ui.label(RichText::new("Connecting…").color(TEXT_SUBTLE()));
                                    });
                                }
                                Some((false, Ok(t))) => {
                                    ui.label(RichText::new(format!("● {t}")).color(SUCCESS()));
                                }
                                Some((false, Err(e))) => {
                                    ui.label(RichText::new(format!("● not reachable: {}", truncate(e, 220))).color(DANGER()));
                                }
                                None => {}
                            }
                        });
                    }
                }
                ui.add_space(14.0);
                self.ai_note(ui);
                self.kubeconfig_files_card(ui);
                ui.add_space(20.0);
            });
        });
        ui.advance_cursor_after_rect(full);
    }
}

/// A path with the home folder shortened to ~.
pub(super) fn short_path(p: &str) -> String {
    match kube::home_text() {
        Some(h) if p.starts_with(&h) => format!("~{}", &p[h.len()..]),
        _ => p.to_string(),
    }
}

/// "team-a, shop-*  ops" -> ["team-a", "shop-*", "ops"]: commas or spaces between, only the
/// characters a namespace (or a pattern) can have.
pub(super) fn parse_namespace_patterns(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '*' | '?')))
        .collect();
    out.dedup();
    out
}

/// The Connect button: a rounded pill with an arrow that moves forward on hover; just an outline
/// until something is picked.
fn connect_button(ui: &mut Ui, enabled: bool) -> egui::Response {
    let probe = ui.painter().layout_no_wrap("Connect".into(), FontId::proportional(z(14.5)), TEXT_DEFAULT());
    let size = egui::vec2(probe.size().x + u(58.0), u(36.0));
    let (r, resp) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    let hot = ui.ctx().animate_bool_with_time(resp.id.with("hot"), enabled && resp.hovered(), 0.12);
    let round = CornerRadius::same((r.height() / 2.0) as u8);
    let p = ui.painter();
    let ink = if enabled {
        let lit = PRIMARY().lerp_to_gamma(Color32::WHITE, 0.14 * hot);
        p.rect_filled(r, round, if resp.is_pointer_button_down_on() { PRIMARY() } else { lit });
        Color32::WHITE
    } else {
        p.rect_stroke(r, round, Stroke::new(1.0, BORDER_DEFAULT()), egui::StrokeKind::Inside);
        TEXT_PLACEHOLDER()
    };
    p.text(egui::pos2(r.left() + u(18.0), r.center().y), egui::Align2::LEFT_CENTER, "Connect", FontId::proportional(z(14.5)), ink);
    let tip = egui::pos2(r.right() - u(17.0) + 3.0 * hot, r.center().y);
    let (w, h) = (u(12.0), u(4.5));
    let s = Stroke::new(1.7, ink);
    p.line_segment([tip - egui::vec2(w, 0.0), tip], s);
    p.line_segment([tip - egui::vec2(h, h), tip], s);
    p.line_segment([tip - egui::vec2(h, -h), tip], s);
    if enabled && resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}
