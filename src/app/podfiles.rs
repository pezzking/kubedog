//! A pod's Storage and Files tabs. Files are read by running `ls`, `head` and `df` in a container,
//! only after a click, with fixed options and the path as one argument (never through a shell).
//! Nothing is written. Files that hold secrets stay blurred until clicked.

use super::dash::{at, at_end, bar, line};
use super::pg::{bytes, label_at};
use super::*;
use std::io::Read;

const LIST_CAP: usize = 2 * 1024 * 1024;
const FILE_CAP: usize = 256 * 1024;
const PATIENCE: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Entry {
    pub name: String,
    /// 'd' folder, '-' file, 'l' link, others.
    pub kind: char,
    pub size: u64,
    pub mode: String,
    pub when: String,
    pub target: Option<String>,
}

struct View_ {
    path: String,
    /// None while it's read.
    content: Option<Result<(Vec<u8>, bool), String>>,
    uncovered: bool,
}

#[derive(Default)]
pub(super) struct Files {
    pub container: Option<String>,
    path: String,
    /// None while it's read.
    list: Option<Result<Vec<Entry>, String>>,
    view: Option<View_>,
    filter: String,
    secret_roots: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Df {
    pub source: String,
    pub size: f64,
    pub used: f64,
    pub avail: f64,
    pub mount: String,
}

/// Volumes whose files are secret values.
pub(super) fn is_secret_volume(v: &Value) -> bool {
    v["secret"].is_object()
        || v["csi"]["driver"].as_str().map(|d| d.contains("secret")).unwrap_or(false)
        || v["projected"]["sources"].as_array().into_iter().flatten().any(|s| s["secret"].is_object() || s["serviceAccountToken"].is_object())
}

/// Where a container's secret volumes are.
fn secret_roots(pod: &Value, container: &str) -> Vec<String> {
    let vols: HashSet<&str> = pod["spec"]["volumes"].as_array().into_iter().flatten().filter(|v| is_secret_volume(v)).filter_map(|v| v["name"].as_str()).collect();
    let mut out: Vec<String> = vec!["/var/run/secrets".into(), "/run/secrets".into(), "/proc".into(), "/sys".into(), "/etc/shadow".into()];
    for c in pod::containers(pod).iter().filter(|c| c["name"].as_str() == Some(container)) {
        out.extend(c["volumeMounts"].as_array().into_iter().flatten().filter(|m| m["name"].as_str().map(|n| vols.contains(n)).unwrap_or(false)).filter_map(|m| m["mountPath"].as_str().map(|p| p.trim_end_matches('/').to_string())));
    }
    out
}

/// Whether a file may hold a secret, by where it is and what it's called.
fn sensitive(path: &str, roots: &[String]) -> bool {
    if roots.iter().any(|r| path == r || path.strip_prefix(r.as_str()).map(|x| x.starts_with('/')).unwrap_or(false)) {
        return true;
    }
    let n = path.rsplit('/').next().unwrap_or("").to_lowercase();
    [".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".netrc", ".pgpass", ".env", ".htpasswd"].iter().any(|e| n.ends_with(e))
        || n.starts_with(".env")
        || ["passw", "secret", "token", "credential", "id_rsa", "id_ed25519", "kubeconfig"].iter().any(|w| n.contains(w))
}

/// "/a/b" + "../c" → "/a/c". Only text: links inside are followed one at a time.
fn join(base: &str, name: &str) -> String {
    let full = if name.starts_with('/') { name.to_string() } else { format!("{base}/{name}") };
    let mut out: Vec<&str> = vec![];
    for p in full.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            x => out.push(x),
        }
    }
    format!("/{}", out.join("/"))
}

/// Names come from inside the container: nothing in them may act on the screen.
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') { '\u{fffd}' } else { c }).collect()
}

/// `ls -lAn`, of GNU and of BusyBox.
fn parse_ls(text: &str) -> Vec<Entry> {
    let mut out: Vec<Entry> = text
        .lines()
        .filter_map(|l| {
            let mut rest = l;
            let mut word = || -> Option<&str> {
                let t = rest.trim_start();
                let end = t.find(' ')?;
                let (w, r) = t.split_at(end);
                rest = r;
                Some(w)
            };
            let mode = word()?.to_string();
            let kind = mode.chars().next().filter(|c| "dl-bcps".contains(*c) && mode.len() >= 10)?;
            word()?.parse::<u64>().ok()?;
            word()?;
            word()?;
            let first = word()?;
            // Devices have two numbers instead of a size.
            let size = if first.ends_with(',') {
                word()?;
                0
            } else {
                first.parse().ok()?
            };
            let d = word()?;
            let when = if d.starts_with(|c: char| c.is_ascii_alphabetic()) { format!("{d} {} {}", word()?, word()?) } else { format!("{d} {}", word()?) };
            let name = rest.strip_prefix(' ')?;
            if name.is_empty() {
                return None;
            }
            let (name, target) = match (kind, name.split_once(" -> ")) {
                ('l', Some((n, t))) => (n.to_string(), Some(t.to_string())),
                _ => (name.to_string(), None),
            };
            Some(Entry { name, kind, size, mode, when, target })
        })
        .collect();
    out.sort_by(|a, b| (a.kind != 'd').cmp(&(b.kind != 'd')).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    out
}

/// `df -kP`.
pub(super) fn parse_df(text: &str) -> Vec<Df> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            let kb = |s: &str| s.parse::<f64>().ok().map(|x| x * 1024.0);
            Some(Df { source: f[0].into(), size: kb(f[1])?, used: kb(f[2])?, avail: kb(f[3])?, mount: f[5..].join(" ") })
        })
        .filter(|d| d.size > 0.0)
        .collect()
}

/// Run one of three reading programs in a container. Bounded in time and size; the rest of the
/// output is cut. Returns what came out and whether there was more.
fn run_reader(k: &Kubectl, ctx: &str, ns: &str, pod: &str, container: &str, cmd: &[&str], cap: usize) -> Result<(Vec<u8>, bool), String> {
    if !matches!(cmd.first(), Some(&"ls" | &"head" | &"df")) {
        return Err("not a reading command".into());
    }
    let mut args: Vec<String> = ["--context", ctx, "-n", ns, "exec", pod, "-c", container, "--"].iter().map(|x| x.to_string()).collect();
    args.extend(cmd.iter().map(|x| x.to_string()));
    let mut c = k.command(&args).ok_or("kubectl was not found on this computer")?;
    c.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().map_err(|e| format!("could not start kubectl: {e}"))?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else { return Err("no output".into()) };
    let (tx, rx) = channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut b = vec![];
        let _ = out.take(cap as u64 + 1).read_to_end(&mut b);
        let _ = tx.send(b);
    });
    let (etx, erx) = channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut b = vec![];
        let _ = err.take(16 * 1024).read_to_end(&mut b);
        let _ = etx.send(b);
    });
    let got = rx.recv_timeout(PATIENCE);
    // Full, or out of patience: end it.
    let over = got.as_ref().map(|b| b.len() > cap).unwrap_or(true);
    if over {
        let _ = child.kill();
    }
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            _ if start.elapsed() > Duration::from_secs(5) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            _ => std::thread::sleep(Duration::from_millis(30)),
        }
    };
    let Ok(mut b) = got else { return Err("The container didn't answer in 20 seconds.".into()) };
    if over {
        b.truncate(cap);
        return Ok((b, true));
    }
    if status.map(|s| s.success()).unwrap_or(false) || (cmd[0] != "head" && !b.is_empty()) {
        return Ok((b, false));
    }
    let e = erx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
    Err(explain(&String::from_utf8_lossy(&e), cmd[0]))
}

fn explain(e: &str, tool: &str) -> String {
    let low = e.to_lowercase();
    if low.contains("executable file not found") || low.contains("stat ") && low.contains("no such file") || low.contains("exit code 127") || low.contains("exit code 126") {
        return format!("This container has no “{tool}” program, so this can't be read. Images made without a shell are like that.");
    }
    if is_refusal(e) {
        return "Your account may not run commands in this pod.".into();
    }
    if low.contains("permission denied") {
        return "The container's own user may not read this.".into();
    }
    let l = e.lines().find(|l| !l.starts_with("Defaulted") && !l.trim().is_empty()).unwrap_or("No answer.");
    truncate(&clean(l), 240)
}

fn packed(r: (Vec<u8>, bool)) -> String {
    serde_json::json!({"b": b64_encode(&r.0), "more": r.1}).to_string()
}

fn unpacked(t: &str) -> Option<(Vec<u8>, bool)> {
    let v: Value = serde_json::from_str(t).ok()?;
    Some((b64_decode(v["b"].as_str()?)?, v["more"].as_bool()?))
}

impl Files {
    pub fn listed(&mut self, path: &str, r: &Result<String, String>) {
        if path != self.path {
            return;
        }
        self.list = Some(match r {
            Ok(t) => unpacked(t).map(|x| parse_ls(&String::from_utf8_lossy(&x.0))).ok_or("Couldn't read the answer.".into()),
            Err(e) => Err(e.clone()),
        });
    }
    pub fn opened(&mut self, path: &str, r: &Result<String, String>) {
        if let Some(v) = self.view.as_mut().filter(|v| v.path == path) {
            v.content = Some(match r {
                Ok(t) => unpacked(t).ok_or("Couldn't read the answer.".into()),
                Err(e) => Err(e.clone()),
            });
        }
    }
}

impl KubedogApp {
    /// Whether commands may be run in containers now: a screenshot never does by itself.
    fn may_exec(&self) -> bool {
        self.screenshot.is_none() || std::env::var("KUBEDOG_SHOT_EXEC").is_ok()
    }

    pub(super) fn files_start(&mut self, sel: &Selected, container: &str) {
        let Some(o) = self.object_of(sel) else { return };
        self.pod.files = Files { container: Some(container.to_string()), secret_roots: secret_roots(&o, container), ..Default::default() };
        let start = pod::containers(&o).iter().find(|c| c["name"].as_str() == Some(container)).and_then(|c| c["workingDir"].as_str()).unwrap_or("/").to_string();
        self.files_go(sel, &start);
    }

    fn files_go(&mut self, sel: &Selected, path: &str) {
        let Some(c) = self.pod.files.container.clone() else { return };
        if !self.may_exec() {
            return;
        }
        let path = join("/", path);
        self.pod.files.path = path.clone();
        self.pod.files.list = None;
        self.pod.files.view = None;
        self.pod.files.filter.clear();
        let (ctx, ns, pod) = (sel.ctx.clone(), sel.ns.clone(), sel.name.clone());
        self.pod_ask(pod::Ask::List(path.clone()), move |k| {
            // With a slash at the end a link to a folder shows the folder.
            let p = if path == "/" { path } else { format!("{path}/") };
            run_reader(k, &ctx, &ns, &pod, &c, &["ls", "-lAn", "--", &p], LIST_CAP).map(packed)
        });
    }

    fn files_open(&mut self, sel: &Selected, path: &str) {
        let Some(c) = self.pod.files.container.clone() else { return };
        if !self.may_exec() {
            return;
        }
        self.pod.files.view = Some(View_ { path: path.to_string(), content: None, uncovered: false });
        let (ctx, ns, pod, path) = (sel.ctx.clone(), sel.ns.clone(), sel.name.clone(), path.to_string());
        self.pod_ask(pod::Ask::Open(path.clone()), move |k| run_reader(k, &ctx, &ns, &pod, &c, &["head", "-c", &(FILE_CAP + 1).to_string(), "--", &path], FILE_CAP).map(packed));
    }

    pub(super) fn pod_files(&mut self, ui: &mut Ui, sel: &Selected, o: &Value) {
        let running: Vec<String> = pod::containers(o).iter().filter_map(|c| c["name"].as_str()).filter(|n| pod::status_of(o, "containerStatuses", n).map(|s| s["state"]["running"].is_object()).unwrap_or(false)).map(String::from).collect();
        if self.pod.files.container.is_none() {
            let mut go = None;
            card(ui, |ui| {
                ui.label(RichText::new("Look around in a container").size(z(16.0)).color(TEXT_DEFAULT()));
                ui.add(egui::Label::new(RichText::new("Kubedog runs “ls” and “head” in it to show its folders and files. It only reads; nothing is changed, and files that may hold secrets stay blurred until you click them.").size(z(13.0)).color(TEXT_MUTED())).wrap());
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    for c in &running {
                        if button(ui, &format!("Open {c}"), true, false) {
                            go = Some(c.clone());
                        }
                    }
                    if running.is_empty() {
                        ui.label(RichText::new("No container is running, so there's nothing to look into.").color(WARNING()));
                    }
                });
            });
            if let (Some(c), true) = (std::env::var("KUBEDOG_SHOT_FILES").ok().filter(|c| running.contains(c)), self.screenshot.is_some()) {
                go = Some(c);
            }
            if let Some(c) = go {
                self.files_start(sel, &c);
                if let Ok(p) = std::env::var("KUBEDOG_SHOT_PATH") {
                    if self.screenshot.is_some() {
                        self.files_go(sel, &p);
                    }
                }
            }
            return;
        }
        // A link led to a file: show its folder and open it.
        if let Some(Err(e)) = &self.pod.files.list {
            let file = self.pod.files.path.clone();
            if e.contains("ot a directory") && file != "/" {
                self.files_go(sel, &join(&file, ".."));
                self.files_open(sel, &file);
            }
        }
        let f = &self.pod.files;
        let (cur, here) = (f.container.clone().unwrap_or_default(), f.path.clone());
        let mut switch: Option<String> = None;
        let mut go: Option<String> = None;
        let mut open_file: Option<String> = None;
        // Container, path, refresh.
        ui.horizontal(|ui| {
            for c in &running {
                if ui.selectable_label(*c == cur, c).clicked() && *c != cur {
                    switch = Some(c.clone());
                }
            }
            ui.separator();
            if ui.add_enabled(here != "/", egui::Button::new("↑")).on_hover_text("One folder up").clicked() {
                go = Some(join(&here, ".."));
            }
            let mut at_ = String::new();
            if ui.link(RichText::new("/").monospace()).clicked() {
                go = Some("/".into());
            }
            for part in here.split('/').filter(|p| !p.is_empty()) {
                at_ = format!("{at_}/{part}");
                if ui.link(RichText::new(clean(part)).monospace()).clicked() {
                    go = Some(at_.clone());
                }
                ui.label(RichText::new("/").monospace().color(TEXT_PLACEHOLDER()));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, "Read again", false, false) {
                    go = Some(here.clone());
                }
                filter_box(ui, &mut self.pod.files.filter, "Filter", u(150.0));
            });
        });
        ui.add_space(6.0);
        let area = ui.available_rect_before_wrap();
        let places_w = u(230.0).min(area.width() * 0.24);
        let has_view = self.pod.files.view.is_some();
        let list_w = if has_view { (area.width() - places_w) * 0.45 } else { area.width() - places_w };
        let places = egui::Rect::from_min_size(area.min, egui::vec2(places_w - 14.0, area.height()));
        let list = egui::Rect::from_min_size(area.min + egui::vec2(places_w, 0.0), egui::vec2(list_w - 12.0, area.height()));
        let viewer = egui::Rect::from_min_max(egui::pos2(list.right() + 16.0, area.top()), area.max);
        // Places: the mounts of this container.
        ui.scope_builder(egui::UiBuilder::new().max_rect(places), |ui| {
            egui::ScrollArea::vertical().id_salt("places").show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.label(RichText::new("Places").size(z(12.0)).color(TEXT_SUBTLE()));
                let mut row = |ui: &mut Ui, path: &str, what: &str, col: Color32| {
                    let (r, resp) = line(ui, u(36.0), true);
                    if path == here {
                        ui.painter().rect_filled(r.expand2(egui::vec2(6.0, 0.0)), CornerRadius::same(6), BG_SELECTED());
                    }
                    label_at(ui, ui.painter(), r.left_top() + egui::vec2(0.0, u(11.0)), path, 12.5, PRIMARY_TEXT(), r.width());
                    label_at(ui, ui.painter(), r.left_top() + egui::vec2(0.0, u(26.0)), what, 11.0, col, r.width());
                    if resp.on_hover_text(path.to_string()).clicked() {
                        go = Some(path.to_string());
                    }
                };
                row(ui, "/", "the container itself", TEXT_PLACEHOLDER());
                let vols = o["spec"]["volumes"].as_array().cloned().unwrap_or_default();
                for c in pod::containers(o).iter().filter(|c| c["name"].as_str() == Some(cur.as_str())) {
                    for m in c["volumeMounts"].as_array().into_iter().flatten() {
                        let v = vols.iter().find(|v| v["name"] == m["name"]).cloned().unwrap_or_default();
                        let (what, col) = volume_words(&v);
                        row(ui, m["mountPath"].as_str().unwrap_or(""), &what, col);
                    }
                }
            });
        });
        // The folder.
        ui.scope_builder(egui::UiBuilder::new().max_rect(list), |ui| match &self.pod.files.list {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Reading the folder…").color(TEXT_SUBTLE()));
                });
            }
            Some(Err(e)) => {
                ui.add(egui::Label::new(RichText::new(e).color(WARNING())).wrap());
            }
            Some(Ok(entries)) => {
                let q = self.pod.files.filter.to_lowercase();
                let shown: Vec<&Entry> = entries.iter().filter(|e| q.is_empty() || e.name.to_lowercase().contains(&q)).collect();
                ui.label(RichText::new(format!("{} of {}", shown.len(), entries.len())).size(z(12.0)).color(TEXT_SUBTLE()));
                let h = u(25.0);
                egui::ScrollArea::vertical().id_salt(("files", &here)).auto_shrink([false, false]).show_rows(ui, h, shown.len(), |ui, range| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for e in &shown[range] {
                        let (r, resp) = line(ui, h, true);
                        let full = join(&here, &e.name);
                        if self.pod.files.view.as_ref().map(|v| v.path == full).unwrap_or(false) {
                            ui.painter().rect_filled(r.expand2(egui::vec2(6.0, 0.0)), CornerRadius::same(5), BG_SELECTED());
                        }
                        file_icon(ui, egui::pos2(r.left() + u(9.0), r.center().y), e.kind, sensitive(&full, &self.pod.files.secret_roots));
                        let name = match &e.target {
                            Some(t) => format!("{}  →  {}", clean(&e.name), clean(t)),
                            None => clean(&e.name),
                        };
                        let wide = r.width() > u(430.0);
                        label_at(ui, ui.painter(), egui::pos2(r.left() + u(26.0), r.center().y), &name, 13.0, if e.kind == 'd' { PRIMARY_TEXT() } else { TEXT_DEFAULT() }, r.width() * if wide { 0.56 } else { 0.7 } - u(26.0));
                        if e.kind == '-' {
                            at_end(ui, r, if wide { 0.72 } else { 1.0 }, &bytes(e.size as f64), 12.0, TEXT_MUTED());
                        }
                        if wide {
                            at_end(ui, r, 1.0, &e.when, 12.0, TEXT_SUBTLE());
                        }
                        if resp.on_hover_text(format!("{}\n{}  {}", clean(&full), e.mode, e.when)).clicked() {
                            match (e.kind, &e.target) {
                                ('d', _) => go = Some(full),
                                ('-', _) => open_file = Some(full),
                                // A link is followed by its text; a file shows itself below.
                                ('l', Some(t)) => go = Some(join(&here, t)),
                                _ => {}
                            }
                        }
                    }
                });
            }
        });
        // The file.
        let mut close = false;
        let shot = self.screenshot.is_some();
        let roots = self.pod.files.secret_roots.clone();
        if let Some(v) = self.pod.files.view.as_mut() {
            ui.scope_builder(egui::UiBuilder::new().max_rect(viewer), |ui| {
                let hide = sensitive(&v.path, &roots) && !v.uncovered;
                ui.horizontal(|ui| {
                    ui.add(egui::Label::new(RichText::new(clean(v.path.rsplit('/').next().unwrap_or(""))).size(z(14.0)).color(TEXT_DEFAULT())).truncate());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        close = button(ui, "Close", false, false);
                        if let Some(Ok((b, _))) = &v.content {
                            if let Ok(t) = std::str::from_utf8(b) {
                                if !hide && button(ui, "Copy", false, false) {
                                    ui.ctx().copy_text(t.to_string());
                                }
                            }
                        }
                    });
                });
                match &v.content {
                    None => {
                        ui.spinner();
                    }
                    Some(Err(e)) => {
                        ui.add(egui::Label::new(RichText::new(e).color(WARNING())).wrap());
                    }
                    Some(Ok((b, more))) => {
                        if hide {
                            ui.label(RichText::new("This may hold a secret.").size(z(12.5)).color(WARNING()));
                            if certs::blurred_block(ui).on_hover_text("Click to show it").clicked() && !shot {
                                v.uncovered = true;
                            }
                        } else {
                            let cut = text_of(b, *more);
                            match cut {
                                Some(t) if t.is_empty() => {
                                    ui.label(RichText::new("Empty.").color(TEXT_SUBTLE()));
                                }
                                Some(t) => {
                                    if *more {
                                        ui.label(RichText::new(format!("The first {}; the file is longer.", bytes(FILE_CAP as f64))).size(z(12.0)).color(WARNING()));
                                    }
                                    Frame::new().fill(LOG_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(10)).show(ui, |ui| {
                                        let lines: Vec<&str> = t.lines().collect();
                                        egui::ScrollArea::both().id_salt(("file", &v.path)).auto_shrink([false, false]).show_rows(ui, z(16.0), lines.len(), |ui, range| {
                                            for l in &lines[range] {
                                                ui.add(egui::Label::new(RichText::new(clean(&l.replace('\t', "    "))).monospace().size(z(12.0)).color(TEXT_DEFAULT())).extend());
                                            }
                                        });
                                    });
                                }
                                None => {
                                    ui.label(RichText::new(format!("Not text ({}{}).", bytes(b.len() as f64), if *more { " and more" } else { "" })).color(TEXT_SUBTLE()));
                                }
                            }
                        }
                    }
                }
            });
        }
        if close {
            self.pod.files.view = None;
        }
        if let Some(c) = switch {
            self.files_start(sel, &c);
        } else if let Some(p) = go {
            self.files_go(sel, &p);
        } else if let Some(p) = open_file {
            self.files_open(sel, &p);
        } else if shot && self.pod.files.view.is_none() {
            if let Some(p) = std::env::var("KUBEDOG_SHOT_FILE").ok().filter(|_| matches!(self.pod.files.list, Some(Ok(_)))) {
                self.files_open(sel, &p);
            }
        }
    }

    // ---------- storage ----------

    pub(super) fn pod_storage(&mut self, ui: &mut Ui, sel: &Selected, o: &Value) {
        let mut open: Option<Selected> = None;
        let mut measure: Option<String> = None;
        let vols = o["spec"]["volumes"].as_array().cloned().unwrap_or_default();
        let claims = self.items_in(&sel.ctx, Kind::PersistentVolumeClaims, &sel.ns).unwrap_or_default();
        self.page_scroll().id_salt("pod-storage").show(ui, |ui| {
            // Disks first.
            let disks: Vec<&Value> = vols.iter().filter(|v| v["persistentVolumeClaim"].is_object()).collect();
            dash::section(ui, "Disks", if disks.is_empty() { "" } else { "the volume claims of this pod" });
            if disks.is_empty() {
                ui.label(RichText::new("This pod has no disk of its own: what it writes is gone when it goes, except on volumes below that live elsewhere.").color(TEXT_SUBTLE()));
            }
            for v in disks {
                let claim = v["persistentVolumeClaim"]["claimName"].as_str().unwrap_or("");
                let c = claims.iter().find(|c| c["metadata"]["name"].as_str() == Some(claim));
                let usage = self.claim_usage(&sel.ctx, &sel.ns, claim).cloned();
                // Or what df said for its mount.
                let mounts = mounts_of(o, v["name"].as_str().unwrap_or(""));
                let measured = mounts.iter().find_map(|(cn, p, _)| match self.pod.df.get(cn) { Some(Some(Ok(l))) => l.iter().find(|d| d.mount.trim_end_matches('/') == p.trim_end_matches('/')).cloned(), _ => None });
                card(ui, |ui| {
                    let (r, resp) = line(ui, u(24.0), true);
                    at(ui, r, 0.0, 0.6, claim, 14.0, PRIMARY_TEXT());
                    let words = c.map(|c| format!("{} · {} · {}", c["status"]["capacity"]["storage"].as_str().unwrap_or(""), c["spec"]["storageClassName"].as_str().unwrap_or("no class"), c["spec"]["accessModes"].as_array().map(|a| a.iter().filter_map(|m| m.as_str()).map(mode_words).collect::<Vec<_>>().join(", ")).unwrap_or_default())).unwrap_or_default();
                    at_end(ui, r, 1.0, &words, 12.5, TEXT_MUTED());
                    if resp.clicked() {
                        open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::PersistentVolumeClaims, ns: sel.ns.clone(), name: claim.into() });
                    }
                    let nums = usage.map(|x| (x.used, x.capacity, x.available, "from the node")).or(measured.map(|d| (d.used, d.size, d.avail, "from df")));
                    match nums {
                        Some((used, size, free, from)) => {
                            let f = used / size.max(1.0);
                            let (r, _) = line(ui, u(24.0), false);
                            bar(ui, r, 0.0, 0.5, f, storage::usage_color(f));
                            at(ui, r, 0.52, 0.48, &format!("{:.0}%  ·  {} used, {} free of {}  ({from})", f * 100.0, bytes(used), bytes(free), bytes(size)), 12.5, TEXT_DEFAULT());
                        }
                        None => {
                            ui.label(RichText::new("How full it is isn't known yet: the node doesn't tell this account. Measure it below.").size(z(12.5)).color(TEXT_SUBTLE()));
                        }
                    }
                    for (cn, p, ro) in &mounts {
                        ui.label(RichText::new(format!("{p}  in {cn}{}", if *ro { ", read only" } else { "" })).monospace().size(z(12.0)).color(TEXT_MUTED()));
                    }
                });
                ui.add_space(8.0);
            }
            // df.
            dash::section(ui, "Measure", "runs “df” in a container; it only reads");
            ui.horizontal_wrapped(|ui| {
                for c in pod::containers(o) {
                    let name = c["name"].as_str().unwrap_or("");
                    let up = pod::status_of(o, "containerStatuses", name).map(|s| s["state"]["running"].is_object()).unwrap_or(false);
                    if ui.add_enabled(up, egui::Button::new(format!("df in {name}"))).clicked() {
                        measure = Some(name.to_string());
                    }
                }
            });
            for c in pod::containers(o) {
                let name = c["name"].as_str().unwrap_or("");
                match self.pod.df.get(name) {
                    Some(None) => {
                        ui.spinner();
                    }
                    Some(Some(Err(e))) => {
                        ui.label(RichText::new(format!("{name}: {e}")).color(WARNING()));
                    }
                    Some(Some(Ok(list))) => {
                        ui.add_space(6.0);
                        let paths: HashSet<String> = c["volumeMounts"].as_array().into_iter().flatten().filter_map(|m| m["mountPath"].as_str()).map(|p| p.trim_end_matches('/').to_string()).chain(["".to_string()]).collect();
                        let mine: Vec<&Df> = list.iter().filter(|d| paths.contains(d.mount.trim_end_matches('/'))).collect();
                        card(ui, |ui| {
                            ui.label(RichText::new(name).size(z(14.0)).color(TEXT_DEFAULT()));
                            for d in mine {
                                let f = d.used / (d.used + d.avail).max(1.0);
                                let (r, resp) = line(ui, u(26.0), false);
                                at(ui, r, 0.0, 0.4, &d.mount, 12.5, TEXT_DEFAULT());
                                bar(ui, r, 0.41, 0.24, f, storage::usage_color(f));
                                at_end(ui, r, 0.72, &format!("{:.0}%", f * 100.0), 12.5, storage::usage_color(f));
                                at_end(ui, r, 1.0, &format!("{} free of {}", bytes(d.avail), bytes(d.size)), 12.5, TEXT_MUTED());
                                resp.on_hover_text(clean(&d.source));
                            }
                            ui.label(RichText::new("Memory-backed mounts show what the node allows, and “/” the node's own disk, shared with other pods.").size(z(11.5)).color(TEXT_PLACEHOLDER()));
                        });
                    }
                    None => {}
                }
            }
            // Everything else.
            let rest: Vec<&Value> = vols.iter().filter(|v| !v["persistentVolumeClaim"].is_object()).collect();
            if !rest.is_empty() {
                dash::section(ui, "Other volumes", "");
                card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for v in rest {
                        let (what, col) = volume_words(v);
                        let (r, resp) = line(ui, u(26.0), false);
                        ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.0), col);
                        label_at(ui, ui.painter(), egui::pos2(r.left() + u(18.0), r.center().y), &what, 12.5, TEXT_DEFAULT(), r.width() * 0.5);
                        let m = mounts_of(o, v["name"].as_str().unwrap_or(""));
                        let mut paths: Vec<String> = m.iter().map(|x| x.1.clone()).collect();
                        paths.sort();
                        paths.dedup();
                        let t = if paths.is_empty() { "only used before the start".to_string() } else { paths.join(", ") };
                        at(ui, r, 0.55, 0.45, &t, 12.0, TEXT_SUBTLE());
                        resp.on_hover_text(m.iter().map(|x| format!("{} in {}", x.1, x.0)).collect::<Vec<_>>().join("\n"));
                    }
                });
            }
            ui.add_space(20.0);
        });
        if let Some(c) = measure {
            if self.may_exec() {
                self.pod.df.insert(c.clone(), None);
                let (ctx, ns, pod, cc) = (sel.ctx.clone(), sel.ns.clone(), sel.name.clone(), c.clone());
                self.pod_ask(pod::Ask::Df(c), move |k| run_reader(k, &ctx, &ns, &pod, &cc, &["df", "-kP"], LIST_CAP).map(|x| String::from_utf8_lossy(&x.0).to_string()));
            }
        }
        if let (Ok(c), true) = (std::env::var("KUBEDOG_SHOT_DF"), self.screenshot.is_some() && self.may_exec()) {
            if !self.pod.df.contains_key(&c) {
                self.pod.df.insert(c.clone(), None);
                let (ctx, ns, pod, cc) = (sel.ctx.clone(), sel.ns.clone(), sel.name.clone(), c.clone());
                self.pod_ask(pod::Ask::Df(c), move |k| run_reader(k, &ctx, &ns, &pod, &cc, &["df", "-kP"], LIST_CAP).map(|x| String::from_utf8_lossy(&x.0).to_string()));
            }
        }
        if let Some(s) = open {
            self.navigate(View::Resource(s.kind), Some(s));
        }
    }
}

/// (container, path, read only) where a volume is mounted.
fn mounts_of(o: &Value, volume: &str) -> Vec<(String, String, bool)> {
    let mut out = vec![];
    for c in pod::containers(o) {
        for m in c["volumeMounts"].as_array().into_iter().flatten().filter(|m| m["name"].as_str() == Some(volume)) {
            out.push((c["name"].as_str().unwrap_or("").to_string(), m["mountPath"].as_str().unwrap_or("").to_string(), m["readOnly"] == true));
        }
    }
    out
}

fn mode_words(m: &str) -> &str {
    match m {
        "ReadWriteOnce" => "one node at a time",
        "ReadWriteMany" => "shared by many nodes",
        "ReadOnlyMany" => "read by many nodes",
        "ReadWriteOncePod" => "one pod at a time",
        x => x,
    }
}

/// What a volume is, in words, and its colour.
fn volume_words(v: &Value) -> (String, Color32) {
    if let Some(c) = v["persistentVolumeClaim"]["claimName"].as_str() {
        return (format!("disk {c}"), SUCCESS());
    }
    if let Some(s) = v["secret"]["secretName"].as_str() {
        return (format!("secret {s}"), WARNING());
    }
    if let Some(s) = v["configMap"]["name"].as_str() {
        return (format!("config map {s}"), INFO());
    }
    if v["emptyDir"].is_object() {
        return (if v["emptyDir"]["medium"] == "Memory" { "scratch space in memory".into() } else { "scratch space, gone with the pod".into() }, TEXT_SUBTLE());
    }
    if let Some(p) = v["hostPath"]["path"].as_str() {
        return (format!("the node's own {p}"), DANGER());
    }
    if is_secret_volume(v) {
        return ("account token and certificates".into(), WARNING());
    }
    if v["projected"].is_object() || v["downwardAPI"].is_object() {
        return ("facts about the pod".into(), INFO());
    }
    let kind = v.as_object().into_iter().flatten().map(|x| x.0.as_str()).find(|k| *k != "name").unwrap_or("volume");
    (kind.to_string(), TEXT_SUBTLE())
}

fn file_icon(ui: &Ui, c: egui::Pos2, kind: char, secret: bool) {
    let p = ui.painter();
    let col = if secret { WARNING() } else if kind == 'd' { PRIMARY_TEXT() } else { TEXT_SUBTLE() };
    let s = u(6.0);
    match kind {
        'd' => {
            p.rect_filled(egui::Rect::from_min_max(c + egui::vec2(-s, -s * 0.75), c + egui::vec2(-s * 0.1, 0.0)), CornerRadius::same(2), col);
            p.rect_filled(egui::Rect::from_min_max(c + egui::vec2(-s, -s * 0.4), c + egui::vec2(s, s * 0.8)), CornerRadius::same(2), col);
        }
        _ => {
            let r = egui::Rect::from_center_size(c, egui::vec2(s * 1.5, s * 1.9));
            p.rect_stroke(r, CornerRadius::same(2), Stroke::new(1.3, col), egui::StrokeKind::Inside);
            if kind == 'l' {
                p.line_segment([r.left_bottom() + egui::vec2(2.5, -2.5), r.right_top() + egui::vec2(-2.5, 2.5)], Stroke::new(1.3, col));
            } else if secret {
                p.circle_filled(c, s * 0.35, col);
            }
        }
    }
}

/// Bytes as text, or None when they aren't. A character cut in half at the end is left out.
fn text_of(b: &[u8], more: bool) -> Option<&str> {
    if b.contains(&0) {
        return None;
    }
    match std::str::from_utf8(b) {
        Ok(t) => Some(t),
        Err(e) if more && b.len() - e.valid_up_to() < 4 => std::str::from_utf8(&b[..e.valid_up_to()]).ok(),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listings() {
        let busybox = "total 148\nlrwxrwxrwx    1 0        0               11 Nov 23 15:18 core -> /proc/kcore\ncrw-rw-rw-    1 0        0           1,   7 Nov 23 15:18 full\ndrwxrwxrwt    2 0        0               40 Nov 23 15:18 mqueue\n-rw-r--r--    1 0        0                7 Oct 21  2025 a  b.txt\n";
        let gnu = "total 188\ncrw-rw-rw- 1 0 0 1, 7 Nov 23 15:18 full\n-rw-r--r--+ 1 1000 0 7 2026-06-13 15:17 x -> y\nbroken line\n";
        let l = parse_ls(busybox);
        assert_eq!(l.iter().map(|e| (e.kind, e.name.as_str())).collect::<Vec<_>>(), vec![('d', "mqueue"), ('-', "a  b.txt"), ('l', "core"), ('c', "full")]);
        assert_eq!(l[2].target.as_deref(), Some("/proc/kcore"));
        assert_eq!((l[1].size, l[1].when.as_str()), (7, "Oct 21 2025"));
        let g = parse_ls(gnu);
        // A file's name may hold an arrow; only links have targets.
        assert_eq!(g.iter().map(|e| (e.kind, e.name.as_str(), e.target.is_some())).collect::<Vec<_>>(), vec![('c', "full", false), ('-', "x -> y", false)]);
        assert!(parse_ls("").is_empty());
        let d = parse_df("Filesystem 1024-blocks Used Available Capacity Mounted on\noverlay 263637176 170005684 80193388 68% /\ntmpfs 0 0 0 - /x\n/dev/sda 100 50 50 50% /my data\n");
        assert_eq!(d.iter().map(|x| x.mount.as_str()).collect::<Vec<_>>(), vec!["/", "/my data"]);
    }

    #[test]
    fn paths_and_secrets() {
        assert_eq!((join("/a/b", "../c").as_str(), join("/", "x").as_str(), join("/a", "/etc/../b").as_str(), join("/a", "../../..").as_str()), ("/a/c", "/x", "/b", "/"));
        let pod = serde_json::json!({"spec": {"volumes": [{"name": "s", "secret": {"secretName": "x"}}, {"name": "c", "configMap": {"name": "y"}}, {"name": "t", "projected": {"sources": [{"serviceAccountToken": {}}]}}],
            "containers": [{"name": "a", "volumeMounts": [{"name": "s", "mountPath": "/creds/"}, {"name": "c", "mountPath": "/conf"}, {"name": "t", "mountPath": "/tok"}]}]}});
        let r = secret_roots(&pod, "a");
        for p in ["/creds/x", "/tok/ca.crt", "/var/run/secrets/kubernetes.io/serviceaccount/token", "/proc/1/environ", "/app/.env", "/x/tls.key", "/home/my-password.txt"] {
            assert!(sensitive(p, &r), "{p}");
        }
        for p in ["/conf/app.yaml", "/credsx/readme", "/etc/hosts"] {
            assert!(!sensitive(p, &r), "{p}");
        }
        assert_eq!(clean("a\u{1b}[31mb\u{202e}"), "a\u{fffd}[31mb\u{fffd}");
        assert_eq!(text_of("hé".as_bytes(), false), Some("hé"));
        assert_eq!(text_of(&"hé".as_bytes()[..2], true), Some("h"));
        assert_eq!(text_of(b"a\0b", false), None);
        assert!(explain("error: exec: \"ls\": executable file not found in $PATH", "ls").contains("no “ls” program"));
        assert!(explain("Error from server (Forbidden): pods is forbidden", "ls").contains("may not run"));
        let (b, m) = unpacked(&packed((vec![0, 255, 7], true))).unwrap();
        assert_eq!((b, m), (vec![0, 255, 7], true));
    }

    #[test]
    fn only_reads() {
        let k = Kubectl::detect();
        assert!(run_reader(&k, "c", "n", "p", "x", &["rm", "-rf", "/"], 10).unwrap_err().contains("not a reading"));
        assert!(run_reader(&k, "c", "n", "p", "x", &[], 10).is_err());
    }
}
