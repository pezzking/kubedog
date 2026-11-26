//! Reading from a service inside a cluster with the login kept in its own secret. A short-lived
//! `kubectl port-forward` leads to it; curl gets the address and the credentials over a pipe, so
//! they're never on a command line. Nothing is stored or shown, redirects and proxies are off,
//! and only GET requests are ever sent.

use super::*;
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

static TUNNELS: Mutex<Vec<Arc<Mutex<Child>>>> = Mutex::new(Vec::new());

/// End every open tunnel (the app is closing).
pub(super) fn close_all() {
    if let Ok(mut t) = TUNNELS.lock() {
        for c in t.drain(..) {
            if let Ok(mut c) = c.lock() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

/// A port on this computer leading to one port in the cluster, while it's alive.
pub(super) struct Tunnel {
    pub port: u16,
    child: Arc<Mutex<Child>>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Ok(mut t) = TUNNELS.lock() {
            t.retain(|c| !Arc::ptr_eq(c, &self.child));
        }
    }
}

/// The port in "Forwarding from 127.0.0.1:54321 -> 9200".
fn forwarded_port(line: &str) -> Option<u16> {
    line.strip_prefix("Forwarding from 127.0.0.1:")?.split(' ').next()?.parse().ok()
}

pub(super) fn tunnel(k: &Kubectl, ctx: &str, ns: &str, target: &str, port: u16) -> Result<Tunnel, String> {
    let args: Vec<String> = ["--context", ctx, "-n", ns, "port-forward", "--address", "127.0.0.1", target, &format!(":{port}")].iter().map(|s| s.to_string()).collect();
    let mut cmd = k.command(&args).ok_or("kubectl was not found on this computer")?;
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("could not start kubectl: {e}"))?;
    let (out, err) = (child.stdout.take(), child.stderr.take());
    let child = Arc::new(Mutex::new(child));
    if let Ok(mut t) = TUNNELS.lock() {
        t.push(child.clone());
    }
    let mut t = Tunnel { port: 0, child };
    let (tx, rx) = channel::<Result<u16, String>>();
    std::thread::spawn(move || {
        if let Some(o) = out {
            // Read on to the end, so kubectl never waits for a full pipe.
            for line in std::io::BufReader::new(o).lines().map_while(Result::ok) {
                if let Some(p) = forwarded_port(&line) {
                    let _ = tx.send(Ok(p));
                }
            }
        }
        let mut s = String::new();
        if let Some(mut e) = err {
            let _ = std::io::Read::read_to_string(&mut e, &mut s);
        }
        let _ = tx.send(Err(s.trim().to_string()));
    });
    match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(port)) => {
            t.port = port;
            Ok(t)
        }
        Ok(Err(e)) => Err(if e.is_empty() { "the port forward ended".into() } else { truncate(&e, 300) }),
        Err(_) => Err("the port forward didn't start in 15 seconds".into()),
    }
}

/// How to sign in.
pub(super) enum Auth {
    None,
    User(String, String),
    Token(String),
}

/// One value of a secret, decoded. Errors never contain it.
pub(super) fn secret_value(k: &Kubectl, ctx: &str, ns: &str, name: &str, key: &str) -> Result<String, String> {
    let args: Vec<String> = ["--context", ctx, "-n", ns, "get", "secret", name, "-o", &format!("jsonpath={{.data.{}}}", key.replace('.', "\\.")), &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
    let b64 = k.run(&args)?;
    if b64.trim().is_empty() {
        return Err(format!("secret {name} has no {key}"));
    }
    b64_decode(b64.trim()).and_then(|b| String::from_utf8(b).ok()).map(|s| s.trim().to_string()).ok_or_else(|| format!("{key} in secret {name} isn't text"))
}

/// A value for curl's config file, in quotes. Control characters are refused.
fn quoted(s: &str) -> Result<String, String> {
    if s.chars().any(|c| c.is_control()) {
        return Err("a value has characters that can't be used in a request".into());
    }
    Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

const MARK: &str = "<<<kubedog:";

fn config(auth: &Auth, base: &str, port: u16, paths: &[String], ca: Option<&str>) -> Result<String, String> {
    let scheme = base.split(':').next().unwrap_or("");
    let mut c = String::from("silent\nshow-error\nget\nmax-time = 25\nnoproxy = \"*\"\n");
    c += &format!("proto = \"={scheme}\"\nconnect-to = \"::127.0.0.1:{port}\"\nwrite-out = \"\\n{MARK}%{{http_code}}>>>\\n\"\n");
    if let Some(ca) = ca {
        c += &format!("cacert = {}\n", quoted(ca)?);
    }
    match auth {
        Auth::None => {}
        Auth::User(u, p) => c += &format!("user = {}\n", quoted(&format!("{u}:{p}"))?),
        Auth::Token(t) => c += &format!("header = {}\n", quoted(&format!("Authorization: Bearer {t}"))?),
    }
    for p in paths {
        c += &format!("url = {}\n", quoted(&format!("{base}{p}"))?);
    }
    Ok(c)
}

/// curl's output: one (status, body) per address.
fn answers(out: &str) -> Vec<(u16, String)> {
    let mut v = vec![];
    let mut rest = out;
    while let Some(i) = rest.find(MARK) {
        let body = rest[..i].trim_end_matches('\n').to_string();
        let tail = &rest[i + MARK.len()..];
        let Some(e) = tail.find(">>>") else { break };
        v.push((tail[..e].parse().unwrap_or(0), body));
        rest = tail[e + 3..].trim_start_matches('\n');
    }
    v
}

/// GET several addresses through a tunnel.
pub(super) fn get(auth: &Auth, base: &str, t: &Tunnel, paths: &[String], ca_pem: Option<&str>) -> Result<Vec<(u16, String)>, String> {
    // The certificate (not a secret) has to be a file; the name is random and it's gone afterwards.
    struct Gone(std::path::PathBuf);
    impl Drop for Gone {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let ca = match ca_pem {
        Some(pem) => {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            let path = std::env::temp_dir().join(format!("kubedog-ca-{}-{}-{nanos}.pem", std::process::id(), t.port));
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| format!("couldn't keep the certificate for a moment: {e}"))?;
            f.write_all(pem.as_bytes()).map_err(|e| e.to_string())?;
            Some(Gone(path))
        }
        None => None,
    };
    let cfg = config(auth, base, t.port, paths, ca.as_ref().and_then(|g| g.0.to_str()))?;
    let mut curl = Command::new("curl");
    crate::kube::quiet(&mut curl);
    let mut child = curl
        .args(["-q", "-K", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "curl was not found on this computer".to_string())?;
    if let Some(mut i) = child.stdin.take() {
        let _ = i.write_all(cfg.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let v = answers(&String::from_utf8_lossy(&out.stdout));
    if v.len() < paths.len() || v.iter().all(|a| a.0 == 0) {
        let e = String::from_utf8_lossy(&out.stderr);
        return Err(truncate(e.lines().next().unwrap_or("no answer"), 200));
    }
    Ok(v)
}

/// What's known of one service, and readings for its charts.
#[derive(Default)]
pub(super) struct Served {
    pub loading: bool,
    pub fetched: Option<Instant>,
    pub error: Option<String>,
    pub data: Option<Value>,
    /// (when, counter or rate, another)
    pub hist: std::collections::VecDeque<(i64, f64, f64)>,
}

impl KubedogApp {
    pub(super) fn login_allowed(&self, key: &str) -> bool {
        if self.screenshot.is_some() {
            return std::env::var("KUBEDOG_SHOT_LOGIN").is_ok();
        }
        self.prefs.logins.iter().any(|k| k == key)
    }

    pub(super) fn allow_login(&mut self, key: &str, on: bool) {
        self.prefs.logins.retain(|k| k != key);
        if on {
            self.prefs.logins.push(key.to_string());
        } else {
            self.served.remove(key);
        }
        self.save();
    }

    /// The question before a login is used. Returns whether it was just allowed.
    pub(super) fn login_card(&mut self, ui: &mut Ui, key: &str, what: &str, how: &str, login: bool) -> bool {
        let mut yes = false;
        card(ui, |ui| {
            ui.label(RichText::new(format!("Look inside {what}?")).size(z(15.0)).strong().color(TEXT_DEFAULT()));
            ui.add_space(4.0);
            ui.add(egui::Label::new(RichText::new(how).size(z(13.0)).color(TEXT_MUTED())).wrap());
            ui.add(egui::Label::new(RichText::new(if login { "Kubedog only reads with it. The login isn't shown or saved: it's read again for every refresh, and used through a short-lived port forward on this computer." } else { "Kubedog only reads, through a short-lived port forward on this computer." }).size(z(12.5)).color(TEXT_SUBTLE())).wrap());
            ui.add_space(8.0);
            yes = button(ui, if login { "Log in and look" } else { "Look inside" }, true, false);
        });
        ui.add_space(12.0);
        if yes {
            self.allow_login(key, true);
            self.refresh_current(true);
        }
        yes
    }

    pub(super) fn on_served(&mut self, key: &str, result: &Result<String, String>) -> bool {
        if !key.starts_with("es|") && !key.starts_with("pulsar|") {
            return false;
        }
        // Logged out while it was being read.
        if !self.login_allowed(key) {
            self.served.remove(key);
            return true;
        }
        let s = self.served.entry(key.to_string()).or_default();
        s.loading = false;
        s.fetched = Some(Instant::now());
        match result.as_ref().map_err(|e| e.clone()).and_then(|t| serde_json::from_str::<Value>(t).map_err(|e| e.to_string())) {
            Ok(v) => {
                let (a, b) = if key.starts_with("es|") { elastic::reading(&v) } else { pulsar::reading(&v) };
                s.hist.push_back((kube::now_secs(), a, b));
                while s.hist.len() > 180 {
                    s.hist.pop_front();
                }
                s.error = None;
                s.data = Some(v);
            }
            Err(e) => s.error = Some(e),
        }
        true
    }

    /// Start a read if it's due. `f` runs on its own thread.
    pub(super) fn serve(&mut self, key: &str, force: bool, f: impl FnOnce(&Kubectl) -> Result<String, String> + Send + 'static) {
        if self.demo || !self.login_allowed(key) {
            return;
        }
        let s = self.served.entry(key.to_string()).or_default();
        if s.loading || (!force && s.fetched.map(|t| t.elapsed() < Duration::from_secs(15)).unwrap_or(false)) {
            return;
        }
        s.loading = true;
        let key = key.to_string();
        self.spawn(move |k| Msg::Text { key, result: f(k) });
    }

    /// The Superpowers part of the sidebar: only what the open clusters really have.
    pub(super) fn sidebar_super(&mut self, ui: &mut Ui) {
        self.sync_crds();
        for c in self.active.clone() {
            for (id, crd) in [("postgres", pg::CRD_CLUSTERS), ("elastic", elastic::CRD)] {
                if self.power_off(id) {
                    continue;
                }
                if let Some(i) = self.crd_index(crd) {
                    let key = Self::custom_list_key(&c, &self.crds[i as usize]);
                    if !self.lists.contains_key(&key) {
                        self.fetch_custom(&c, i);
                    }
                }
            }
            if !self.power_off("pulsar") && !self.lists.contains_key(&Self::list_key(&c, Kind::Pods)) {
                self.fetch_list(&c, Kind::Pods);
            }
        }
        if !self.group_header(ui, "Superpowers", "⚡") {
            return;
        }
        for (view, label) in self.power_pages() {
            let n = if view == View::Incident { self.companion_new() } else { 0 };
            let more = (n > 0).then(|| format!("{n} new"));
            if self.nav_fav(ui, self.view == view && self.selected.is_none(), view, label, label, more.as_deref()) {
                self.powers.sel = None;
                self.incident.sel = None;
                self.pg_sel = None;
                self.es_sel = None;
                self.pu_sel = None;
                self.hive.node = None;
                self.grafana.sel = None;
                self.set_view(view);
            }
        }
        ui.add_space(14.0);
    }

    /// A page's top line with the way back. Returns whether to go back.
    pub(super) fn super_back(&mut self, ui: &mut Ui, id: &pg::PgId, what: &str) -> bool {
        let mut close = ui.input(|i| i.key_pressed(Key::Escape)) && self.dialog.is_none() && self.palette.is_none();
        ui.horizontal(|ui| {
            if back_button(ui).on_hover_text("Back to the list (Esc)").clicked() {
                close = true;
            }
            let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
            ui.painter().circle_filled(d.center(), 3.5, context_color(&id.ctx));
            ui.label(RichText::new(format!("{} · {what}", ctx_label(&id.ctx))).size(z(12.0)).color(TEXT_SUBTLE()));
            self.ai_corner(ui, what != "Why is it broken?");
        });
        close
    }

    /// Cards in a grid: (id, colour, title, lines). Returns the one clicked.
    pub(super) fn super_cards(&self, ui: &mut Ui, cards: &[(pg::PgId, Color32, Vec<(String, Color32)>)]) -> Option<pg::PgId> {
        let mut open = None;
        let gap = 14.0;
        let avail = ui.available_width();
        let cols = ((avail + gap) / (u(400.0) + gap)).floor().max(1.0);
        let w = ((avail + gap) / cols - gap).min(u(520.0));
        let multi = self.active.len() > 1;
        for row in cards.chunks(cols as usize) {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                for (id, tone, lines) in row {
                    let (r, resp) = ui.allocate_exact_size(egui::vec2(w, u(62.0 + 26.0 * lines.len() as f32)), Sense::click());
                    let p = ui.painter();
                    p.rect_filled(r, CornerRadius::same(10), if resp.hovered() { BG_HOVER() } else { BG_CARD() });
                    p.rect_stroke(r, CornerRadius::same(10), Stroke::new(1.0, if resp.hovered() { PRIMARY_TEXT() } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
                    p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(4.0, r.height())), CornerRadius { nw: 10, sw: 10, ne: 0, se: 0 }, *tone);
                    let x = r.left() + 18.0;
                    pg::label_at(ui, p, egui::pos2(x, r.top() + u(24.0)), &id.name, 15.5, PRIMARY_TEXT(), w - 36.0);
                    let sub = if multi { format!("{} · {}", id.ns, ctx_label(&id.ctx)) } else { id.ns.clone() };
                    pg::label_at(ui, p, egui::pos2(x, r.top() + u(45.0)), &sub, 12.0, TEXT_SUBTLE(), w - 36.0);
                    for (i, (t, col)) in lines.iter().enumerate() {
                        pg::label_at(ui, p, egui::pos2(x, r.top() + u(72.0 + 26.0 * i as f32)), t, 12.5, *col, w - 36.0);
                    }
                    if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        open = Some(id.clone());
                    }
                }
            });
            ui.add_space(gap - 5.0);
        }
        open
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests() {
        let c = config(&Auth::User("me".into(), "a\"b\\c".into()), "https://x.y.svc:9200", 555, &["/a?b=c".into()], Some("/tmp/ca.pem")).unwrap();
        assert!(c.contains("user = \"me:a\\\"b\\\\c\"\n") && c.contains("connect-to = \"::127.0.0.1:555\"") && c.contains("proto = \"=https\""));
        assert!(c.contains("noproxy = \"*\"") && !c.contains("location") && !c.contains("insecure"));
        // A line break can't smuggle in another option.
        assert!(config(&Auth::Token("x\nurl = \"http://evil\"".into()), "http://b:1", 1, &[], None).is_err());
        assert!(config(&Auth::None, "http://b:1", 1, &["/a\n".into()], None).is_err());
        assert_eq!(forwarded_port("Forwarding from 127.0.0.1:54321 -> 9200"), Some(54321));
        assert_eq!(forwarded_port("Handling connection for 54321"), None);
        let out = format!("{{\"a\":1}}\n{MARK}200>>>\n\n{MARK}403>>>\n");
        assert_eq!(answers(&out), vec![(200, "{\"a\":1}".to_string()), (403, String::new())]);
        assert!(answers("nothing").is_empty());
    }
}
