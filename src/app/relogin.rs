//! A cluster whose login has ended: says so, and for OpenShift offers `oc login --web` (the sign-in in the browser).
use super::*;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// How long the sign-in in the browser may take before Kubedog stops waiting.
const WAIT: Duration = Duration::from_secs(300);

struct Run {
    got: Arc<Mutex<Option<Result<(), String>>>>,
    stop: Arc<AtomicBool>,
    /// The oc that waits for the browser, so it can be ended when Kubedog quits.
    child: Arc<Mutex<Option<std::process::Child>>>,
}

#[derive(Default)]
pub(super) struct Relogin {
    running: HashMap<String, Run>,
    /// What the last try said, per cluster.
    said: HashMap<String, (String, bool)>,
    /// Put away until the logins are fine again: the clusters it was put away for.
    hidden: Vec<String>,
}

/// What can be offered for a cluster whose login has ended.
#[derive(Debug, PartialEq)]
pub(super) enum Offer {
    /// `oc login --web` for this address.
    Web(String),
    /// The same, but there's no `oc` on this computer.
    NoOc,
    /// The whole app works through a Linux in WSL: its browser isn't ours. The line to run there.
    InLinux(String),
    /// Not a login `oc` made: Kubedog doesn't know how this cluster is logged in to.
    Unknown,
}

/// Whether kubectl's error says the login is missing or has ended (not: you may not do this).
pub(super) fn logged_out(e: &str) -> bool {
    e.contains("You must be logged in to the server") || e.contains("(Unauthorized)") || e.contains("error: Unauthorized") || e.contains("asked for the client to provide credentials")
}

/// A login made by `oc login`: it names the user "name/cluster", with the cluster named after its address.
pub(super) fn oc_made(c: &ContextInfo) -> bool {
    !c.cluster.is_empty() && c.user.strip_suffix(&c.cluster).is_some_and(|u| u.len() > 1 && u.ends_with('/'))
}

/// The address as it may be handed to `oc`: https, a host, perhaps a port, and nothing else.
pub(super) fn server_ok(server: &str) -> Option<String> {
    let rest = server.strip_prefix("https://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
        Some(_) => return None,
        None => (rest, None),
    };
    let fine = !host.is_empty() && host.len() <= 253 && !host.starts_with(['-', '.']) && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    fine.then(|| match port {
        Some(p) => format!("https://{host}:{p}"),
        None => format!("https://{host}"),
    })
}

/// A small question only a logged-in account gets an answer to (yes or no; either is fine here).
pub(super) fn check_args(ctx: &str) -> Vec<String> {
    ["--context", ctx, "auth", "can-i", "get", "pods", "--request-timeout=15s"].map(String::from).to_vec()
}

pub(super) fn login_args(server: &str) -> Vec<String> {
    vec!["login".into(), "--web".into(), format!("--server={server}")]
}

pub(super) fn offer(c: &ContextInfo, wsl: bool, has_oc: bool) -> Offer {
    match server_ok(&c.server).filter(|_| oc_made(c)) {
        None => Offer::Unknown,
        Some(s) if wsl => Offer::InLinux(format!("oc {}", login_args(&s).join(" "))),
        Some(s) if has_oc => Offer::Web(s),
        Some(_) => Offer::NoOc,
    }
}

/// Of the answers a cluster gave (when, its error), the newest decides: an old refusal that was never read again
/// doesn't keep the notice up after a login made somewhere else.
pub(super) fn newest_says_out<T: Ord>(answers: impl Iterator<Item = (T, Option<String>)>) -> bool {
    answers.max_by(|a, b| a.0.cmp(&b.0)).is_some_and(|(_, e)| e.as_deref().is_some_and(logged_out))
}

/// What `oc` said when it failed, as one short line.
fn why(stderr: &str) -> String {
    if stderr.contains("unknown flag: --web") {
        return "This oc is too old for the sign-in in a browser. A newer oc knows it; or log in the way you usually do and press Refresh.".into();
    }
    let line = stderr.lines().map(str::trim).filter(|l| !l.is_empty()).last().unwrap_or("oc gave no reason");
    truncate(line.trim_start_matches("error: "), 220)
}

fn oc_program(k: &Kubectl) -> Option<std::path::PathBuf> {
    // kubectl may itself be oc, on computers that only have that one.
    kube::find_program("oc").or_else(|| k.bin.clone().filter(|b| b.file_stem().is_some_and(|s| s == "oc")))
}

impl KubedogApp {
    /// The open clusters that said the login has ended, in the order they're open.
    fn logged_out_clusters(&self) -> Vec<String> {
        if self.screenshot.is_some() {
            return if std::env::var("KUBEDOG_SHOT_RELOGIN").is_ok() { self.active.clone() } else { vec![] };
        }
        self.active
            .iter()
            .filter(|c| {
                let pre = format!("list|{c}|");
                newest_says_out(self.lists.iter().filter(|(k, _)| k.starts_with(&pre)).filter_map(|(_, l)| Some((l.fetched?, l.error.clone()))))
            })
            .cloned()
            .collect()
    }

    /// When Kubedog quits: an oc that still waits for a browser is ended, so it can't write a login later.
    pub(super) fn relogin_end_all(&mut self) {
        for (_, r) in self.relogin.running.drain() {
            r.stop.store(true, Ordering::Relaxed);
            if let Some(mut c) = r.child.lock().ok().and_then(|mut c| c.take()) {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// Every frame: takes the result of a sign-in that ended.
    pub(super) fn relogin_tick(&mut self) {
        let done: Vec<(String, Result<(), String>)> = self.relogin.running.iter().filter_map(|(c, r)| r.got.lock().ok().and_then(|mut g| g.take()).map(|g| (c.clone(), g))).collect();
        for (ctx, got) in done {
            self.relogin.running.remove(&ctx);
            match got {
                Ok(()) => {
                    // Everything that was refused is read again, and what was decided from it too: the
                    // namespaces and which superpowers there are. The kubeconfig may name the login differently now.
                    let pre = format!("list|{ctx}|");
                    let again: Vec<Kind> = self.lists.iter_mut().filter(|(k, l)| k.starts_with(&pre) && l.error.as_deref().is_some_and(logged_out)).filter_map(|(k, l)| {
                        l.error = None;
                        l.fetched = None;
                        l.gen += 1;
                        kind_from_key(k)
                    }).collect();
                    self.relogin.said.remove(&ctx);
                    self.load_contexts();
                    self.namespaces.remove(&ctx);
                    self.fetch_namespaces(&ctx);
                    self.powers.asked.remove(&ctx);
                    for k in again {
                        self.fetch_list(&ctx, k);
                    }
                    self.refresh_current(true);
                    self.toast(format!("{}: logged in", ctx_label(&ctx)), false);
                }
                Err(e) => {
                    self.relogin.said.insert(ctx, (e, true));
                }
            }
        }
    }

    fn relogin_start(&mut self, ctx: &str, server: &str) {
        if self.screenshot.is_some() || self.relogin.running.contains_key(ctx) {
            return;
        }
        let Some(oc) = oc_program(&self.kubectl) else { return };
        let mut cmd = self.kubectl.other(&oc, &login_args(server));
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());
        let (got, stop, kept) = (Arc::new(Mutex::new(None)), Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(None)));
        self.relogin.said.remove(ctx);
        self.relogin.running.insert(ctx.to_string(), Run { got: got.clone(), stop: stop.clone(), child: kept.clone() });
        let (egui_ctx, kubectl, ctx) = (self.egui_ctx.clone(), self.kubectl.clone(), ctx.to_string());
        std::thread::spawn(move || {
            let answer = (|| {
                let mut child = cmd.spawn().map_err(|e| format!("oc couldn't be started: {e}"))?;
                // What oc says is read beside it: a browser it started may keep the pipe open long after oc ended.
                let (tx, rx) = std::sync::mpsc::channel();
                if let Some(e) = child.stderr.take() {
                    std::thread::spawn(move || {
                        use std::io::Read;
                        let mut err = String::new();
                        let _ = e.take(16 * 1024).read_to_string(&mut err);
                        let _ = tx.send(err);
                    });
                }
                *kept.lock().map_err(|_| "oc couldn't be kept".to_string())? = Some(child);
                let began = Instant::now();
                let status = loop {
                    let mut k = kept.lock().map_err(|_| "oc couldn't be kept".to_string())?;
                    // Taken away: Kubedog is quitting.
                    let Some(child) = k.as_mut() else { return Err("Stopped.".to_string()) };
                    match child.try_wait() {
                        Ok(Some(s)) => break s,
                        Ok(None) => {}
                        Err(e) => return Err(e.to_string()),
                    }
                    let (stopped, late) = (stop.load(Ordering::Relaxed), began.elapsed() > WAIT);
                    if stopped || late {
                        let _ = child.kill();
                        let _ = child.wait();
                        *k = None;
                        return Err(if stopped { "Stopped.".to_string() } else { "No sign-in came back from the browser in five minutes.".to_string() });
                    }
                    drop(k);
                    std::thread::sleep(Duration::from_millis(150));
                };
                if let Ok(mut k) = kept.lock() {
                    *k = None;
                }
                if !status.success() {
                    return Err(why(&rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default()));
                }
                // oc logged someone in; whether that renewed the login this context uses is asked from the cluster.
                match kubectl.run(&check_args(&ctx)) {
                    Err(e) if logged_out(&e) => Err("The sign-in worked, but this cluster still says you aren't logged in: it was probably for another user than the one this context uses. oc made or chose a context for that user; open that one from the start page, or sign in as this context's user.".to_string()),
                    _ => Ok(()),
                }
            })();
            if let Ok(mut g) = got.lock() {
                *g = Some(answer);
            }
            egui_ctx.request_repaint();
        });
    }

    /// Above the page: one card for the open clusters whose login has ended, a row for each.
    pub(super) fn relogin_cards(&mut self, ui: &mut Ui) {
        let out = self.logged_out_clusters();
        // Put away only as long as it's about the same clusters.
        self.relogin.hidden.retain(|c| out.contains(c));
        let out: Vec<String> = out.into_iter().filter(|c| !self.relogin.hidden.contains(c)).collect();
        if out.is_empty() {
            return;
        }
        let has_oc = match std::env::var("KUBEDOG_SHOT_RELOGIN").ok().filter(|_| self.screenshot.is_some()).as_deref() {
            Some("none") => false,
            Some(_) => true,
            None => oc_program(&self.kubectl).is_some(),
        };
        let offers: Vec<(String, Offer)> = out
            .iter()
            .map(|ctx| {
                let what = match self.contexts.iter().find(|c| c.name == *ctx) {
                    // For a picture: a made-up login by oc.
                    Some(_) if self.screenshot.is_some() => offer(&ContextInfo { name: ctx.clone(), cluster: "api-shop-example-com:6443".into(), user: "dev/api-shop-example-com:6443".into(), namespace: String::new(), server: "https://api.shop.example.com:6443".into(), source: String::new() }, false, has_oc),
                    Some(c) => offer(c, self.kubectl.wsl.is_some(), has_oc),
                    None => Offer::Unknown,
                };
                (ctx.clone(), what)
            })
            .collect();
        let (mut start, mut stop, mut hide) = (None, None, false);
        Frame::new().fill(WARN_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            for (ctx, what) in &offers {
                let running = self.relogin.running.contains_key(ctx);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{}: your login has ended", ctx_label(ctx))).color(WARNING()).strong());
                    match what {
                        Offer::Web(_) if running => {
                            ui.spinner();
                            ui.label(RichText::new("waiting for the sign-in in your browser").color(TEXT_MUTED()).size(z(12.5)));
                            if button(ui, "Stop", false, false) {
                                stop = Some(ctx.clone());
                            }
                        }
                        Offer::Web(server) => {
                            if button(ui, "Log in", true, false) {
                                start = Some((ctx.clone(), server.clone()));
                            }
                        }
                        Offer::InLinux(line) => {
                            ui.add(egui::Label::new(RichText::new(line).monospace().size(z(12.5)).color(TEXT_DEFAULT())).truncate()).on_hover_text(line);
                            if button(ui, "Copy", false, false) {
                                ui.ctx().copy_text(line.clone());
                            }
                        }
                        Offer::NoOc | Offer::Unknown => {}
                    }
                });
                if let Some((t, bad)) = self.relogin.said.get(ctx).filter(|_| !running) {
                    ui.add(egui::Label::new(RichText::new(t).color(if *bad { DANGER() } else { SUCCESS() }).size(z(12.5))).wrap());
                }
            }
            ui.add_space(2.0);
            let has = |f: fn(&Offer) -> bool| offers.iter().any(|(_, o)| f(o));
            let mut say = |ui: &mut Ui, t: &str| {
                ui.add(egui::Label::new(RichText::new(t).color(TEXT_MUTED()).size(z(12.5))).wrap());
            };
            if has(|o| matches!(o, Offer::Web(_))) {
                say(ui, "Log in opens your browser for the sign-in. OpenShift's oc then saves the new login in your kubeconfig file and makes that cluster the current one for kubectl and oc in your terminals, as it does when you run oc login yourself.");
            }
            if has(|o| matches!(o, Offer::NoOc)) {
                say(ui, "Logging in from here needs OpenShift's oc program, which isn't on this computer. Install oc (your cluster's web console has it under ? > Command line tools) and start Kubedog again, or log in the way you usually do and press Refresh.");
            }
            if has(|o| matches!(o, Offer::InLinux(_))) {
                say(ui, "Kubedog works through your Linux in WSL: run the line there, then press Refresh.");
            }
            if has(|o| matches!(o, Offer::Unknown)) {
                say(ui, "Where there's no button: log in the way you usually do for that cluster, then press Refresh.");
            }
            ui.add_space(2.0);
            hide = button(ui, "Not now", false, false);
        });
        ui.add_space(6.0);
        if let Some((ctx, server)) = start {
            self.relogin_start(&ctx, &server);
        }
        if let Some(r) = stop.and_then(|c| self.relogin.running.get(&c)) {
            r.stop.store(true, Ordering::Relaxed);
        }
        if hide {
            self.relogin.hidden = offers.into_iter().map(|x| x.0).collect();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(cluster: &str, user: &str, server: &str) -> ContextInfo {
        ContextInfo { name: "shop".into(), cluster: cluster.into(), user: user.into(), namespace: String::new(), server: server.into(), source: String::new() }
    }

    #[test]
    fn a_login_that_ended() {
        assert!(logged_out("error: You must be logged in to the server (Unauthorized)"));
        assert!(logged_out("error: the server has asked for the client to provide credentials"));
        assert!(logged_out("error: Unauthorized"));
        // Not allowed isn't the same as not logged in, and neither is a cluster that doesn't answer.
        assert!(!logged_out("Error from server (Forbidden): pods is forbidden: User \"dev\" cannot list resource"));
        assert!(!logged_out("Unable to connect to the server: dial tcp 192.0.2.7:6443: i/o timeout"));
    }

    #[test]
    fn only_addresses_go_to_oc() {
        assert_eq!(server_ok("https://api.shop.example.com:6443").as_deref(), Some("https://api.shop.example.com:6443"));
        assert_eq!(server_ok("https://api.shop.example.com/").as_deref(), Some("https://api.shop.example.com"));
        assert_eq!(server_ok("https://192.0.2.7:6443").as_deref(), Some("https://192.0.2.7:6443"));
        for bad in ["", "http://api.shop.example.com:6443", "https://", "https://-x.example.com", "https://a b:6443", "https://api.example.com:6443/path", "https://api.example.com:6443?x=1", "https://user@api.example.com", "https://api.example.com:port", "https://api.example.com:6443 --insecure-skip-tls-verify", "https://[::1]:6443"] {
            assert_eq!(server_ok(bad), None, "{bad:?}");
        }
        assert_eq!(login_args("https://api.shop.example.com:6443"), ["login", "--web", "--server=https://api.shop.example.com:6443"]);
    }

    #[test]
    fn what_is_offered() {
        let oc = ctx("api-shop-example-com:6443", "dev/api-shop-example-com:6443", "https://api.shop.example.com:6443");
        assert!(oc_made(&oc));
        assert_eq!(offer(&oc, false, true), Offer::Web("https://api.shop.example.com:6443".into()));
        assert_eq!(offer(&oc, false, false), Offer::NoOc);
        assert_eq!(offer(&oc, true, true), Offer::InLinux("oc login --web --server=https://api.shop.example.com:6443".into()));
        // Another kind of login, or an address that isn't plain: no guess is made.
        let other = ctx("shop", "shop-admin", "https://192.0.2.7:6443");
        assert!(!oc_made(&other) && !oc_made(&ctx("", "/", "")) && !oc_made(&ctx("c", "/c", "")) && !oc_made(&ctx("c", "c", "")));
        assert_eq!(offer(&other, false, true), Offer::Unknown);
        assert_eq!(offer(&ctx("c:6443", "dev/c:6443", "http://c:6443"), false, true), Offer::Unknown);
    }

    #[test]
    fn the_newest_answer_decides() {
        let out = Some("error: You must be logged in to the server (Unauthorized)".to_string());
        // Refused first, fine later (logged in somewhere else, then Refresh): no notice.
        assert!(!newest_says_out([(1, out.clone()), (2, None)].into_iter()));
        assert!(newest_says_out([(2, out.clone()), (1, None)].into_iter()));
        assert!(newest_says_out([(1, out.clone())].into_iter()));
        // Nothing read yet, or another kind of error last.
        assert!(!newest_says_out(Vec::<(i32, Option<String>)>::new().into_iter()));
        assert!(!newest_says_out([(1, out), (2, Some("Unable to connect to the server".into()))].into_iter()));
        assert_eq!(check_args("shop"), ["--context", "shop", "auth", "can-i", "get", "pods", "--request-timeout=15s"]);
    }

    #[test]
    fn why_it_failed() {
        assert_eq!(why("Opening login URL\nerror: x509: certificate signed by unknown authority\n\n"), "x509: certificate signed by unknown authority");
        assert_eq!(why(""), "oc gave no reason");
        assert!(why("error: unknown flag: --web\nSee 'oc login --help' for usage.").starts_with("This oc is too old"));
    }
}
