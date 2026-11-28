//! Is there a newer Kubedog? Asked once a day from GitHub's public list of releases; nothing is installed by itself.
use super::*;
use std::sync::{Arc, Mutex};

/// The one address that is asked. Nothing about this computer, its clusters or the version in use goes along.
const LATEST: &str = "https://api.github.com/repos/pezzking/kubedog/releases/latest";
/// Where the downloads are, opened in the browser on a click.
const PAGE: &str = "https://github.com/pezzking/kubedog/releases/latest";
const DAY: i64 = 24 * 3600;
/// After this many tries in a row without an answer (a day apart), Kubedog stops asking by itself.
const GIVE_UP: u32 = 3;
/// A file with this name next to the program (the Windows installer can put it there) makes Kubedog air-gapped.
const MARK: &str = "airgapped";

#[derive(Default)]
pub(super) struct Update {
    /// The answer of the request that runs, when it's there.
    /// An error says what went wrong, and whether GitHub was reached at all.
    got: Arc<Mutex<Option<Result<String, (String, bool)>>>>,
    asking: bool,
    /// The request that runs was asked for with a click.
    by_hand: bool,
    /// Air-gapped by how Kubedog was installed or started; looked at once, at the first use.
    forced: Option<bool>,
    /// What the last try by hand said, for Settings.
    said: Option<(String, bool)>,
    /// Homebrew updating Kubedog, after a click.
    brew: Option<Brew>,
}

/// One run of Homebrew: what it says while it works, and how it ended.
struct Brew {
    out: Arc<Mutex<String>>,
    done: Arc<Mutex<Option<bool>>>,
}

/// How far Homebrew is.
#[derive(Clone, Copy, PartialEq, Debug)]
enum BrewState {
    No,
    Running,
    Done,
    Failed,
}

/// What Homebrew is asked to do, one after the other: read its lists again (a version from today isn't in them
/// yet), then update Kubedog and nothing else. Fixed words only; `line` is one of the two lines `how` gives.
pub(super) fn brew_steps(line: &str) -> Vec<Vec<String>> {
    let upgrade: Vec<String> = line.split_whitespace().skip(1).map(String::from).collect();
    vec![vec!["update".into()], upgrade]
}

/// The end of a long text, from the start of a line.
pub(super) fn tail(text: &str, lines: usize) -> String {
    let l: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    l[l.len().saturating_sub(lines)..].join("\n")
}

/// The app to start again: the `.app` this program is in, if it is in one.
pub(super) fn app_bundle(exe: &str) -> Option<&str> {
    let i = exe.find("/Kubedog.app/")?;
    Some(&exe[..i + "/Kubedog.app".len()])
}

/// How this Kubedog got here, which decides what "update" means.
#[derive(Debug, PartialEq)]
pub(super) enum How {
    /// Homebrew keeps it: the line to run.
    Brew(&'static str),
    /// A download: the page with the installer or the archive.
    Page,
}

/// "0.7.2" or "v0.7.2" as numbers. Anything else isn't a version.
fn parts(v: &str) -> Option<Vec<u32>> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let p: Vec<u32> = v.split('.').map(|x| if x.is_empty() || x.len() > 6 || !x.bytes().all(|b| b.is_ascii_digit()) { None } else { x.parse().ok() }).collect::<Option<_>>()?;
    (p.len() == 3).then_some(p)
}

/// Whether `latest` is a later version than `mine`.
pub(super) fn newer(latest: &str, mine: &str) -> bool {
    matches!((parts(latest), parts(mine)), (Some(l), Some(m)) if l > m)
}

/// The version GitHub names as the newest release: only a plain number is taken from the answer.
pub(super) fn latest_in(answer: &Value) -> Option<String> {
    if answer["draft"].as_bool() == Some(true) || answer["prerelease"].as_bool() == Some(true) {
        return None;
    }
    let p = parts(answer["tag_name"].as_str()?)?;
    Some(format!("{}.{}.{}", p[0], p[1], p[2]))
}

/// A day since the last answer and since the last try, answered or not (or a clock that went back).
pub(super) fn due(now: i64, last: i64, tried: i64) -> bool {
    (last <= 0 || now < last || now - last >= DAY) && (tried <= 0 || now < tried || now - tried >= DAY)
}

/// Whether the installation says air-gapped: `KUBEDOG_AIRGAPPED` set to something that isn't "no", or the file.
pub(super) fn forced_by(env: Option<&str>, file: bool) -> bool {
    match env.map(|e| e.trim().to_ascii_lowercase()) {
        Some(e) if !e.is_empty() => !matches!(e.as_str(), "0" | "no" | "false" | "off"),
        _ => file,
    }
}

/// After a try by itself: the tries without an answer in a row, and whether that is enough to stop asking.
pub(super) fn after_try(answered: bool, fails: u32) -> (u32, bool) {
    if answered {
        return (0, false);
    }
    let n = fails.saturating_add(1);
    (n, n >= GIVE_UP)
}

/// From where the program is: Homebrew's folders mean Homebrew updates it. The Mac app sits in Applications either
/// way, so for that one `cask` says whether Homebrew has a record of it.
pub(super) fn how(exe: &str, cask: bool) -> How {
    let p = exe.replace('\\', "/");
    if p.contains("/Caskroom/") || (p.contains("/Kubedog.app/") && cask) {
        How::Brew("brew upgrade --cask kubedog-app")
    } else if p.contains("/Cellar/") || p.contains("/homebrew/") || p.contains("/linuxbrew/") {
        How::Brew("brew upgrade kubedog")
    } else {
        How::Page
    }
}

/// A proxy named in the environment (HTTPS_PROXY) is used, as a browser would: GitHub is outside, unlike what the
/// other requests of Kubedog talk to.
fn ask() -> Result<String, (String, bool)> {
    let agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(8)))
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent("Kubedog")
        .tls_config(ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build())
        .build()
        .new_agent();
    let mut resp = agent.get(LATEST).header("Accept", "application/vnd.github+json").call().map_err(|_| ("GitHub can't be reached from this computer.".to_string(), false))?;
    if resp.status().as_u16() != 200 {
        return Err((format!("GitHub answered {}.", resp.status().as_u16()), true));
    }
    let text = resp.body_mut().with_config().limit(1024 * 1024).read_to_string().map_err(|_| ("GitHub's answer couldn't be read.".to_string(), true))?;
    serde_json::from_str::<Value>(&text).ok().as_ref().and_then(latest_in).ok_or_else(|| ("GitHub's answer names no version.".to_string(), true))
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl KubedogApp {
    /// The newer version to tell about, if one is known.
    pub(super) fn update_there(&self) -> Option<String> {
        if self.screenshot.is_some() {
            return std::env::var("KUBEDOG_SHOT_UPDATE").ok().filter(|v| newer(v, env!("CARGO_PKG_VERSION")));
        }
        Some(self.prefs.update_latest.clone()).filter(|v| self.prefs.update_check && newer(v, env!("CARGO_PKG_VERSION")))
    }

    /// Air-gapped by the installation (not by the switch in Settings).
    fn airgap_forced(&mut self) -> bool {
        if self.screenshot.is_some() {
            return std::env::var("KUBEDOG_SHOT_AIRGAPPED").as_deref() == Ok("forced");
        }
        *self.update.forced.get_or_insert_with(|| {
            let file = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join(MARK).exists())).unwrap_or(false);
            forced_by(std::env::var("KUBEDOG_AIRGAPPED").ok().as_deref(), file)
        })
    }

    /// Kubedog itself asks the internet for nothing.
    pub(super) fn airgapped(&mut self) -> bool {
        self.airgap_forced() || self.prefs.airgapped
    }

    /// For Settings: by the installation, switched on, and switched on by itself. A screenshot can make it up.
    fn airgap_state(&mut self) -> (bool, bool, bool) {
        let forced = self.airgap_forced();
        if self.screenshot.is_some() {
            let v = std::env::var("KUBEDOG_SHOT_AIRGAPPED").unwrap_or_default();
            return (forced, forced || v == "on" || v == "auto", v == "auto");
        }
        (forced, forced || self.prefs.airgapped, self.prefs.airgapped && self.prefs.airgapped_auto)
    }

    /// Every frame: takes an answer that came, and asks when a day has passed. Never in a screenshot.
    pub(super) fn update_tick(&mut self) {
        if self.screenshot.is_some() {
            return;
        }
        if self.update.asking {
            let Some(got) = self.update.got.lock().ok().and_then(|mut g| g.take()) else { return };
            self.update.asking = false;
            let by_hand = std::mem::take(&mut self.update.by_hand);
            self.update.said = None;
            match got {
                Ok(v) => {
                    self.prefs.update_latest = v.clone();
                    self.prefs.update_last = now();
                    self.prefs.update_fails = 0;
                    // GitHub answers, so this computer isn't cut off after all.
                    if self.prefs.airgapped_auto {
                        self.prefs.airgapped = false;
                        self.prefs.airgapped_auto = false;
                    }
                    self.save();
                    if by_hand {
                        self.update.said = Some(if newer(&v, env!("CARGO_PKG_VERSION")) { (format!("Kubedog {v} is available."), false) } else { ("You have the newest version.".into(), false) });
                    }
                }
                // Not said unless it was asked by hand: no internet is normal in many places.
                // GitHub was reached but gave nothing to use (too many requests from this address, say): there
                // is internet, so this doesn't count towards stopping.
                Err((e, true)) => {
                    self.prefs.update_fails = 0;
                    if self.prefs.airgapped_auto {
                        self.prefs.airgapped = false;
                        self.prefs.airgapped_auto = false;
                    }
                    self.save();
                    if by_hand {
                        self.update.said = Some((e, true));
                    }
                }
                Err((e, false)) if by_hand => self.update.said = Some((e, true)),
                Err(_) => {
                    let (fails, stop) = after_try(false, self.prefs.update_fails);
                    self.prefs.update_fails = fails;
                    if stop && !self.prefs.airgapped {
                        self.prefs.airgapped = true;
                        self.prefs.airgapped_auto = true;
                    }
                    self.save();
                }
            }
            return;
        }
        if self.prefs.update_check && due(now(), self.prefs.update_last, self.prefs.update_tried) && !self.airgapped() {
            self.update_ask(false);
        }
    }

    fn update_ask(&mut self, by_hand: bool) {
        if self.screenshot.is_some() || self.update.asking {
            return;
        }
        // By hand is only offered where the person may: never when the installation says air-gapped.
        if self.airgap_forced() {
            return;
        }
        self.update.asking = true;
        self.update.by_hand = by_hand;
        if !by_hand {
            self.prefs.update_tried = now();
            self.save();
        }
        self.update.said = by_hand.then(|| (String::new(), false));
        let (got, ctx) = (self.update.got.clone(), self.egui_ctx.clone());
        std::thread::spawn(move || {
            let a = ask();
            if let Ok(mut g) = got.lock() {
                *g = Some(a);
            }
            ctx.request_repaint();
        });
    }

    /// The top bar: a few words when there is a newer version; a click leads to Settings > About.
    pub(super) fn update_top(&mut self, ui: &mut Ui) {
        let Some(v) = self.update_there().filter(|v| *v != self.prefs.update_skip) else { return };
        // Only where the bar has room for it: Settings > About says it too.
        if ui.available_width() < z(130.0) + u(96.0) {
            return;
        }
        let b = ui.add(egui::Button::new(RichText::new(format!("{v} is available")).size(z(12.5)).color(PRIMARY())).frame(false)).on_hover_text(format!("Kubedog {v} is out; you have {}. Click for how to update.", env!("CARGO_PKG_VERSION")));
        if b.clicked() {
            self.settings_section = "About";
            if self.view != View::Settings {
                self.navigate(View::Settings, None);
            }
        }
    }

    fn brew_state(&self) -> BrewState {
        if self.screenshot.is_some() {
            return match std::env::var("KUBEDOG_SHOT_BREW").as_deref() {
                Ok("running") => BrewState::Running,
                Ok("done") => BrewState::Done,
                Ok("failed") => BrewState::Failed,
                _ => BrewState::No,
            };
        }
        match self.update.brew.as_ref().map(|b| b.done.lock().ok().and_then(|d| *d)) {
            None => BrewState::No,
            Some(None) => BrewState::Running,
            Some(Some(true)) => BrewState::Done,
            Some(Some(false)) => BrewState::Failed,
        }
    }

    /// Starts Homebrew, after a click. Never in a screenshot.
    fn brew_start(&mut self, line: &'static str) {
        if self.screenshot.is_some() || self.brew_state() == BrewState::Running {
            return;
        }
        let run = Brew { out: Arc::new(Mutex::new(String::new())), done: Arc::new(Mutex::new(None)) };
        let (out, done, ctx) = (run.out.clone(), run.done.clone(), self.egui_ctx.clone());
        self.update.brew = Some(run);
        let say = |out: &Arc<Mutex<String>>, t: &str| {
            if let Ok(mut o) = out.lock() {
                o.push_str(t);
                o.push('\n');
                // Only the end is shown; a long run doesn't pile up.
                if o.len() > 40_000 {
                    let cut = o.char_indices().map(|x| x.0).find(|i| *i >= o.len() - 20_000).unwrap_or(0);
                    o.drain(..cut);
                }
            }
        };
        let Some(brew) = crate::kube::find_program("brew") else {
            say(&out, "Homebrew (brew) wasn't found on this computer.");
            if let Ok(mut d) = done.lock() {
                *d = Some(false);
            }
            return;
        };
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut ok = true;
            for args in brew_steps(line) {
                say(&out, &format!("brew {}", args.join(" ")));
                let mut c = std::process::Command::new(&brew);
                crate::kube::quiet(&mut c);
                c.args(&args).env("PATH", crate::kube::child_path()).env("HOMEBREW_NO_ENV_HINTS", "1").env("HOMEBREW_NO_COLOR", "1").env("NONINTERACTIVE", "1");
                c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
                let mut child = match c.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        say(&out, &format!("Homebrew couldn't be started: {e}"));
                        ok = false;
                        break;
                    }
                };
                let readers: Vec<_> = [child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)]
                    .into_iter()
                    .flatten()
                    .map(|s| {
                        let (out, ctx) = (out.clone(), ctx.clone());
                        std::thread::spawn(move || {
                            for l in std::io::BufReader::new(s).lines().map_while(Result::ok) {
                                if let Ok(mut o) = out.lock() {
                                    o.push_str(&l);
                                    o.push('\n');
                                }
                                ctx.request_repaint();
                            }
                        })
                    })
                    .collect();
                let status = child.wait();
                for r in readers {
                    let _ = r.join();
                }
                if !status.map(|s| s.success()).unwrap_or(false) {
                    ok = false;
                    break;
                }
            }
            if let Ok(mut d) = done.lock() {
                *d = Some(ok);
            }
            ctx.request_repaint();
        });
    }

    /// Starts Kubedog again (the newly installed one) and closes this one.
    fn restart(&mut self) {
        let exe = std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        let started = match app_bundle(&exe) {
            Some(app) => std::process::Command::new("/usr/bin/open").args(["-n", app]).spawn(),
            // Homebrew's own folder for the old version is gone; its link leads to the new one.
            None => std::process::Command::new(crate::kube::find_program("kubedog").unwrap_or_else(|| exe.clone().into())).spawn(),
        };
        match started {
            Ok(_) => self.egui_ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(e) => self.update.said = Some((format!("Kubedog couldn't be started again: {e}. Close it and open it yourself."), true)),
        }
    }

    /// Where Homebrew installed Kubedog: a button that lets Homebrew update it, and the line to do it by hand.
    fn settings_brew(&mut self, ui: &mut Ui, line: &'static str, airgapped: bool) {
        let state = self.brew_state();
        let by_hand = |ui: &mut Ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(line).monospace().size(z(13.0)).color(TEXT_DEFAULT()));
                if button(ui, "Copy", false, false) {
                    ui.ctx().copy_text(line.to_string());
                }
            });
        };
        match state {
            BrewState::No if airgapped => {
                settings::hint(ui, "Homebrew installed this Kubedog. Close Kubedog and run this in a terminal:");
                by_hand(ui);
            }
            BrewState::No => {
                settings::hint(ui, "Homebrew installed this Kubedog and can update it. It downloads the new version from GitHub and replaces this one; nothing else is updated. Kubedog keeps running meanwhile.");
                ui.add_space(4.0);
                if button(ui, "Update with Homebrew", true, false) {
                    self.brew_start(line);
                }
                ui.add_space(6.0);
                settings::hint(ui, "Or close Kubedog and run this in a terminal:");
                by_hand(ui);
            }
            BrewState::Running => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Homebrew is updating Kubedog. This can take a few minutes.").color(TEXT_DEFAULT()));
                });
            }
            BrewState::Done => {
                work::said(ui, "Homebrew is done. The new Kubedog runs after a restart.", SUCCESS());
                ui.add_space(6.0);
                if button(ui, "Restart Kubedog", true, false) {
                    self.restart();
                }
                if let Some((t, true)) = self.update.said.as_ref().filter(|s| !s.0.is_empty()) {
                    ui.add_space(6.0);
                    work::said(ui, t, WARNING());
                }
            }
            BrewState::Failed => {
                work::said(ui, "Homebrew didn't finish; nothing was changed by Kubedog. What it said is below. You can try again, or run the line in a terminal:", WARNING());
                ui.add_space(6.0);
                by_hand(ui);
                ui.add_space(4.0);
                if button(ui, "Try again", false, false) {
                    self.brew_start(line);
                }
            }
        }
        let said = if self.screenshot.is_some() && state != BrewState::No { "brew update\nAlready up-to-date.\nbrew upgrade --cask kubedog-app\n==> Upgrading 1 outdated package".to_string() } else { self.update.brew.as_ref().and_then(|b| b.out.lock().ok().map(|o| tail(&o, 8))).unwrap_or_default() };
        if !said.is_empty() {
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(said).monospace().size(z(11.5)).color(TEXT_MUTED())).wrap());
        }
    }

    /// Settings > About: the switch, what is known, and how to update.
    pub(super) fn settings_update(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        card(ui, |ui| {
            ui.label(RichText::new("Internet and updates").size(z(15.0)).strong().color(TEXT_DEFAULT()));
            ui.add_space(4.0);
            let (forced, mut gap, auto) = self.airgap_state();
            if ui.add_enabled(!forced, egui::Checkbox::new(&mut gap, "Air-gapped: Kubedog never asks the internet by itself")).changed() {
                self.prefs.airgapped = gap;
                self.prefs.airgapped_auto = false;
                // Switched off by hand: start counting again, and look soon.
                self.prefs.update_fails = 0;
                self.prefs.update_tried = 0;
                self.update.said = None;
                self.save();
            }
            if forced {
                settings::hint(ui, "Set by how Kubedog was installed: a file named airgapped next to the program, or KUBEDOG_AIRGAPPED. It can't be switched off here.");
            } else if auto {
                work::said(ui, "Switched on by itself: github.com couldn't be reached three times, a day apart. Reaching it switches this off again.", WARNING());
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if self.update.asking {
                        ui.spinner();
                    } else if button(ui, "Look now", false, false) {
                        self.update_ask(true);
                    }
                    ui.label(RichText::new("Asks github.com once, now.").color(TEXT_MUTED()));
                });
                if let Some((t, _)) = self.update.said.as_ref().filter(|s| !s.0.is_empty()) {
                    ui.add_space(6.0);
                    work::said(ui, t, WARNING());
                }
            } else {
                settings::hint(ui, "The only thing Kubedog asks the internet without a click is the look for a new version. What you set up yourself (AI, Grafana, Proxmox, Elasticsearch) still goes where you point it.");
            }
            ui.add_space(10.0);
            let mut on = self.prefs.update_check && !gap;
            if ui.add_enabled(!gap, egui::Checkbox::new(&mut on, "Look for a new version once a day")).changed() {
                self.prefs.update_check = on;
                self.prefs.update_fails = 0;
                self.update.said = None;
                self.save();
            }
            settings::hint(ui, "Kubedog asks github.com which version is the newest. Nothing about you, this computer or your clusters is sent, and nothing is installed by itself. After a look without an answer it waits a day; after three of those it stops and switches Air-gapped on.");
            ui.add_space(8.0);
            match self.update_there() {
                Some(v) => {
                    work::said(ui, &format!("Kubedog {v} is available. You have {}.", env!("CARGO_PKG_VERSION")), TEXT_DEFAULT());
                    ui.add_space(6.0);
                    let exe = std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                    let cask = ["/opt/homebrew/Caskroom/kubedog-app", "/usr/local/Caskroom/kubedog-app"].iter().any(|d| std::path::Path::new(d).is_dir());
                    let shot_brew = self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_BREW").is_ok();
                    match if shot_brew { How::Brew("brew upgrade --cask kubedog-app") } else { how(&exe, cask) } {
                        How::Brew(line) => self.settings_brew(ui, line, gap),
                        How::Page => {
                            settings::hint(ui, "The download page has the installer for Windows and the files for Linux and macOS. It opens in your browser.");
                            if button(ui, "Open the download page", true, false) {
                                ui.ctx().open_url(egui::OpenUrl::new_tab(PAGE));
                            }
                        }
                    }
                    ui.add_space(6.0);
                    if self.prefs.update_skip == v {
                        settings::hint(ui, "Not shown in the top bar for this version.");
                    } else if button(ui, "Don't remind me of this version", false, false) {
                        self.prefs.update_skip = v;
                        self.save();
                    }
                }
                None if self.prefs.update_check && !gap => {
                    ui.horizontal(|ui| {
                        if self.update.asking {
                            ui.spinner();
                        } else if button(ui, "Look now", false, false) {
                            self.update_ask(true);
                        }
                        let known = !self.prefs.update_latest.is_empty() && self.prefs.update_last > 0;
                        ui.label(RichText::new(if known { "No newer version was found at the last look." } else { "Not known yet: GitHub hasn't answered." }).color(TEXT_MUTED()));
                    });
                    if let Some((t, bad)) = self.update.said.as_ref().filter(|s| !s.0.is_empty()) {
                        ui.add_space(6.0);
                        work::said(ui, t, if *bad { WARNING() } else { SUCCESS() });
                    }
                }
                None => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_homebrew_is_asked() {
        assert_eq!(brew_steps("brew upgrade --cask kubedog-app"), [vec!["update".to_string()], vec!["upgrade".into(), "--cask".into(), "kubedog-app".into()]]);
        assert_eq!(brew_steps("brew upgrade kubedog")[1], ["upgrade", "kubedog"]);
        assert_eq!(tail("a\n\nb\nc\n", 2), "b\nc");
        assert_eq!(tail("", 3), "");
        assert_eq!(app_bundle("/Applications/Kubedog.app/Contents/MacOS/kubedog"), Some("/Applications/Kubedog.app"));
        assert_eq!(app_bundle("/opt/homebrew/Cellar/kubedog/0.9.0/bin/kubedog"), None);
    }

    #[test]
    fn which_version_is_newer() {
        assert!(newer("0.7.2", "0.7.1") && newer("v0.8.0", "0.7.9") && newer("0.10.0", "0.9.9") && newer("1.0.0", "0.99.99"));
        assert!(!newer("0.7.1", "0.7.1") && !newer("0.7.0", "0.7.1") && !newer("0.9.9", "0.10.0"));
        // What isn't a plain version is never "newer".
        for bad in ["", "v", "0.8", "0.8.0.1", "0.8.0-rc1", "0.8.x", "9999999.0.0", "0..1", " 0.8.0", "0.8.0\n", "../../x"] {
            assert!(!newer(bad, "0.7.1"), "{bad:?}");
        }
    }

    #[test]
    fn what_github_says() {
        assert_eq!(latest_in(&serde_json::json!({"tag_name": "v0.8.0", "draft": false, "prerelease": false})), Some("0.8.0".into()));
        assert_eq!(latest_in(&serde_json::json!({"tag_name": "0.8.0"})), Some("0.8.0".into()));
        assert_eq!(latest_in(&serde_json::json!({"tag_name": "v0.8.0", "prerelease": true})), None);
        assert_eq!(latest_in(&serde_json::json!({"tag_name": "v0.8.0", "draft": true})), None);
        assert_eq!(latest_in(&serde_json::json!({"tag_name": "<b>0.8.0</b>"})), None);
        assert_eq!(latest_in(&serde_json::json!({"message": "Not Found"})), None);
    }

    #[test]
    fn once_a_day() {
        let now = 1_000_000;
        assert!(due(now, 0, 0) && due(now, now - DAY, 0) && due(now, 2_000_000, 0));
        assert!(!due(now, now - DAY + 1, 0) && !due(now, now, 0));
        // After a try, answered or not: not again within the day, whatever the clock did in between.
        assert!(!due(now, 0, now - 10) && !due(now, 0, now - DAY + 1) && !due(now, now - 2 * DAY, now - 3600));
        assert!(due(now, 0, now - DAY) && due(now, 0, now + 50));
    }

    #[test]
    fn three_tries_without_an_answer_stop_it() {
        assert_eq!(after_try(false, 0), (1, false));
        assert_eq!(after_try(false, 1), (2, false));
        assert_eq!(after_try(false, 2), (3, true));
        assert_eq!(after_try(false, u32::MAX), (u32::MAX, true));
        assert_eq!(after_try(true, 2), (0, false));
    }

    #[test]
    fn air_gapped_by_the_installation() {
        assert!(forced_by(None, true) && !forced_by(None, false));
        assert!(forced_by(Some("1"), false) && forced_by(Some("yes"), false) && forced_by(Some(" TRUE "), false));
        // Said plainly in the environment, it goes before the file.
        assert!(!forced_by(Some("0"), true) && !forced_by(Some("off"), true) && !forced_by(Some("No"), true));
        assert!(forced_by(Some(""), true) && !forced_by(Some("  "), false));
    }

    #[test]
    fn how_to_update() {
        let app = "/Applications/Kubedog.app/Contents/MacOS/kubedog";
        assert_eq!(how(app, true), How::Brew("brew upgrade --cask kubedog-app"));
        // The same place, put there from the downloaded disk image.
        assert_eq!(how(app, false), How::Page);
        assert_eq!(how("/opt/homebrew/Cellar/kubedog/0.7.1/bin/kubedog", false), How::Brew("brew upgrade kubedog"));
        assert_eq!(how("/home/linuxbrew/.linuxbrew/bin/kubedog", false), How::Brew("brew upgrade kubedog"));
        assert_eq!(how("C:\\Program Files\\Kubedog\\kubedog.exe", true), How::Page);
        assert_eq!(how("/home/dev/bin/kubedog", false), How::Page);
    }
}
