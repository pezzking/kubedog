//! Is there a newer Kubedog? Asked once a day from GitHub's public list of releases; nothing is installed by itself.
use super::*;
use std::sync::{Arc, Mutex};

/// The one address that is asked. Nothing about this computer, its clusters or the version in use goes along.
const LATEST: &str = "https://api.github.com/repos/pezzking/kubedog/releases/latest";
/// Where the downloads are, opened in the browser on a click.
const PAGE: &str = "https://github.com/pezzking/kubedog/releases/latest";
const DAY: i64 = 24 * 3600;
/// After a try that got no answer, the next one waits this long.
const AGAIN: i64 = 3600;

#[derive(Default)]
pub(super) struct Update {
    /// The answer of the request that runs, when it's there.
    got: Arc<Mutex<Option<Result<String, String>>>>,
    asking: bool,
    /// When this run last tried (clock time), so a computer without internet isn't asked again and again.
    tried: i64,
    /// What the last try by hand said, for Settings.
    said: Option<(String, bool)>,
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

/// A day since the last answer (or a clock that went back), and an hour since the last try without one.
pub(super) fn due(now: i64, last: i64, tried: i64) -> bool {
    (last <= 0 || now < last || now - last >= DAY) && (tried <= 0 || now < tried || now - tried >= AGAIN)
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
fn ask() -> Result<String, String> {
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
    let mut resp = agent.get(LATEST).header("Accept", "application/vnd.github+json").call().map_err(|_| "GitHub can't be reached from this computer.".to_string())?;
    if resp.status().as_u16() != 200 {
        return Err(format!("GitHub answered {}.", resp.status().as_u16()));
    }
    let text = resp.body_mut().with_config().limit(1024 * 1024).read_to_string().map_err(|_| "GitHub's answer couldn't be read.".to_string())?;
    serde_json::from_str::<Value>(&text).ok().as_ref().and_then(latest_in).ok_or_else(|| "GitHub's answer names no version.".to_string())
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

    /// Every frame: takes an answer that came, and asks when a day has passed. Never in a screenshot.
    pub(super) fn update_tick(&mut self) {
        if self.screenshot.is_some() {
            return;
        }
        if self.update.asking {
            let Some(got) = self.update.got.lock().ok().and_then(|mut g| g.take()) else { return };
            self.update.asking = false;
            let by_hand = self.update.said.take().is_some();
            match got {
                Ok(v) => {
                    self.prefs.update_latest = v.clone();
                    self.prefs.update_last = now();
                    self.save();
                    if by_hand {
                        self.update.said = Some(if newer(&v, env!("CARGO_PKG_VERSION")) { (format!("Kubedog {v} is available."), false) } else { ("You have the newest version.".into(), false) });
                    }
                }
                // Not said unless it was asked by hand: no internet is normal in many places.
                Err(e) if by_hand => self.update.said = Some((e, true)),
                Err(_) => {}
            }
            return;
        }
        if self.prefs.update_check && due(now(), self.prefs.update_last, self.update.tried) {
            self.update_ask(false);
        }
    }

    fn update_ask(&mut self, by_hand: bool) {
        if self.screenshot.is_some() || self.update.asking {
            return;
        }
        self.update.asking = true;
        self.update.tried = now();
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

    /// Settings > About: the switch, what is known, and how to update.
    pub(super) fn settings_update(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        card(ui, |ui| {
            ui.label(RichText::new("Updates").size(z(15.0)).strong().color(TEXT_DEFAULT()));
            ui.add_space(4.0);
            let mut on = self.prefs.update_check;
            if ui.checkbox(&mut on, "Look for a new version once a day").changed() {
                self.prefs.update_check = on;
                self.update.said = None;
                self.save();
            }
            settings::hint(ui, "Kubedog asks github.com which version is the newest. Nothing about you, this computer or your clusters is sent, and nothing is installed by itself. Without internet nothing happens.");
            ui.add_space(8.0);
            match self.update_there() {
                Some(v) => {
                    work::said(ui, &format!("Kubedog {v} is available. You have {}.", env!("CARGO_PKG_VERSION")), TEXT_DEFAULT());
                    ui.add_space(6.0);
                    let exe = std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                    let cask = ["/opt/homebrew/Caskroom/kubedog-app", "/usr/local/Caskroom/kubedog-app"].iter().any(|d| std::path::Path::new(d).is_dir());
                    match how(&exe, cask) {
                        How::Brew(line) => {
                            settings::hint(ui, "Homebrew installed this Kubedog. Close Kubedog and run this in a terminal:");
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(line).monospace().size(z(13.0)).color(TEXT_DEFAULT()));
                                if button(ui, "Copy", false, false) {
                                    ui.ctx().copy_text(line.to_string());
                                }
                            });
                        }
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
                None if self.prefs.update_check => {
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
        // No answer at the last try: not again within the hour, whatever the clock did in between.
        assert!(!due(now, 0, now - 10) && !due(now, 0, now - AGAIN + 1));
        assert!(due(now, 0, now - AGAIN) && due(now, 0, now + 50));
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
