//! Talking to clusters through the `kubectl` program, off the UI thread.
//!
//! Kubedog reads the same kubeconfig files kubectl uses. Lookup order:
//! KUBEDOGCONFIG, then KUBECONFIG, then ~/.kube/config.

use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Windows opens a black console window for every program a windowed app starts, unless told not to.
/// Does nothing on other systems.
pub fn quiet(c: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    let _ = c;
}

/// Request timeout passed to every read call.
pub const REQUEST_TIMEOUT: &str = "15s";

#[derive(Clone, Debug)]
pub struct Kubectl {
    pub bin: Option<PathBuf>,
    pub kubeconfig: Option<String>,
    pub helm: Option<PathBuf>,
    /// The CloudNativePG plugin (kubectl cnpg), if it's installed.
    pub cnpg: Option<PathBuf>,
}

/// The person's home folder (Windows has no HOME of its own).
pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

/// The home folder as text, for paths that are shown or typed.
pub fn home_text() -> Option<String> {
    home().map(|h| h.to_string_lossy().to_string())
}

/// Where Kubedog keeps its own files (settings, added kubeconfig files), the way each system expects.
pub fn data_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        home().map(|h| h.join("Library/Application Support/Kubedog"))
    } else if cfg!(windows) {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("Kubedog")).or_else(|| home().map(|h| h.join("AppData/Roaming/Kubedog")))
    } else {
        std::env::var_os("XDG_CONFIG_HOME").filter(|x| !x.is_empty()).map(|x| PathBuf::from(x).join("kubedog")).or_else(|| home().map(|h| h.join(".config/kubedog")))
    }
}

/// What separates the files in KUBECONFIG and the folders in PATH.
pub const LIST_SEP: char = if cfg!(windows) { ';' } else { ':' };

fn search_paths() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = if cfg!(windows) {
        vec![]
    } else {
        vec!["/opt/homebrew/bin".into(), "/usr/local/bin".into(), "/usr/bin".into()]
    };
    if let Some(h) = home() {
        v.push(h.join(".rd/bin"));
        v.push(h.join("bin"));
        v.push(h.join(".local/bin"));
    }
    if let Some(p) = std::env::var_os("PATH") {
        v.extend(std::env::split_paths(&p));
    }
    v
}

/// A kubectl in Kubedog's own folder, next to the program.
fn beside_kubedog() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    Some(dir.join(if cfg!(windows) { "kubectl.exe" } else { "kubectl" })).filter(|p| p.is_file())
}

pub fn find_program(name: &str) -> Option<PathBuf> {
    let file = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
    search_paths()
        .into_iter()
        .map(|d| d.join(&file))
        .find(|p| p.is_file())
}

/// PATH for child processes: a Finder-launched app gets a bare PATH, but
/// kubeconfig credential plugins (aws, gcloud, oc...) need the usual dirs.
pub fn child_path() -> String {
    let parts: Vec<String> = search_paths()
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    parts.join(&LIST_SEP.to_string())
}

impl Kubectl {
    pub fn detect() -> Self {
        let bin = std::env::var_os("KUBEDOG_KUBECTL")
            .map(PathBuf::from)
            .filter(|p| p.is_file())
            .or_else(|| find_program("kubectl"))
            // OpenShift's own program takes the same commands; closed-off networks often have only that one.
            .or_else(|| find_program("oc"))
            // The one that came with Kubedog (the Windows installer can bring it), when the computer has none.
            .or_else(beside_kubedog)
            // For trying what a computer without kubectl sees.
            .filter(|_| std::env::var_os("KUBEDOG_NO_KUBECTL").is_none());
        let kubeconfig = std::env::var("KUBEDOGCONFIG")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("KUBECONFIG").ok().filter(|s| !s.is_empty()));
        Kubectl {
            bin,
            kubeconfig,
            helm: find_program("helm"),
            cnpg: find_program("kubectl-cnpg"),
        }
    }

    pub fn kubeconfig_label(&self) -> String {
        match &self.kubeconfig {
            Some(k) => k.clone(),
            None => "~/.kube/config".to_string(),
        }
    }

    pub fn command(&self, args: &[String]) -> Option<Command> {
        let bin = self.bin.as_ref()?;
        let mut c = Command::new(bin);
        c.args(args);
        self.prepare(&mut c);
        Some(c)
    }

    fn prepare(&self, c: &mut Command) {
        quiet(c);
        c.env("PATH", child_path());
        if let Some(k) = &self.kubeconfig {
            c.env("KUBECONFIG", k);
        }
        c.stdin(Stdio::null());
    }

    /// Run kubectl and collect stdout. Errors carry stderr.
    pub fn run(&self, args: &[String]) -> Result<String, String> {
        let Some(mut c) = self.command(args) else {
            return Err("kubectl was not found on this computer".into());
        };
        let out = c.output().map_err(|e| format!("could not start kubectl: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Err(if err.is_empty() {
                format!("kubectl exited with {}", out.status)
            } else {
                err
            })
        }
    }

    /// Run kubectl, but no longer than this: `exec` has no time limit of its own.
    pub fn run_for(&self, args: &[String], most: Duration) -> Result<String, String> {
        use std::io::Read;
        let Some(mut c) = self.command(args) else {
            return Err("kubectl was not found on this computer".into());
        };
        let mut child = c.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("could not start kubectl: {e}"))?;
        let read = |r: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut b = vec![];
                if let Some(mut r) = r {
                    let _ = r.read_to_end(&mut b);
                }
                String::from_utf8_lossy(&b).to_string()
            })
        };
        let out = read(child.stdout.take().map(|x| Box::new(x) as Box<dyn Read + Send>));
        let err = read(child.stderr.take().map(|x| Box::new(x) as Box<dyn Read + Send>));
        let began = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if began.elapsed() > most => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("it took longer than {} seconds and was stopped", most.as_secs()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(40)),
                Err(e) => return Err(e.to_string()),
            }
        };
        let (out, err) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
        if status.success() {
            Ok(out)
        } else {
            let err = err.trim().to_string();
            Err(if err.is_empty() { format!("kubectl exited with {status}") } else { err })
        }
    }

    /// Run kubectl feeding `input` on stdin (kubectl apply -f -).
    pub fn run_with_input(&self, args: &[String], input: &str) -> Result<String, String> {
        use std::io::Write;
        let Some(mut c) = self.command(args) else {
            return Err("kubectl was not found on this computer".into());
        };
        c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("could not start kubectl: {e}"))?;
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(input.as_bytes());
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    pub fn run_helm(&self, args: &[String]) -> Result<String, String> {
        let Some(bin) = &self.helm else {
            return Err("helm was not found on this computer".into());
        };
        let mut c = Command::new(bin);
        c.args(args);
        self.prepare(&mut c);
        let out = c.output().map_err(|e| format!("could not start helm: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Start a long-running kubectl (logs -f, port-forward) and stream its
    /// output lines to `tx` tagged with `id`.
    pub fn spawn_stream(
        &self,
        args: &[String],
        id: u64,
        tx: Sender<Msg>,
        repaint: impl Fn() + Send + Clone + 'static,
    ) -> Result<Child, String> {
        let Some(mut c) = self.command(args) else {
            return Err("kubectl was not found on this computer".into());
        };
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("could not start kubectl: {e}"))?;
        if let Some(out) = child.stdout.take() {
            let tx = tx.clone();
            let rp = repaint.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(out).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(Msg::StreamLine { id, line, err: false }).is_err() {
                        break;
                    }
                    rp();
                }
                let _ = tx.send(Msg::StreamEnded { id });
                rp();
            });
        }
        if let Some(err) = child.stderr.take() {
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(Msg::StreamLine { id, line, err: true }).is_err() {
                        break;
                    }
                    repaint();
                }
            });
        }
        Ok(child)
    }
}

/// Messages from worker threads back to the UI.
pub enum Msg {
    /// A Grafana's answer (grafana::Answer) for a cluster, and what it was asked with.
    Grafana { ctx: String, binding: String, what: Box<dyn std::any::Any + Send> },
    Contexts(Result<(Vec<ContextInfo>, Option<String>), String>),
    List {
        key: String,
        result: Result<Vec<Value>, String>,
        /// The table rows, built on the worker thread so the window never waits for them.
        rows: Option<Box<dyn std::any::Any + Send>>,
    },
    Text {
        key: String,
        result: Result<String, String>,
    },
    ActionDone {
        what: String,
        result: Result<String, String>,
    },
    StreamLine {
        id: u64,
        line: String,
        err: bool,
    },
    StreamEnded {
        id: u64,
    },
}

#[derive(Clone, Debug)]
pub struct ContextInfo {
    pub name: String,
    pub cluster: String,
    pub user: String,
    pub namespace: String,
    pub server: String,
    /// The kubeconfig file this context was read from.
    pub source: String,
}

pub fn parse_contexts(json: &str) -> Result<(Vec<ContextInfo>, Option<String>), String> {
    let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let current = v["current-context"].as_str().map(|s| s.to_string());
    let clusters = v["clusters"].as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for c in v["contexts"].as_array().cloned().unwrap_or_default() {
        let name = c["name"].as_str().unwrap_or("").to_string();
        let cluster = c["context"]["cluster"].as_str().unwrap_or("").to_string();
        let server = clusters
            .iter()
            .find(|k| k["name"].as_str() == Some(cluster.as_str()))
            .and_then(|k| k["cluster"]["server"].as_str())
            .unwrap_or("")
            .to_string();
        out.push(ContextInfo {
            name,
            cluster,
            user: c["context"]["user"].as_str().unwrap_or("").to_string(),
            namespace: c["context"]["namespace"].as_str().unwrap_or("").to_string(),
            server,
            source: String::new(),
        });
    }
    Ok((out, current))
}

pub fn parse_items(json: &str) -> Result<Vec<Value>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("bad JSON from kubectl: {e}"))?;
    Ok(v["items"].as_array().cloned().unwrap_or_default())
}

// ---------- time helpers ----------

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

/// Parse an RFC 3339 UTC time like 2024-05-01T12:34:56Z into Unix seconds.
pub fn parse_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |a: usize, n: usize| -> Option<i64> { s.get(a..a + n)?.parse().ok() };
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (h, mi, se) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    // days from civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + se)
}

/// kubectl-style short age: 45s, 12m, 5h3m, 3d4h, 2y40d.
pub fn age(ts: &str) -> String {
    let Some(t) = parse_time(ts) else {
        return "-".into();
    };
    human_duration((now_secs() - t).max(0))
}

pub fn human_duration(s: i64) -> String {
    let (m, h, d) = (s / 60, s / 3600, s / 86400);
    if s < 120 {
        format!("{s}s")
    } else if m < 10 {
        format!("{}m{}s", m, s % 60)
    } else if h < 3 {
        format!("{m}m")
    } else if h < 8 {
        format!("{}h{}m", h, m % 60)
    } else if d < 2 {
        format!("{h}h")
    } else if d < 8 {
        format!("{}d{}h", d, h % 24)
    } else if d < 365 * 2 {
        format!("{d}d")
    } else {
        format!("{}y{}d", d / 365, d % 365)
    }
}

/// Seconds since a timestamp, for sorting by age.
pub fn age_secs(ts: &str) -> i64 {
    parse_time(ts).map(|t| now_secs() - t).unwrap_or(i64::MAX)
}
