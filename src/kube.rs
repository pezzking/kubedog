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
    /// On Windows: a Linux in WSL that kubectl, helm and the kubeconfig are taken from, instead of this computer.
    pub wsl: Option<Wsl>,
}

/// A Linux in Windows (WSL) the whole app works through: its own programs and its own kubeconfig.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Wsl {
    pub linux: String,
    /// Where that Linux looks for programs, as its own shell has it (without Windows' folders).
    pub path: String,
    /// Its kubeconfig files, as paths in that Linux.
    pub kubeconfig: Vec<String>,
    pub kubectl: String,
    /// Empty when it has none.
    pub helm: String,
    pub cnpg: String,
}

pub fn system32(program: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or("C:\\Windows".into())).join("System32").join(program)
}

/// Asked of the Linux once. Its path and kubeconfig come from the person's own shell there, so what their start-up
/// files set is seen; the programs are then looked for in plain sh, where no alias is in the way. Fixed text.
const WSL_ASK: &str = r#"s=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f7); [ -x "$s" ] || s=/bin/sh
e=$("$s" -lic 'printf "\nKD_HOME=%s\nKD_PATH=%s\nKD_KUBECONFIG=%s\n" "$HOME" "$PATH" "$KUBECONFIG"' 2>/dev/null)
printf '%s\n' "$e"
p=$(printf '%s\n' "$e" | sed -n 's/^KD_PATH=//p' | tail -1)
[ -n "$p" ] && PATH=$p
for t in kubectl helm kubectl-cnpg; do printf 'KD_%s=%s\n' "$t" "$(command -v "$t")"; done
"#;

impl Wsl {
    /// What starts a program in the Linux: wsl.exe and its first arguments. No shell reads them.
    pub fn start(&self, program: &str) -> (PathBuf, Vec<String>) {
        let mut a: Vec<String> = ["-d", &self.linux, "--exec", "env"].iter().map(|x| x.to_string()).collect();
        a.push(format!("PATH={}", self.path));
        a.push(format!("KUBECONFIG={}", self.kubeconfig.join(":")));
        a.push(program.to_string());
        (system32("wsl.exe"), a)
    }

    pub fn json(&self) -> Value {
        serde_json::json!({"linux": self.linux, "path": self.path, "kubeconfig": self.kubeconfig, "kubectl": self.kubectl, "helm": self.helm, "cnpg": self.cnpg})
    }

    pub fn from_json(v: &Value) -> Option<Wsl> {
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        let w = Wsl { linux: s("linux"), path: s("path"), kubeconfig: v["kubeconfig"].as_array().map(|l| l.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(), kubectl: s("kubectl"), helm: s("helm"), cnpg: s("cnpg") };
        (!w.linux.is_empty() && !w.kubectl.is_empty()).then_some(w)
    }

    /// From what the Linux answered.
    pub fn from_answer(linux: &str, text: &str) -> Result<Wsl, String> {
        let get = |key: &str| text.lines().filter_map(|l| l.trim_end_matches('\r').strip_prefix(key)).next_back().unwrap_or("").trim().to_string();
        let home = get("KD_HOME=");
        if home.is_empty() {
            return Err(format!("{linux} didn't answer: is it still there, and does it start?"));
        }
        let kubectl = get("KD_kubectl=");
        if kubectl.is_empty() {
            return Err(format!("kubectl isn't installed in {linux}. Install it there, or switch this off in Settings > Terminal."));
        }
        let own = get("KD_KUBECONFIG=");
        let kubeconfig: Vec<String> = if own.is_empty() { vec![format!("{}/.kube/config", home.trim_end_matches('/'))] } else { own.split(':').filter(|p| !p.is_empty()).map(String::from).collect() };
        Ok(Wsl { linux: linux.to_string(), path: wsl_path(&get("KD_PATH=")), kubeconfig, kubectl, helm: get("KD_helm="), cnpg: get("KD_kubectl-cnpg=") })
    }

    /// Ask the Linux where its things are. Takes a moment when it has to be started first.
    pub fn ask(linux: &str) -> Result<Wsl, String> {
        let mut c = Command::new(system32("wsl.exe"));
        c.args(["-d", linux, "--exec", "sh", "-c", WSL_ASK]).stdin(Stdio::null());
        quiet(&mut c);
        let o = c.output().map_err(|e| format!("WSL couldn't be started: {e}"))?;
        Wsl::from_answer(linux, &String::from_utf8_lossy(&o.stdout))
    }
}

/// The Linux's own folders for programs: Windows' folders (under /mnt) are left out, they aren't needed and make it long.
fn wsl_path(path: &str) -> String {
    let l: Vec<&str> = path.trim().split(':').filter(|p| !p.is_empty() && !p.starts_with("/mnt/")).collect();
    if l.is_empty() { "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into() } else { l.join(":") }
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
    // Last: what mise installed. Its programs are on the PATH only in a shell mise was switched on in, which an
    // app started from the Dock or the Start menu isn't.
    v.extend(mise_dirs());
    v
}

/// Where mise (a tool that installs tools) keeps what it installed.
pub fn mise_installs() -> PathBuf {
    let set = |k: &str| std::env::var_os(k).map(PathBuf::from).filter(|p| p.is_absolute());
    let h = home().unwrap_or_default();
    let usual = || if cfg!(windows) { set("LOCALAPPDATA").unwrap_or_else(|| h.join("AppData/Local")).join("mise") } else { h.join(".local/share/mise") };
    set("MISE_DATA_DIR").or_else(|| set("XDG_DATA_HOME").filter(|_| !cfg!(windows)).map(|p| p.join("mise"))).unwrap_or_else(usual).join("installs")
}

/// The folders with the programs mise installed, looked up once.
pub fn mise_dirs() -> Vec<PathBuf> {
    static DIRS: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
    DIRS.get_or_init(|| Some(mise_installs()).filter(|m| m.is_absolute()).map(|m| mise_dirs_in(&m)).unwrap_or_default()).clone()
}

/// A version as numbers, so 2.10 comes after 2.9.
fn version_key(name: &str) -> Vec<u64> {
    name.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).map(|x| x.parse().unwrap_or(u64::MAX)).collect()
}

/// Per tool in mise's folder: the version mise calls the latest (or the highest there is), and in it the folders
/// that hold programs. The programs themselves, not mise's stand-ins for them.
pub fn mise_dirs_in(installs: &std::path::Path) -> Vec<PathBuf> {
    let mut tools: Vec<PathBuf> = std::fs::read_dir(installs).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    tools.sort();
    let mut out = vec![];
    for tool in tools.into_iter().take(500) {
        let latest = tool.join("latest");
        let v = if latest.is_dir() {
            latest
        } else {
            let mut vs: Vec<PathBuf> = std::fs::read_dir(&tool).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
            vs.sort_by_key(|p| version_key(&p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()));
            let Some(v) = vs.pop() else { continue };
            v
        };
        out.extend(["bin", "node_modules/.bin"].iter().map(|d| v.join(d)).filter(|d| d.is_dir()));
        out.push(v);
    }
    out
}

/// mise's stand-in for a program: a link to mise itself, which needs mise's settings to find the real one.
pub fn mise_shim(p: &std::path::Path) -> bool {
    p.is_symlink() && std::fs::canonicalize(p).ok().and_then(|r| r.file_stem().map(|n| n == "mise")).unwrap_or(false)
}

/// Kubedog's own folder, where the Windows installer puts the programs it brings along.
fn own_dir() -> Option<PathBuf> {
    Some(std::env::current_exe().ok()?.parent()?.to_path_buf())
}

/// A program in Kubedog's own folder, next to Kubedog itself.
fn beside_kubedog(name: &str) -> Option<PathBuf> {
    Some(own_dir()?.join(if cfg!(windows) { format!("{name}.exe") } else { name.to_string() })).filter(|p| p.is_file())
}

pub fn find_program(name: &str) -> Option<PathBuf> {
    let file = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
    search_paths()
        .into_iter()
        .map(|d| d.join(&file))
        .find(|p| p.is_file() && !mise_shim(p))
}

/// PATH for child processes: a Finder-launched app gets a bare PATH, but
/// kubeconfig credential plugins (aws, gcloud, oc...) need the usual dirs.
pub fn child_path() -> String {
    // Kubedog's own folder last: kubectl finds a plugin that came with Kubedog (cnpg) there, and yours goes first.
    let parts: Vec<String> = search_paths()
        .into_iter()
        .chain(own_dir())
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
            .or_else(|| beside_kubedog("kubectl"))
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
            cnpg: find_program("kubectl-cnpg").or_else(|| beside_kubedog("kubectl-cnpg")),
            wsl: None,
        }
    }

    pub fn kubeconfig_label(&self) -> String {
        match &self.kubeconfig {
            Some(k) => k.clone(),
            None => "~/.kube/config".to_string(),
        }
    }

    pub fn command(&self, args: &[String]) -> Option<Command> {
        if let Some(w) = &self.wsl {
            return Some(Self::in_wsl(w, &w.kubectl, args));
        }
        let bin = self.bin.as_ref()?;
        let mut c = Command::new(bin);
        c.args(args);
        self.prepare(&mut c);
        Some(c)
    }

    /// A program of the Linux, with its own path and kubeconfig: nothing of this computer's is handed over.
    fn in_wsl(w: &Wsl, program: &str, args: &[String]) -> Command {
        let (p, first) = w.start(program);
        let mut c = Command::new(p);
        c.args(first).args(args);
        quiet(&mut c);
        c.stdin(Stdio::null());
        c
    }

    /// kubectl for a terminal, where Kubedog doesn't start it itself: the program and what goes before the arguments.
    pub fn program(&self) -> Option<(String, Vec<String>)> {
        match &self.wsl {
            Some(w) => {
                let (p, first) = w.start(&w.kubectl);
                Some((p.to_string_lossy().to_string(), first))
            }
            None => Some((self.bin.as_ref()?.to_string_lossy().to_string(), vec![])),
        }
    }

    /// Another program of this computer (OpenShift's oc), started with the same path and kubeconfig as kubectl.
    pub fn other(&self, program: &std::path::Path, args: &[String]) -> Command {
        let mut c = Command::new(program);
        c.args(args);
        self.prepare(&mut c);
        c
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
        let mut c = match (&self.wsl, &self.helm) {
            (Some(w), _) if w.helm.is_empty() => return Err(format!("helm isn't installed in {}", w.linux)),
            (Some(w), _) => Self::in_wsl(w, &w.helm, args),
            (None, None) => return Err("helm was not found on this computer".into()),
            (None, Some(bin)) => {
                let mut c = Command::new(bin);
                c.args(args);
                self.prepare(&mut c);
                c
            }
        };
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

#[cfg(test)]
mod wsl_tests {
    use super::*;

    #[test]
    fn a_linux_in_wsl() {
        let text = "Welcome\r\n\nKD_HOME=/home/dev\nKD_PATH=/home/dev/.local/bin:/usr/local/bin:/usr/bin:/mnt/c/Program Files/One:/mnt/c/Windows\nKD_KUBECONFIG=\nKD_kubectl=/usr/local/bin/kubectl\nKD_helm=\nKD_kubectl-cnpg=/home/dev/.local/bin/kubectl-cnpg\n";
        let w = Wsl::from_answer("Ubuntu", text).unwrap();
        assert_eq!(w.path, "/home/dev/.local/bin:/usr/local/bin:/usr/bin");
        assert_eq!(w.kubeconfig, ["/home/dev/.kube/config"]);
        assert_eq!((w.kubectl.as_str(), w.helm.as_str(), w.cnpg.as_str()), ("/usr/local/bin/kubectl", "", "/home/dev/.local/bin/kubectl-cnpg"));
        assert_eq!(Wsl::from_json(&w.json()), Some(w.clone()));
        // Its own KUBECONFIG, when its shell sets one.
        let own = Wsl::from_answer("Ubuntu", &text.replace("KD_KUBECONFIG=", "KD_KUBECONFIG=/work/one:/work/two")).unwrap();
        assert_eq!(own.kubeconfig, ["/work/one", "/work/two"]);
        // Nothing that could be mistaken for fine.
        assert!(Wsl::from_answer("Ubuntu", "").unwrap_err().contains("didn't answer"));
        assert!(Wsl::from_answer("Ubuntu", &text.replace("KD_kubectl=/usr/local/bin/kubectl", "KD_kubectl=")).unwrap_err().contains("isn't installed in Ubuntu"));

        // Every kubectl and helm goes into the Linux, each argument on its own, with the Linux's path and kubeconfig.
        let k = Kubectl { bin: None, kubeconfig: Some("C:\\Users\\dev\\.kube\\config".into()), helm: None, cnpg: None, wsl: Some(own) };
        let c = k.command(&["--context".into(), "shop".into(), "get".into(), "pods".into(), "-o".into(), "jsonpath={..name}{\"\\n\"}".into()]).unwrap();
        let args: Vec<String> = c.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(args, ["-d", "Ubuntu", "--exec", "env", "PATH=/home/dev/.local/bin:/usr/local/bin:/usr/bin", "KUBECONFIG=/work/one:/work/two", "/usr/local/bin/kubectl", "--context", "shop", "get", "pods", "-o", "jsonpath={..name}{\"\\n\"}"]);
        assert!(c.get_program().to_string_lossy().ends_with("wsl.exe"));
        // Nothing of Windows' own is handed over.
        assert!(c.get_envs().all(|(k, _)| k != "KUBECONFIG" && k != "PATH"));
        assert_eq!(k.program().unwrap().1.last().unwrap(), "/usr/local/bin/kubectl");
        assert!(k.run_helm(&["list".into()]).unwrap_err().contains("helm isn't installed in Ubuntu"));
        // The question itself is sound sh (here it has no WSL to ask, so it tells about this computer).
        #[cfg(unix)]
        {
            let o = Command::new("sh").args(["-c", WSL_ASK]).output().unwrap();
            let t = String::from_utf8_lossy(&o.stdout).to_string();
            assert!(t.contains("\nKD_HOME=/") && t.contains("\nKD_PATH=/") && t.contains("\nKD_kubectl=") && t.contains("\nKD_kubectl-cnpg="), "{t}");
        }
        // Without WSL: as it always was.
        let plain = Kubectl { bin: Some("/bin/echo".into()), kubeconfig: None, helm: None, cnpg: None, wsl: None };
        assert_eq!(plain.program().unwrap(), ("/bin/echo".to_string(), vec![]));
    }

    #[test]
    fn programs_mise_installed_are_found() {
        let i = std::env::temp_dir().join(format!("kubedog-mise-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&i);
        assert!(mise_dirs_in(&i).is_empty());
        for d in ["kubectl/1.9.0", "kubectl/1.10.0", "helm/3.1.0/bin", "helm/4.0.0/bin", "npm-made-up/1.0.0/node_modules/.bin", "empty"] {
            std::fs::create_dir_all(i.join(d)).unwrap();
        }
        std::fs::write(i.join("kubectl/.mise.backend.toml"), "").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("./3.1.0", i.join("helm/latest")).unwrap();
        let helm = if cfg!(unix) { "helm/latest" } else { "helm/4.0.0" };
        // The highest version by numbers (1.10 after 1.9), what mise calls the latest before that, and the folders
        // inside that hold programs.
        assert_eq!(mise_dirs_in(&i), [i.join(helm).join("bin"), i.join(helm), i.join("kubectl/1.10.0"), i.join("npm-made-up/1.0.0/node_modules/.bin"), i.join("npm-made-up/1.0.0")]);
        // mise's stand-in is a link to mise itself: not taken for the program.
        #[cfg(unix)]
        {
            std::fs::write(i.join("mise"), "").unwrap();
            std::fs::write(i.join("kubectl/1.10.0/kubectl"), "").unwrap();
            std::os::unix::fs::symlink(i.join("mise"), i.join("empty/kubectl")).unwrap();
            assert!(mise_shim(&i.join("empty/kubectl")) && !mise_shim(&i.join("kubectl/1.10.0/kubectl")) && !mise_shim(&i.join("none")) && !mise_shim(&i.join("mise")));
        }
        let _ = std::fs::remove_dir_all(&i);
    }
}
