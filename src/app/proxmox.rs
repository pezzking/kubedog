//! Proxmox VE: hosts, virtual machines, containers and storage, and which Kubernetes node runs on which
//! host. Reading only: GET requests with an API token, no redirects, no proxies, and the server's
//! certificate is always checked. The token is kept in memory, and in the system's keychain when asked.

use super::face::{many, Face, Side};
use super::grafana::{explain, pem_ders};
use super::incident::{chip_button, tab_strip};
use super::pg::{label_at, panel, pill};
use super::work::{name_of, said};
use super::*;

/// Bytes in a few digits.
fn size(b: f64) -> String {
    let (n, unit) = [(1024f64.powi(4), "Ti"), (1024f64.powi(3), "Gi"), (1024f64.powi(2), "Mi")].into_iter().find(|x| b >= x.0).unwrap_or((1024.0, "Ki"));
    let x = b / n;
    if x >= 10.0 || (x - x.round()).abs() < 0.05 { format!("{x:.0} {unit}") } else { format!("{x:.1} {unit}") }
}

// ---------- settings ----------

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Conf {
    pub name: String,
    pub url: String,
    /// user@realm!name
    pub token: String,
    /// Certificate authorities (PEM) for this server only; empty: the system's.
    pub ca: String,
    /// The token's secret is in the system's keychain.
    pub keep: bool,
    /// Kubedog's shared certificate authorities are trusted for this server too.
    pub shared: bool,
}

impl Conf {
    pub fn json(&self) -> Value {
        serde_json::json!({"name": self.name, "url": self.url, "token": self.token, "ca": self.ca, "keep": self.keep, "shared": self.shared})
    }
    pub fn from_json(v: &Value) -> Conf {
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        Conf { name: s("name"), url: s("url"), token: s("token"), ca: s("ca"), keep: v["keep"].as_bool().unwrap_or(false), shared: v["shared"].as_bool().unwrap_or(false) }
    }
    pub fn label(&self) -> String {
        if !self.name.is_empty() {
            return self.name.clone();
        }
        self.url.split("://").nth(1).unwrap_or(&self.url).split(':').next().unwrap_or("").to_string()
    }
    fn complete(&self) -> bool {
        check_url(&self.url).is_ok() && check_token(&self.token).is_ok()
    }
    /// What a secret was typed for: it's forgotten when any of this changes, and never sent elsewhere.
    fn binding(&self) -> String {
        let d = ring::digest::digest(&ring::digest::SHA256, format!("{}\n{}\n{}{}", self.url, self.token, self.ca, if self.shared { "\nshared" } else { "" }).as_bytes());
        d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The address, tidied, with Proxmox's own port when none is given.
pub(super) fn check_url(s: &str) -> Result<String, String> {
    let u = super::grafana::check_url(s).map_err(|e| e.replace("Grafana's", "Proxmox's").replace("the password would", "the token would"))?;
    let uri: ureq::http::Uri = u.parse().map_err(|_| "That isn't a web address.".to_string())?;
    if uri.path().trim_matches('/') != "" {
        return Err("Enter only the server, like https://proxmox.example.com:8006".into());
    }
    let host = uri.host().unwrap_or("");
    Ok(format!("{}://{host}:{}", uri.scheme_str().unwrap_or("https"), uri.port_u16().unwrap_or(8006)))
}

fn check_token(s: &str) -> Result<(), String> {
    let ok = s.split_once('!').map(|(u, n)| u.contains('@') && !u.starts_with('@') && !u.ends_with('@') && !n.is_empty()).unwrap_or(false);
    if ok && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"@!-_.+".contains(&b)) { Ok(()) } else { Err("Write it like kubedog@pve!reader".into()) }
}

fn check_secret(s: &str) -> Result<(), String> {
    if !s.is_empty() && s.len() < 200 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') { Ok(()) } else { Err("That isn't a token's secret: letters, digits and dashes only.".into()) }
}

// ---------- asking ----------

struct Client {
    agent: ureq::Agent,
    url: String,
    auth: String,
    ca: bool,
}

impl Client {
    fn new(c: &Conf, secret: &str) -> Result<Client, String> {
        let url = check_url(&c.url)?;
        check_token(&c.token)?;
        check_secret(secret)?;
        let ca = super::grafana::trusted(&c.ca, c.shared);
        let roots = if ca.is_empty() {
            ureq::tls::RootCerts::PlatformVerifier
        } else {
            let ders = pem_ders(&ca).into_iter().collect::<Option<Vec<_>>>().filter(|d| !d.is_empty()).ok_or("The saved certificate can't be read.")?;
            let list: Vec<_> = ders.iter().map(|d| ureq::tls::Certificate::from_der(d).to_owned()).collect();
            ureq::tls::RootCerts::new_with_certs(&list)
        };
        let agent = ureq::Agent::config_builder()
            .https_only(url.starts_with("https://"))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(8)))
            .timeout_global(Some(Duration::from_secs(25)))
            .user_agent("Kubedog")
            .tls_config(ureq::tls::TlsConfig::builder().root_certs(roots).build())
            .build()
            .new_agent();
        Ok(Client { agent, url, auth: format!("PVEAPIToken={}={secret}", c.token), ca: !ca.is_empty() })
    }

    fn get(&self, path: &str) -> Result<Value, String> {
        let mut r = self.agent.get(format!("{}/api2/json{path}", self.url)).header("Authorization", &self.auth).header("Accept", "application/json").call().map_err(|e| explain(&e, self.ca).text().to_string())?;
        match r.status().as_u16() {
            200 => {}
            401 => return Err("Proxmox refused the token.".into()),
            403 => return Err("this token may not read it".into()),
            300..=399 => return Err("It sends requests somewhere else.".into()),
            c => return Err(format!("Proxmox answered {c}.")),
        }
        let t = r.body_mut().with_config().limit(24 * 1024 * 1024).read_to_string().map_err(|e| explain(&e, self.ca).text().to_string())?;
        let v: Value = serde_json::from_str(&t).map_err(|_| "What answers there isn't Proxmox.".to_string())?;
        v.get("data").cloned().ok_or("What answers there isn't Proxmox.".into())
    }
}

/// Everything the page shows; what the token may not read is named.
fn read_all(c: &Conf, secret: &str) -> Result<Value, String> {
    let k = Client::new(c, secret)?;
    let mut out = serde_json::json!({"version": k.get("/version")?, "gone": {}});
    for (key, path) in [("resources", "/cluster/resources"), ("status", "/cluster/status"), ("tasks", "/cluster/tasks"), ("ha", "/cluster/ha/status/current"), ("nobackup", "/cluster/backup-info/not-backed-up")] {
        match k.get(path) {
            Ok(v) => out[key] = v,
            // Without this there's nothing to show.
            Err(e) if key == "resources" => return Err(format!("The list of hosts and machines: {e}")),
            Err(e) => out["gone"][key] = Value::String(e),
        }
    }
    Ok(out)
}

/// One machine: its state, settings (a few, known ones), snapshots, addresses, history and tasks.
fn read_guest(c: &Conf, secret: &str, g: &Sel) -> Result<Value, String> {
    let good = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    if !good(&g.node) || !matches!(g.kind.as_str(), "qemu" | "lxc") {
        return Err("That isn't a machine.".into());
    }
    let k = Client::new(c, secret)?;
    let base = format!("/nodes/{}/{}/{}", g.node, g.kind, g.id);
    let mut out = serde_json::json!({"gone": {}});
    let mut ask = |key: &str, path: String| match k.get(&path) {
        Ok(v) => out[key] = v,
        Err(e) => out["gone"][key] = Value::String(e),
    };
    ask("status", format!("{base}/status/current"));
    ask("config", format!("{base}/config"));
    ask("snapshots", format!("{base}/snapshot"));
    ask("history", format!("{base}/rrddata?timeframe=day"));
    ask("tasks", format!("/nodes/{}/tasks?vmid={}&limit=20", g.node, g.id));
    if g.kind == "qemu" {
        ask("net", format!("{base}/agent/network-get-interfaces"));
    }
    out["config"] = known_settings(&out["config"]);
    Ok(out)
}

/// Settings worth showing. Passwords, keys and the like aren't taken over, whatever they're called.
fn known_settings(v: &Value) -> Value {
    let keep = ["cores", "sockets", "vcpus", "cpu", "cpulimit", "cpuunits", "memory", "balloon", "swap", "ostype", "bios", "machine", "boot", "onboot", "agent", "scsihw", "numa", "tags", "protection", "startup", "hotplug", "unprivileged", "features", "arch", "hostname", "searchdomain", "nameserver", "rootfs", "name", "description"];
    let disk = |k: &str| ["scsi", "virtio", "sata", "ide", "net", "mp", "efidisk", "tpmstate", "ipconfig", "unused", "hostpci"].iter().any(|p| k.strip_prefix(p).map(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false));
    Value::Object(v.as_object().into_iter().flatten().filter(|(k, _)| keep.contains(&k.as_str()) || disk(k)).map(|(k, x)| (k.clone(), x.clone())).collect())
}

// ---------- what's there ----------

#[derive(Clone, Debug, Default, PartialEq)]
struct Host {
    name: String,
    online: bool,
    cpu: f64,
    cores: f64,
    mem: f64,
    maxmem: f64,
    disk: f64,
    maxdisk: f64,
    up: i64,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Guest {
    id: i64,
    name: String,
    node: String,
    kind: String,
    status: String,
    template: bool,
    cpu: f64,
    cores: f64,
    mem: f64,
    maxmem: f64,
    maxdisk: f64,
    up: i64,
    tags: String,
    lock: String,
    ha: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Store {
    name: String,
    node: String,
    ok: bool,
    used: f64,
    size: f64,
    shared: bool,
    kind: String,
    content: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct World {
    hosts: Vec<Host>,
    guests: Vec<Guest>,
    stores: Vec<Store>,
}

impl World {
    fn read(v: &Value) -> World {
        let mut w = World::default();
        let f = |x: &Value| x.as_f64().unwrap_or(0.0);
        let s = |x: &Value| x.as_str().unwrap_or("").to_string();
        for r in v["resources"].as_array().into_iter().flatten() {
            match r["type"].as_str().unwrap_or("") {
                "node" => w.hosts.push(Host { name: s(&r["node"]), online: r["status"] == "online", cpu: f(&r["cpu"]), cores: f(&r["maxcpu"]), mem: f(&r["mem"]), maxmem: f(&r["maxmem"]), disk: f(&r["disk"]), maxdisk: f(&r["maxdisk"]), up: f(&r["uptime"]) as i64 }),
                k @ ("qemu" | "lxc") => w.guests.push(Guest { id: r["vmid"].as_i64().unwrap_or(0), name: s(&r["name"]), node: s(&r["node"]), kind: k.into(), status: s(&r["status"]), template: r["template"].as_i64() == Some(1) || r["template"] == true, cpu: f(&r["cpu"]), cores: f(&r["maxcpu"]), mem: f(&r["mem"]), maxmem: f(&r["maxmem"]), maxdisk: f(&r["maxdisk"]), up: f(&r["uptime"]) as i64, tags: s(&r["tags"]), lock: s(&r["lock"]), ha: s(&r["hastate"]) }),
                "storage" => w.stores.push(Store { name: s(&r["storage"]), node: s(&r["node"]), ok: r["status"] == "available", used: f(&r["disk"]), size: f(&r["maxdisk"]), shared: r["shared"].as_i64() == Some(1), kind: s(&r["plugintype"]), content: s(&r["content"]) }),
                _ => {}
            }
        }
        w.hosts.sort_by(|a, b| a.name.cmp(&b.name));
        w.guests.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        w.stores.sort_by(|a, b| a.name.cmp(&b.name).then(a.node.cmp(&b.node)));
        // Shared storage is listed once per host.
        let mut seen = HashSet::new();
        w.stores.retain(|s| !s.shared || seen.insert(s.name.clone()));
        w
    }
}

/// A Kubernetes node: (cluster, name, providerID, control plane).
type KNode = (String, String, String, bool);

/// Which machine a Kubernetes node is: by its provider's id, else by its name when only one has it.
fn links(w: &World, nodes: &[KNode]) -> HashMap<i64, Vec<(KNode, bool)>> {
    let mut out: HashMap<i64, Vec<(KNode, bool)>> = HashMap::new();
    let short = |s: &str| s.to_lowercase().split('.').next().unwrap_or("").to_string();
    for n in nodes {
        let id = n.2.strip_prefix("proxmox://").and_then(|x| x.rsplit('/').next()).and_then(|x| x.parse::<i64>().ok());
        let by_id = id.filter(|i| w.guests.iter().any(|g| g.id == *i));
        let found = match by_id {
            Some(i) => Some((i, true)),
            // Another provider's id says it's somewhere else.
            None if !n.2.is_empty() && !n.2.starts_with("proxmox://") && ["aws", "gce", "azure", "openstack", "vsphere", "digitalocean", "hcloud", "ibm", "oci"].iter().any(|p| n.2.starts_with(&format!("{p}:"))) => None,
            None => {
                let m: Vec<&Guest> = w.guests.iter().filter(|g| !g.template && (g.name.eq_ignore_ascii_case(&n.1) || short(&g.name) == short(&n.1))).collect();
                match m.as_slice() {
                    [g] => Some((g.id, false)),
                    _ => None,
                }
            }
        };
        if let Some((i, sure)) = found {
            out.entry(i).or_default().push((n.clone(), sure));
        }
    }
    out
}

struct Finding {
    tone: Tone,
    what: String,
    more: String,
}

/// What isn't right, or could go wrong.
fn findings(v: &Value, w: &World, l: &HashMap<i64, Vec<(KNode, bool)>>, now: i64) -> Vec<Finding> {
    let mut out: Vec<Finding> = vec![];
    let mut add = |tone: Tone, what: String, more: String| out.push(Finding { tone, what, more });
    if let Some(c) = v["status"].as_array().into_iter().flatten().find(|x| x["type"] == "cluster") {
        if c["quorate"].as_i64() == Some(0) {
            add(Tone::Danger, "The cluster has no quorum".into(), "nothing can be started, moved or changed until enough hosts are back".into());
        }
    }
    for h in &w.hosts {
        if !h.online {
            add(Tone::Danger, format!("Host {} is offline", h.name), many(w.guests.iter().filter(|g| g.node == h.name && !g.template).count() as i64, "machine"));
            continue;
        }
        let part = |a: f64, b: f64| if b > 0.0 { a / b } else { 0.0 };
        if part(h.mem, h.maxmem) > 0.92 {
            add(Tone::Danger, format!("Host {} is nearly out of memory", h.name), format!("{} of {} used", size(h.mem), size(h.maxmem)));
        } else if part(h.mem, h.maxmem) > 0.85 {
            add(Tone::Warning, format!("Host {} uses much of its memory", h.name), format!("{} of {}", size(h.mem), size(h.maxmem)));
        }
        if h.cpu > 0.9 {
            add(Tone::Warning, format!("Host {} is busy", h.name), format!("{:.0}% of its CPU", h.cpu * 100.0));
        }
        if part(h.disk, h.maxdisk) > 0.85 {
            add(Tone::Warning, format!("Host {}'s own disk is filling up", h.name), format!("{:.0}%", part(h.disk, h.maxdisk) * 100.0));
        }
        let given: f64 = w.guests.iter().filter(|g| g.node == h.name && g.status == "running").map(|g| g.maxmem).sum();
        if h.maxmem > 0.0 && given > h.maxmem * 1.05 {
            add(Tone::Warning, format!("Host {} has promised more memory than it has", h.name), format!("{} to running machines, it has {}", size(given), size(h.maxmem)));
        }
    }
    // One host gone: would the others have room?
    let on: Vec<&Host> = w.hosts.iter().filter(|h| h.online).collect();
    if on.len() > 1 {
        for h in &on {
            let given: f64 = w.guests.iter().filter(|g| g.node == h.name && g.status == "running").map(|g| g.maxmem).sum();
            let free: f64 = on.iter().filter(|x| x.name != h.name).map(|x| (x.maxmem - x.mem).max(0.0)).sum();
            if given > free {
                add(Tone::Warning, format!("The others have no room for {}'s machines", h.name), format!("{} is needed, {} is free", size(given), size(free)));
            }
        }
    }
    for s in &w.stores {
        if !s.ok {
            add(Tone::Danger, format!("Storage {} isn't available", s.name), if s.shared { String::new() } else { format!("on {}", s.node) });
        } else if s.size > 0.0 && s.used / s.size > 0.85 {
            add(if s.used / s.size > 0.93 { Tone::Danger } else { Tone::Warning }, format!("Storage {} is {:.0}% full", s.name, s.used / s.size * 100.0), format!("{} of {}{}", size(s.used), size(s.size), if s.shared { String::new() } else { format!(", on {}", s.node) }));
        }
    }
    for h in v["ha"].as_array().into_iter().flatten().filter(|h| h["type"] == "service" && matches!(h["state"].as_str(), Some("error" | "fence" | "recovery"))) {
        add(Tone::Danger, format!("High availability: {} is in {}", h["sid"].as_str().unwrap_or(""), h["state"].as_str().unwrap_or("")), String::new());
    }
    for g in &w.guests {
        if let Some(k) = l.get(&g.id) {
            if g.status != "running" {
                add(Tone::Danger, format!("{} is {}", g.name, g.status), format!("{} Kubernetes node {}", if k.iter().all(|x| x.1) { "it's" } else { "by its name it's" }, k.iter().map(|x| x.0 .1.as_str()).collect::<Vec<_>>().join(", ")));
            }
        }
        if !g.lock.is_empty() {
            add(Tone::Warning, format!("{} is locked", g.name), g.lock.clone());
        }
    }
    // Control planes, and all nodes of a cluster, on one host.
    let mut by: std::collections::BTreeMap<String, Vec<(&KNode, &str)>> = Default::default();
    for g in &w.guests {
        for (n, _) in l.get(&g.id).into_iter().flatten() {
            by.entry(n.0.clone()).or_default().push((n, g.node.as_str()));
        }
    }
    for (ctx, v) in by {
        let mut cp: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        for (n, h) in v.iter().filter(|x| x.0 .3) {
            cp.entry(h).or_default().push(n.1.as_str());
        }
        let total: usize = cp.values().map(|x| x.len()).sum();
        for (h, names) in cp.iter().filter(|x| total >= 3 && x.1.len() * 2 > total) {
            add(Tone::Danger, format!("Most control plane nodes of {} are on host {h}", ctx_label(&ctx)), format!("{}: when that host goes, so does the cluster's control plane", names.join(", ")));
        }
        for (h, names) in cp.iter().filter(|x| x.1.len() > 1 && x.1.len() * 2 <= total) {
            add(Tone::Warning, format!("Control plane nodes of {} share host {h}", ctx_label(&ctx)), names.join(", "));
        }
        let hosts: HashSet<&str> = v.iter().map(|x| x.1).collect();
        if v.len() > 1 && hosts.len() == 1 && w.hosts.len() > 1 {
            add(Tone::Danger, format!("All nodes of {} are on one host", ctx_label(&ctx)), format!("{}, while there are {} hosts", hosts.into_iter().next().unwrap_or(""), w.hosts.len()));
        }
    }
    let bad: Vec<&Value> = v["tasks"].as_array().into_iter().flatten().filter(|t| failed(t) && now - t["starttime"].as_i64().unwrap_or(0) < 86400).collect();
    if !bad.is_empty() {
        add(Tone::Warning, format!("{} failed in the last day", many(bad.len() as i64, "task")), bad.iter().take(3).map(|t| format!("{} {}", task_word(t["type"].as_str().unwrap_or("")), t["id"].as_str().unwrap_or(""))).collect::<Vec<_>>().join(", "));
    }
    let nb = v["nobackup"].as_array().map(|a| a.len()).unwrap_or(0);
    if nb > 0 {
        let names = v["nobackup"].as_array().into_iter().flatten().filter_map(|x| x["name"].as_str()).map(String::from).collect::<Vec<_>>();
        add(Tone::Warning, format!("{} in no backup job", many(nb as i64, "machine")), some_names(&names));
    }
    out.sort_by_key(|f| f.tone != Tone::Danger);
    out
}

fn failed(t: &Value) -> bool {
    let s = t["status"].as_str().unwrap_or("");
    !t["endtime"].is_null() && !s.is_empty() && s != "OK" && !s.starts_with("WARNINGS")
}

fn task_word(t: &str) -> String {
    match t {
        "vzdump" => "Backup".into(),
        "qmstart" | "vzstart" => "Start".into(),
        "qmstop" | "vzstop" => "Stop".into(),
        "qmshutdown" | "vzshutdown" => "Shut down".into(),
        "qmreboot" | "vzreboot" => "Reboot".into(),
        "qmigrate" | "vzmigrate" => "Migrate".into(),
        "qmsnapshot" | "vzsnapshot" => "Snapshot".into(),
        "qmclone" | "vzclone" => "Clone".into(),
        "qmcreate" | "vzcreate" => "Create".into(),
        "qmdestroy" | "vzdestroy" => "Remove".into(),
        "aptupdate" => "Update package lists".into(),
        "imgcopy" | "download" => "Copy an image".into(),
        "startall" => "Start all".into(),
        "stopall" => "Stop all".into(),
        "vncproxy" | "spiceproxy" | "vncshell" => "Console".into(),
        x => x.to_string(),
    }
}

// ---------- in the app ----------

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Sel {
    pub binding: String,
    pub node: String,
    pub kind: String,
    pub id: i64,
}

#[derive(Default)]
struct One {
    at: Option<Instant>,
    loading: bool,
    data: Option<Value>,
    fail: Option<String>,
}

#[derive(Default)]
pub(super) struct Proxmox {
    /// binding -> the token's secret. Memory only.
    secrets: HashMap<String, String>,
    asked_key: HashSet<String>,
    state: HashMap<String, One>,
    guest: HashMap<String, One>,
    pub sel: Option<Sel>,
    tab: usize,
    which: usize,
    bad_only: bool,
    /// Settings, under Superpowers: shown or not.
    pub setup: bool,
    edit: Vec<Conf>,
    typed: HashMap<usize, String>,
    ca: HashMap<usize, super::grafana::Conf>,
    confirm: Option<usize>,
}

const TABS: [&str; 5] = ["Overview", "Machines", "Storage", "Tasks", "Kubernetes"];

fn keychain(binding: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new("kubedog", &format!("proxmox-{}", &binding[..24])).map_err(|e| format!("The system's keychain: {e}"))
}

impl KubedogApp {
    /// Set up, or a cluster that says it runs on Proxmox.
    pub(super) fn has_proxmox(&self) -> bool {
        self.prefs.proxmox.iter().any(|c| c.complete())
            || self.crds.iter().any(|k| k.key.starts_with("proxmoxclusters.infrastructure.cluster"))
            || self.active.iter().any(|c| {
                self.refs(c, Kind::Nodes, "").unwrap_or_default().iter().any(|n| n["spec"]["providerID"].as_str().unwrap_or("").starts_with("proxmox://"))
                    || self.refs(c, Kind::StorageClasses, "").unwrap_or_default().iter().any(|s| s["provisioner"].as_str().unwrap_or("").contains("proxmox"))
            })
    }

    fn pve_conf(&self) -> Option<Conf> {
        let l: Vec<&Conf> = self.prefs.proxmox.iter().filter(|c| c.complete()).collect();
        l.get(self.proxmox.which.min(l.len().saturating_sub(1))).map(|c| (*c).clone())
    }

    /// Reads while its page is open. Never in a screenshot.
    pub(super) fn refresh_proxmox(&mut self, force: bool) {
        if self.view != View::Proxmox || self.screenshot.is_some() || self.demo || self.power_off("proxmox") {
            return;
        }
        let Some(c) = self.pve_conf() else { return };
        let b = c.binding();
        let Some(secret) = self.proxmox.secrets.get(&b).cloned() else {
            // From the keychain, once; in a thread, for the system may ask the person.
            if c.keep && self.proxmox.asked_key.insert(b.clone()) {
                self.spawn(move |_| Msg::Text { key: format!("pve|key|{b}"), result: keychain(&b).and_then(|e| e.get_password().map_err(|e| format!("The keychain: {e}"))) });
            }
            return;
        };
        let every = Duration::from_secs(20);
        self.pve_read(&c, force);
        if let Some(sel) = self.proxmox.sel.clone().filter(|s| s.binding == b) {
            let k = format!("{sel:?}");
            let g = self.proxmox.guest.entry(k.clone()).or_default();
            if !g.loading && (force || g.at.map(|t| t.elapsed() >= every).unwrap_or(true)) {
                g.loading = true;
                g.at = Some(Instant::now());
                self.spawn(move |_| Msg::Text { key: format!("pve|one|{k}"), result: read_guest(&c, &secret, &sel).map(|v| v.to_string()) });
            }
        }
    }

    /// Reads one Proxmox, when it's time or asked for.
    fn pve_read(&mut self, c: &Conf, force: bool) {
        let b = c.binding();
        let Some(secret) = self.proxmox.secrets.get(&b).cloned().filter(|_| self.screenshot.is_none() && !self.demo) else { return };
        let s = self.proxmox.state.entry(b.clone()).or_default();
        // A refused token isn't tried again by itself.
        let tried = s.fail.as_deref().map(|f| f.contains("refused")).unwrap_or(false) && !force;
        if !s.loading && !tried && (force || s.at.map(|t| t.elapsed() >= Duration::from_secs(20)).unwrap_or(true)) {
            s.loading = true;
            s.at = Some(Instant::now());
            let c = c.clone();
            self.spawn(move |_| Msg::Text { key: format!("pve|all|{b}"), result: read_all(&c, &secret).map(|v| v.to_string()) });
        }
    }

    pub(super) fn on_proxmox(&mut self, key: &str, result: &Result<String, String>) -> bool {
        let Some(k) = key.strip_prefix("pve|") else { return false };
        let (what, id) = k.split_once('|').unwrap_or((k, ""));
        match what {
            "key" => match result {
                Ok(t) => {
                    // Only while it's still the one that's set up.
                    if self.prefs.proxmox.iter().any(|c| c.binding() == id) {
                        self.proxmox.secrets.insert(id.to_string(), t.clone());
                    }
                    self.refresh_proxmox(true);
                }
                Err(e) => self.proxmox.state.entry(id.to_string()).or_default().fail = Some(e.clone()),
            },
            "all" | "one" => {
                let map = if what == "all" { &mut self.proxmox.state } else { &mut self.proxmox.guest };
                let Some(s) = map.get_mut(id) else { return true };
                s.loading = false;
                match result.as_ref().map_err(|e| e.clone()).and_then(|t| serde_json::from_str(t).map_err(|e| e.to_string())) {
                    Ok(v) => {
                        s.data = Some(v);
                        s.fail = None;
                    }
                    Err(e) => s.fail = Some(e),
                }
            }
            _ => {}
        }
        true
    }

    fn pve_forget(&mut self, b: &str) {
        self.proxmox.secrets.remove(b);
        self.proxmox.state.remove(b);
        self.proxmox.asked_key.remove(b);
        if self.proxmox.sel.as_ref().map(|s| s.binding == b).unwrap_or(false) {
            self.proxmox.sel = None;
        }
    }

    /// Kubernetes nodes of the shown clusters.
    fn pve_nodes(&self) -> Vec<KNode> {
        let mut v = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for n in self.refs(c, Kind::Nodes, "").unwrap_or_default() {
                let l = &n["metadata"]["labels"];
                let cp = ["node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master"].iter().any(|k| !l[*k].is_null());
                v.push((c.clone(), name_of(n).to_string(), if self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_PROXMOX").is_ok() { String::new() } else { n["spec"]["providerID"].as_str().unwrap_or("").to_string() }, cp));
            }
        }
        v
    }

    pub(super) fn proxmox_view(&mut self, ui: &mut Ui) {
        // For pictures: made-up answers from a file, nothing is asked.
        if self.screenshot.is_some() {
            if let Some(v) = std::env::var("KUBEDOG_SHOT_PROXMOX").ok().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
                let c = Conf { name: "made-up".into(), url: "https://proxmox.example.com:8006".into(), token: "a@pve!b".into(), ..Default::default() };
                if self.prefs.proxmox.is_empty() {
                    self.prefs.proxmox.push(c.clone());
                }
                let b = c.binding();
                self.proxmox.secrets.insert(b.clone(), "made-up".into());
                if let Some(t) = std::env::var("KUBEDOG_SHOT_TAB").ok().and_then(|t| t.parse::<usize>().ok()) {
                    self.proxmox.tab = t.min(TABS.len() - 1);
                }
                if let (Ok(id), None) = (std::env::var("KUBEDOG_SHOT_OBJ"), &self.proxmox.sel) {
                    if let Some(g) = World::read(&v["all"]).guests.into_iter().find(|g| g.name == id) {
                        let sel = Sel { binding: b.clone(), node: g.node, kind: g.kind, id: g.id };
                        self.proxmox.guest.insert(format!("{sel:?}"), One { data: Some(v["one"].clone()), ..Default::default() });
                        self.proxmox.sel = Some(sel);
                    }
                }
                self.proxmox.state.entry(b).or_default().data = Some(v["all"].clone());
            }
        }
        if self.power_off("proxmox") {
            self.header(ui, false, Some("Proxmox".into()), false);
            said(ui, "Proxmox is switched off in Settings > Superpowers.", TEXT_SUBTLE());
            return;
        }
        let confs: Vec<Conf> = self.prefs.proxmox.iter().filter(|c| c.complete()).cloned().collect();
        let Some(c) = self.pve_conf() else {
            self.header(ui, false, Some("Proxmox".into()), false);
            ui.add_space(20.0);
            card(ui, |ui| {
                panel(ui, "Proxmox isn't set up yet", "it takes an address and a token that may read");
                said(ui, "Kubedog then shows your hosts, machines and storage, which Kubernetes node runs where, and what goes when a host goes. It only reads.", TEXT_MUTED());
                ui.add_space(6.0);
                if button(ui, "Set it up", true, false) {
                    self.settings_section = "Superpowers";
                    self.proxmox.setup = true;
                    self.navigate(View::Settings, None);
                }
            });
            return;
        };
        let b = c.binding();
        let data = self.proxmox.state.get(&b).and_then(|s| s.data.clone());
        let world = data.as_ref().map(World::read).unwrap_or_default();
        let l = links(&world, &self.pve_nodes());
        if let (Some(sel), Some(_)) = (self.proxmox.sel.clone().filter(|s| s.binding == b), &data) {
            self.pve_guest_page(ui, &sel, &world, &l);
            return;
        }
        self.header(ui, true, Some("Proxmox".into()), true);
        if confs.len() > 1 {
            ui.horizontal_wrapped(|ui| {
                for (i, x) in confs.iter().enumerate() {
                    if chip_button(ui, &x.label(), i == self.proxmox.which.min(confs.len() - 1)) {
                        self.proxmox.which = i;
                        self.proxmox.sel = None;
                    }
                }
            });
            ui.add_space(4.0);
        }
        if !self.proxmox.secrets.contains_key(&b) {
            self.pve_login(ui, &c);
            return;
        }
        let mut tab = self.proxmox.tab;
        ui.horizontal(|ui| tab_strip(ui, &TABS, &mut tab));
        self.proxmox.tab = tab;
        ui.add_space(6.0);
        let fail = self.proxmox.state.get(&b).and_then(|s| s.fail.clone());
        if let Some(e) = &fail {
            said(ui, e, WARNING());
            ui.horizontal(|ui| {
                if button(ui, "Try again", false, false) {
                    self.refresh_proxmox(true);
                }
                if button(ui, "Enter the secret again", false, false) {
                    self.pve_forget(&b);
                    // Not from the keychain this time.
                    self.proxmox.asked_key.insert(b.clone());
                }
            });
            ui.add_space(6.0);
        }
        let Some(data) = data else {
            if fail.is_none() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    said(ui, "Asking Proxmox…", TEXT_SUBTLE());
                });
            }
            return;
        };
        let mut open: Option<Sel> = None;
        let mut go: Option<Selected> = None;
        self.page_scroll().id_salt(("proxmox", tab)).show(ui, |ui| {
            match tab {
                0 => self.pve_overview(ui, &data, &world, &l),
                1 => open = self.pve_machines(ui, &b, &world, &l),
                2 => pve_stores(ui, &world, &self.search.to_lowercase()),
                3 => pve_tasks(ui, &data, &self.search.to_lowercase()),
                _ => go = self.pve_kubernetes(ui, &world, &l),
            }
            let gone: Vec<String> = data["gone"].as_object().into_iter().flatten().map(|(k, e)| format!("{}: {}", match k.as_str() { "status" => "the cluster's state", "tasks" => "tasks", "ha" => "high availability", "nobackup" => "what's in no backup", x => x }, e.as_str().unwrap_or(""))).collect();
            if !gone.is_empty() {
                said(ui, &format!("Not read: {}.", gone.join("; ")), TEXT_PLACEHOLDER());
            }
            ui.add_space(20.0);
        });
        if let Some(s) = open {
            self.proxmox.sel = Some(s);
            self.refresh_proxmox(false);
        }
        if let Some(s) = go {
            self.navigate(View::Resource(s.kind), Some(s));
        }
    }

    fn pve_login(&mut self, ui: &mut Ui, c: &Conf) {
        let b = c.binding();
        let i = self.prefs.proxmox.iter().position(|x| x == c).unwrap_or(0);
        card(ui, |ui| {
            panel(ui, &c.label(), &c.url);
            if let Some(e) = self.proxmox.state.get(&b).and_then(|s| s.fail.clone()) {
                said(ui, &e, WARNING());
            } else if c.keep && self.proxmox.asked_key.contains(&b) {
                said(ui, "Asking the keychain…", TEXT_SUBTLE());
            }
            self.pve_secret_row(ui, i, c);
        });
    }

    /// Where the token's secret is typed. It goes to memory, and to the keychain when asked.
    fn pve_secret_row(&mut self, ui: &mut Ui, i: usize, c: &Conf) {
        let b = c.binding();
        let mut keep = c.keep;
        let mut done = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Secret of {}", c.token)).size(z(13.0)).color(TEXT_MUTED()));
            let t = self.proxmox.typed.entry(i).or_default();
            let r = ui.add(egui::TextEdit::singleline(t).password(true).hint_text("paste it here").desired_width(u(300.0)));
            ui.checkbox(&mut keep, RichText::new("Keep it in the system's keychain").size(z(13.0)));
            done = (button(ui, "Connect", true, false) || r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))) && !t.trim().is_empty();
        });
        if keep != c.keep {
            if let Some(x) = self.prefs.proxmox.get_mut(i) {
                x.keep = keep;
            }
            if let Some(x) = self.proxmox.edit.get_mut(i) {
                x.keep = keep;
            }
            if !keep && self.screenshot.is_none() {
                let b = b.clone();
                std::thread::spawn(move || keychain(&b).and_then(|e| e.delete_credential().map_err(|e| e.to_string())));
            }
            self.save();
        }
        if done && self.screenshot.is_none() {
            let t = self.proxmox.typed.remove(&i).unwrap_or_default().trim().to_string();
            match check_secret(&t) {
                Err(e) => self.toast(e, true),
                Ok(()) => {
                    if keep {
                        if let Err(e) = keychain(&b).and_then(|k| k.set_password(&t).map_err(|e| e.to_string())) {
                            self.toast(format!("It isn't kept: {}", truncate(&e, 120)), true);
                        }
                    }
                    self.pve_forget(&b);
                    self.proxmox.secrets.insert(b, t);
                    let mut c = c.clone();
                    c.keep = keep;
                    self.pve_read(&c, true);
                }
            }
        }
    }

    fn pve_overview(&mut self, ui: &mut Ui, data: &Value, w: &World, l: &HashMap<i64, Vec<(KNode, bool)>>) {
        let f = findings(data, w, l, kube::now_secs());
        let running = w.guests.iter().filter(|g| g.status == "running").count();
        let (bad, warn) = (f.iter().filter(|x| x.tone == Tone::Danger).count(), f.iter().filter(|x| x.tone == Tone::Warning).count());
        let cluster = data["status"].as_array().into_iter().flatten().find(|x| x["type"] == "cluster").and_then(|c| c["name"].as_str()).map(|n| format!("cluster {n}, ")).unwrap_or_default();
        let face = Face {
            tone: if bad > 0 { Tone::Danger } else if warn > 0 { Tone::Warning } else { Tone::Success },
            head: if f.is_empty() { "All is well".into() } else { format!("{} to look at", many(f.len() as i64, "thing")) },
            sub: format!("{cluster}Proxmox VE {}", data["version"]["version"].as_str().unwrap_or("")),
            notes: vec![],
            pills: vec![],
            facts: vec![
                face::Fact::new("Hosts", format!("{} of {} online", w.hosts.iter().filter(|h| h.online).count(), w.hosts.len())),
                face::Fact::new("Machines running", format!("{running} of {}", w.guests.iter().filter(|g| !g.template).count())),
                face::Fact::new("Kubernetes nodes here", l.values().map(|x| x.len()).sum::<usize>().to_string()),
                face::Fact::new("Memory", format!("{} of {}", size(w.hosts.iter().map(|h| h.mem).sum()), size(w.hosts.iter().map(|h| h.maxmem).sum()))),
                face::Fact::new("Storage", format!("{} of {}", size(w.stores.iter().map(|s| s.used).sum()), size(w.stores.iter().map(|s| s.size).sum()))),
            ],
        };
        face::show(ui, &face, Side::None);
        ui.add_space(10.0);
        if !f.is_empty() {
            let items: Vec<ops::Item> = f.into_iter().map(|x| ops::Item::new(x.tone, vec![x.what, x.more])).collect();
            let items = self.op_filter(items);
            ops::table(ui, "To look at", "", &[("What", 0.42), ("More", 0.58)], &items, 60, "Nothing with this filter.");
        }
        panel(ui, "Hosts", "");
        ui.add_space(6.0);
        let hosts = w.hosts.clone();
        dash::grid(ui, hosts.len(), u(360.0), u(196.0), 14.0, |ui, i, r| {
            let h = &hosts[i];
            let p = ui.painter();
            p.rect(r, CornerRadius::same(10), BG_CARD(), Stroke::new(1.0, BORDER_SUBTLE()), egui::StrokeKind::Inside);
            p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(4.0, r.height())), CornerRadius { nw: 10, sw: 10, ne: 0, se: 0 }, if h.online { SUCCESS() } else { DANGER() });
            let x = r.left() + u(18.0);
            label_at(ui, p, egui::pos2(x, r.top() + u(24.0)), &h.name, 15.5, TEXT_DEFAULT(), r.width() - u(150.0));
            let t = if h.online { format!("up {}", kube::human_duration(h.up)) } else { "offline".into() };
            p.text(egui::pos2(r.right() - u(16.0), r.top() + u(24.0)), egui::Align2::RIGHT_CENTER, t, FontId::proportional(z(12.0)), if h.online { TEXT_SUBTLE() } else { DANGER() });
            let part = |a: f64, b: f64| if b > 0.0 { a / b } else { 0.0 };
            for (j, (name, frac, words)) in [("CPU", h.cpu, format!("{:.0}% of {} cores", h.cpu * 100.0, h.cores)), ("Memory", part(h.mem, h.maxmem), format!("{} of {}", size(h.mem), size(h.maxmem))), ("Own disk", part(h.disk, h.maxdisk), format!("{} of {}", size(h.disk), size(h.maxdisk)))].into_iter().enumerate() {
                let (frac, words) = if h.online { (frac, words) } else { (0.0, "not known".to_string()) };
                let y = r.top() + u(58.0 + 32.0 * j as f32);
                label_at(ui, p, egui::pos2(x, y), name, 12.5, TEXT_MUTED(), u(74.0));
                let bar = egui::Rect::from_min_max(egui::pos2(x + u(78.0), y - 4.0), egui::pos2(r.right() - u(150.0), y + 4.0));
                p.rect_filled(bar, CornerRadius::same(4), BG_MUTED());
                if frac > 0.0 {
                    p.rect_filled(egui::Rect::from_min_size(bar.min, egui::vec2((bar.width() * frac.min(1.0) as f32).max(3.0), bar.height())), CornerRadius::same(4), dash::load_color(frac));
                }
                p.text(egui::pos2(r.right() - u(16.0), y), egui::Align2::RIGHT_CENTER, words, FontId::proportional(z(12.0)), TEXT_DEFAULT());
            }
            let on: Vec<&Guest> = w.guests.iter().filter(|g| g.node == h.name && !g.template).collect();
            let k: usize = on.iter().map(|g| l.get(&g.id).map(|x| x.len()).unwrap_or(0)).sum();
            let words = format!("{}, {} running{}", many(on.len() as i64, "machine"), on.iter().filter(|g| g.status == "running").count(), if k > 0 { format!(", {}", many(k as i64, "Kubernetes node")) } else { String::new() });
            label_at(ui, p, egui::pos2(x, r.bottom() - u(22.0)), &words, 12.5, TEXT_SUBTLE(), r.width() - u(34.0));
        });
        ui.add_space(12.0);
    }

    fn pve_machines(&mut self, ui: &mut Ui, b: &str, w: &World, l: &HashMap<i64, Vec<(KNode, bool)>>) -> Option<Sel> {
        let q = self.search.to_lowercase();
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.proxmox.bad_only, "Only what isn't running");
        });
        let list: Vec<&Guest> = w.guests.iter().filter(|g| !g.template && (!self.proxmox.bad_only || g.status != "running") && (q.is_empty() || [&g.name, &g.node, &g.tags, &g.status].iter().any(|t| t.to_lowercase().contains(&q)) || g.id.to_string().contains(&q))).collect();
        let mut open = None;
        let heads = [("Name", 0.24), ("Id", 0.07), ("State", 0.09), ("Host", 0.12), ("CPU", 0.1), ("Memory", 0.14), ("Disk", 0.08), ("Up", 0.07), ("Kubernetes", 0.09)];
        card(ui, |ui| {
            panel(ui, &format!("Machines ({})", list.len()), "virtual machines and containers; click one for its settings, addresses and history");
            ui.spacing_mut().item_spacing.y = 0.0;
            let col = |r: egui::Rect, i: usize| {
                let w = r.width() - u(18.0);
                (r.left() + u(18.0) + w * heads[..i].iter().map(|h| h.1).sum::<f32>(), w * heads[i].1 - 8.0)
            };
            let (h, _) = dash::line(ui, u(24.0), false);
            for (i, t) in heads.iter().enumerate() {
                let (x, w) = col(h, i);
                label_at(ui, ui.painter(), egui::pos2(x, h.center().y), t.0, 11.5, TEXT_SUBTLE(), w);
            }
            for g in list.iter().take(400) {
                let (r, resp) = dash::line(ui, u(28.0), true);
                let on = g.status == "running";
                ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.5), if on { SUCCESS() } else if l.contains_key(&g.id) { DANGER() } else { TEXT_PLACEHOLDER() });
                let k = l.get(&g.id).map(|x| x.iter().map(|n| n.0 .1.clone()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                let cells = [
                    (format!("{}{}", g.name, if g.kind == "lxc" { "  (container)" } else { "" }), PRIMARY_TEXT()),
                    (g.id.to_string(), TEXT_MUTED()),
                    (g.status.clone(), if on { TEXT_MUTED() } else { WARNING() }),
                    (g.node.clone(), TEXT_MUTED()),
                    (if on { format!("{:.0}% of {}", g.cpu * 100.0, g.cores) } else { format!("{} cores", g.cores) }, TEXT_MUTED()),
                    (if on { format!("{} of {}", size(g.mem), size(g.maxmem)) } else { size(g.maxmem) }, if on && g.maxmem > 0.0 && g.mem / g.maxmem > 0.92 { WARNING() } else { TEXT_MUTED() }),
                    (size(g.maxdisk), TEXT_MUTED()),
                    (if on { kube::human_duration(g.up) } else { "-".into() }, TEXT_MUTED()),
                    (k, TEXT_DEFAULT()),
                ];
                for (i, (t, c)) in cells.iter().enumerate() {
                    let (x, w) = col(r, i);
                    label_at(ui, ui.painter(), egui::pos2(x, r.center().y), t, if i == 0 { 13.0 } else { 12.5 }, *c, w);
                }
                if resp.clicked() {
                    open = Some(Sel { binding: b.to_string(), node: g.node.clone(), kind: g.kind.clone(), id: g.id });
                }
            }
            if list.is_empty() {
                said(ui, "None with this filter.", TEXT_SUBTLE());
            }
        });
        open
    }

    /// Which Kubernetes node is where, and what goes with a host.
    fn pve_kubernetes(&mut self, ui: &mut Ui, w: &World, l: &HashMap<i64, Vec<(KNode, bool)>>) -> Option<Selected> {
        let mut go = None;
        let nodes = self.pve_nodes();
        let linked: HashSet<(String, String)> = l.values().flatten().map(|x| (x.0 .0.clone(), x.0 .1.clone())).collect();
        if nodes.is_empty() {
            said(ui, "The nodes of the open clusters aren't known (yet): your account may not be allowed to list them.", TEXT_SUBTLE());
            return None;
        }
        if linked.is_empty() {
            said(ui, "No node of the open clusters was found among these machines: nothing has their provider's id or their name.", WARNING());
            return None;
        }
        for h in &w.hosts {
            let here: Vec<(&Guest, &(KNode, bool))> = w.guests.iter().filter(|g| g.node == h.name).flat_map(|g| l.get(&g.id).into_iter().flatten().map(move |n| (g, n))).collect();
            if here.is_empty() {
                continue;
            }
            let names: HashSet<(String, String)> = here.iter().map(|x| (x.1 .0 .0.clone(), x.1 .0 .1.clone())).collect();
            let (pods, alone) = self.pve_impact(&names);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    let (d, _) = ui.allocate_exact_size(egui::vec2(u(12.0), u(12.0)), Sense::hover());
                    ui.painter().circle_filled(d.center(), u(5.0), if h.online { SUCCESS() } else { DANGER() });
                    ui.label(RichText::new(format!("Host {}", h.name)).size(z(15.5)).color(TEXT_DEFAULT()));
                    if !h.online {
                        pill(ui, "offline", DANGER());
                    }
                });
                ui.add_space(2.0);
                said(ui, &format!("If it goes: {} and {} go with it{}.", many(names.len() as i64, "Kubernetes node"), many(pods as i64, "pod"), if alone.is_empty() { "; no workload has all its pods here".to_string() } else { format!("; {} {} all pods here", many(alone.len() as i64, "workload"), if alone.len() == 1 { "has" } else { "have" }) }), if alone.is_empty() { TEXT_MUTED() } else { WARNING() });
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    for (g, (n, sure)) in &here {
                        let text = format!("{}{}  ·  {} ({})", n.1, if n.3 { " (control plane)" } else { "" }, g.name, g.id);
                        let r = ui.add(egui::Button::new(RichText::new(text).size(z(12.5)).color(PRIMARY_TEXT())).fill(BG_MUTED()).corner_radius(CornerRadius::same(6)));
                        let tip = if *sure { "Known by the node's provider id" } else { "Found by its name" };
                        if r.on_hover_text(format!("{tip}\n{}", ctx_label(&n.0))).clicked() {
                            go = Some(Selected { ctx: n.0.clone(), kind: Kind::Nodes, ns: String::new(), name: n.1.clone() });
                        }
                    }
                });
                if !alone.is_empty() {
                    ui.add_space(6.0);
                    said(ui, "All pods on this host:", TEXT_SUBTLE());
                    ui.horizontal_wrapped(|ui| {
                        for s in alone.iter().take(24) {
                            let r = ui.add(egui::Button::new(RichText::new(format!("{}/{}", s.ns, s.name)).size(z(12.5)).color(TEXT_DEFAULT())).fill(BG_MUTED()).corner_radius(CornerRadius::same(6)));
                            if r.on_hover_text(format!("{}, {}", s.kind.singular(), ctx_label(&s.ctx))).clicked() {
                                go = Some(s.clone());
                            }
                        }
                        if alone.len() > 24 {
                            said(ui, &format!("and {} more", alone.len() - 24), TEXT_PLACEHOLDER());
                        }
                    });
                }
            });
            ui.add_space(10.0);
        }
        let rest: Vec<String> = nodes.iter().filter(|n| !linked.contains(&(n.0.clone(), n.1.clone()))).map(|n| n.1.clone()).collect();
        if !rest.is_empty() {
            said(ui, &format!("Not found here: {}.", some_names(&rest)), TEXT_PLACEHOLDER());
        }
        go
    }

    /// Pods on these nodes, and workloads of more than one pod that have all of them there.
    fn pve_impact(&self, nodes: &HashSet<(String, String)>) -> (usize, Vec<Selected>) {
        let mut pods = 0;
        let mut by: HashMap<(String, Kind, String, String), (usize, usize)> = HashMap::new();
        for c in nodes.iter().map(|n| n.0.clone()).collect::<HashSet<_>>() {
            let Some(l) = self.lists.get(&Self::list_key(&c, Kind::Pods)) else { continue };
            for (o, r) in l.items.iter().zip(&l.rows) {
                let Some(n) = o["spec"]["nodeName"].as_str().filter(|_| !matches!(o["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))) else { continue };
                let here = nodes.contains(&(c.clone(), n.to_string()));
                pods += here as usize;
                if let Some((k, name)) = r.workload.clone().filter(|w| matches!(w.0, Kind::Deployments | Kind::StatefulSets)) {
                    let e = by.entry((c.clone(), k, r.ns.clone(), name)).or_default();
                    e.0 += 1;
                    e.1 += here as usize;
                }
            }
        }
        let mut alone: Vec<Selected> = by.into_iter().filter(|(_, (all, here))| *all > 1 && all == here).map(|((ctx, kind, ns, name), _)| Selected { ctx, kind, ns, name }).collect();
        alone.sort_by(|a, b| (&a.ns, &a.name, a.kind.singular(), &a.ctx).cmp(&(&b.ns, &b.name, b.kind.singular(), &b.ctx)));
        (pods, alone)
    }

    fn pve_guest_page(&mut self, ui: &mut Ui, sel: &Sel, w: &World, l: &HashMap<i64, Vec<(KNode, bool)>>) {
        let mut close = ui.input(|i| i.key_pressed(Key::Escape)) && self.dialog.is_none() && self.palette.is_none();
        let g = w.guests.iter().find(|g| g.id == sel.id).cloned().unwrap_or_default();
        ui.horizontal(|ui| {
            close |= back_button(ui).on_hover_text("All machines (Esc)").clicked();
            ui.label(RichText::new("Proxmox · Machines").size(z(12.0)).color(TEXT_SUBTLE()));
            self.ai_corner(ui, false);
        });
        if close {
            self.proxmox.sel = None;
            return;
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new(&g.name).size(z(20.0)).strong().color(TEXT_DEFAULT()));
            ui.label(RichText::new(format!("{} on {}", sel.id, sel.node)).size(z(13.0)).color(TEXT_SUBTLE()));
            pill(ui, &g.status, if g.status == "running" { SUCCESS() } else { WARNING() });
            if g.kind == "lxc" {
                pill(ui, "container", INFO());
            }
            for t in g.tags.split([';', ',']).filter(|t| !t.is_empty()) {
                pill(ui, t, TEXT_SUBTLE());
            }
        });
        ui.add_space(8.0);
        let one = self.proxmox.guest.get(&format!("{sel:?}"));
        let (data, fail) = (one.and_then(|o| o.data.clone()).unwrap_or_default(), one.and_then(|o| o.fail.clone()));
        let mut go = None;
        self.page_scroll().id_salt(("pve-guest", sel.id)).show(ui, |ui| {
            let on = g.status == "running";
            let face = Face {
                tone: if on { Tone::Success } else { Tone::Muted },
                head: if on { format!("Running for {}", kube::human_duration(g.up)) } else { g.status.clone() },
                sub: format!("{} cores, {} memory, {} disk", g.cores, size(g.maxmem), size(g.maxdisk)),
                notes: if g.lock.is_empty() { vec![] } else { vec![format!("Locked: {}", g.lock)] },
                pills: vec![],
                facts: vec![face::Fact::new("CPU", format!("{:.0}%", g.cpu * 100.0)), face::Fact::new("Memory", size(g.mem)), face::Fact::new("High availability", if g.ha.is_empty() { "no".into() } else { g.ha.clone() })],
            };
            face::show(ui, &face, Side::None);
            ui.add_space(10.0);
            for (n, sure) in l.get(&sel.id).into_iter().flatten() {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("This is Kubernetes node {} of {}", n.1, ctx_label(&n.0))).size(z(14.0)).color(TEXT_DEFAULT()));
                        ui.label(RichText::new(if *sure { "known by its provider id" } else { "found by its name" }).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                        if button(ui, "Open the node", false, false) {
                            go = Some(Selected { ctx: n.0.clone(), kind: Kind::Nodes, ns: String::new(), name: n.1.clone() });
                        }
                    });
                });
                ui.add_space(8.0);
            }
            if let Some(e) = fail {
                said(ui, &e, WARNING());
            }
            if data.is_null() {
                said(ui, "Reading the machine…", TEXT_SUBTLE());
                return;
            }
            let hist = data["history"].as_array().cloned().unwrap_or_default();
            let line = |k: &str| -> Vec<f64> { hist.iter().filter_map(|p| p[k].as_f64()).collect() };
            for (t, v, f) in [("CPU, the last day", line("cpu"), true), ("Memory, the last day", line("mem"), false)] {
                if v.len() > 2 {
                    card(ui, |ui| {
                        panel(ui, t, "");
                        pg::spark(ui, &v, u(70.0), if f { PRIMARY_TEXT() } else { INFO() }, |x| if f { format!("{:.0}%", x * 100.0) } else { size(x) });
                    });
                    ui.add_space(8.0);
                }
            }
            let ips: Vec<ops::Item> = data["net"]["result"].as_array().into_iter().flatten().filter(|i| i["name"] != "lo").map(|i| {
                let a = i["ip-addresses"].as_array().into_iter().flatten().filter_map(|x| x["ip-address"].as_str()).collect::<Vec<_>>().join(", ");
                ops::Item::new(Tone::Normal, vec![i["name"].as_str().unwrap_or("").into(), a, i["hardware-address"].as_str().unwrap_or("").into()])
            }).collect();
            if sel.kind == "qemu" {
                let why = data["gone"]["net"].as_str().map(|e| if e.contains("500") { "The guest agent doesn't answer.".to_string() } else { e.to_string() }).unwrap_or("None.".into());
                ops::table(ui, "Addresses", "from the guest agent", &[("Interface", 0.25), ("Addresses", 0.5), ("Hardware address", 0.25)], &ips, 30, &why);
            }
            let set: Vec<ops::Item> = data["config"].as_object().into_iter().flatten().map(|(k, v)| ops::Item::new(Tone::Normal, vec![k.clone(), v.as_str().map(String::from).unwrap_or(v.to_string())])).collect();
            ops::table(ui, "Settings", "a choice of them; passwords and keys are left out", &[("Setting", 0.2), ("Value", 0.8)], &set, 60, data["gone"]["config"].as_str().unwrap_or("None."));
            let now = kube::now_secs();
            let snaps: Vec<ops::Item> = data["snapshots"].as_array().into_iter().flatten().filter(|s| s["name"] != "current").map(|s| {
                let at = s["snaptime"].as_i64();
                let old = at.map(|t| now - t > 30 * 86400).unwrap_or(false);
                ops::Item::new(if old { Tone::Warning } else { Tone::Normal }, vec![s["name"].as_str().unwrap_or("").into(), ops::ago(now, at), s["description"].as_str().unwrap_or("").trim().into()])
            }).collect();
            ops::table(ui, "Snapshots", "older than a month is marked: they keep growing", &[("Name", 0.3), ("Made", 0.2), ("Description", 0.5)], &snaps, 40, data["gone"]["snapshots"].as_str().unwrap_or("None."));
            task_table(ui, "Its tasks", data["tasks"].as_array().cloned().unwrap_or_default(), "");
            ui.add_space(20.0);
        });
        if let Some(s) = go {
            self.navigate(View::Resource(s.kind), Some(s));
        }
    }

    // ---------- settings ----------

    pub(super) fn settings_proxmox(&mut self, ui: &mut Ui) {
        said(ui, "Optional. Kubedog reads your Proxmox VE hosts, machines and storage, and shows which Kubernetes node runs where. It never changes anything there.", TEXT_SUBTLE());
        ui.add_space(6.0);
        card(ui, |ui| {
            panel(ui, "A token that may only read", "made once, in Proxmox");
            said(ui, "Datacenter > Permissions > Users: add a user, such as kubedog@pve. API Tokens: add one for it (with Privilege Separation off, or give the token the role too). Permissions > Add: path /, that user, role PVEAuditor. The secret is shown once, when the token is made.", TEXT_MUTED());
        });
        ui.add_space(10.0);
        if self.proxmox.edit.len() != self.prefs.proxmox.len() {
            self.proxmox.edit = self.prefs.proxmox.clone();
        }
        let mut changed = false;
        let mut remove = None;
        for i in 0..self.proxmox.edit.len() {
            let mut e = self.proxmox.edit[i].clone();
            let before = self.prefs.proxmox[i].clone();
            let mut done = false;
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    panel(ui, &if e.label().is_empty() { "New Proxmox".to_string() } else { e.label() }, "");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if self.proxmox.confirm == Some(i) {
                            if button(ui, "Really remove", false, true) {
                                remove = Some(i);
                            }
                        } else if button(ui, "Remove", false, false) {
                            self.proxmox.confirm = Some(i);
                        }
                    });
                });
                let field = |ui: &mut Ui, label: &str, add: &mut dyn FnMut(&mut Ui)| {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(egui::vec2(u(130.0), u(24.0)), Sense::hover());
                        label_at(ui, ui.painter(), r.left_center(), label, 13.0, TEXT_MUTED(), r.width());
                        add(ui);
                    });
                };
                field(ui, "Name", &mut |ui| done |= ui.add(egui::TextEdit::singleline(&mut e.name).hint_text("optional").desired_width(u(240.0))).lost_focus());
                field(ui, "Address", &mut |ui| done |= ui.add(egui::TextEdit::singleline(&mut e.url).hint_text("https://proxmox.example.com:8006").desired_width(u(420.0))).lost_focus());
                if let Err(t) = check_url(&e.url).map(|_| ()).or_else(|t| if e.url.is_empty() { Ok(()) } else { Err(t) }) {
                    said(ui, &t, WARNING());
                }
                field(ui, "Token", &mut |ui| done |= ui.add(egui::TextEdit::singleline(&mut e.token).hint_text("kubedog@pve!reader").desired_width(u(240.0))).lost_focus());
                if !e.token.is_empty() {
                    if let Err(t) = check_token(e.token.trim()) {
                        said(ui, &t, WARNING());
                    }
                }
                ui.add_space(6.0);
                let mut ca = self.proxmox.ca.remove(&i).unwrap_or_default();
                ca.ca = e.ca.clone();
                ca.shared = e.shared;
                done |= self.grafana_ca(ui, &format!("proxmox|{i}"), &mut ca);
                e.ca = ca.ca.clone();
                e.shared = ca.shared;
                self.proxmox.ca.insert(i, ca);
                said(ui, "Add this first. Proxmox usually signs its own certificate: its authority is the file /etc/pve/pve-root-ca.pem on a host. The address has to be a name or number that's in the host's certificate.", TEXT_PLACEHOLDER());
                ui.add_space(6.0);
                if before.complete() {
                    if self.proxmox.secrets.contains_key(&before.binding()) {
                        ui.horizontal(|ui| {
                            let s = self.proxmox.state.get(&before.binding());
                            match s.map(|s| (s.loading, s.fail.clone(), s.data.is_some())) {
                                Some((true, _, _)) => {
                                    ui.spinner();
                                }
                                Some((_, Some(f), _)) => said(ui, &f, DANGER()),
                                Some((_, None, true)) => said(ui, "Connected", SUCCESS()),
                                _ => {}
                            }
                            if button(ui, "Forget the secret", false, false) {
                                let b = before.binding();
                                if before.keep && self.screenshot.is_none() {
                                    let b = b.clone();
                                    std::thread::spawn(move || keychain(&b).and_then(|e| e.delete_credential().map_err(|e| e.to_string())));
                                }
                                self.pve_forget(&b);
                            }
                            if self.connected && button(ui, "Open Proxmox", true, false) {
                                self.proxmox.which = self.prefs.proxmox.iter().filter(|c| c.complete()).position(|c| *c == before).unwrap_or(0);
                                self.set_view(View::Proxmox);
                            }
                        });
                    } else {
                        self.pve_secret_row(ui, i, &before);
                    }
                }
            });
            ui.add_space(10.0);
            if done {
                let mut ok = e.clone();
                ok.name = e.name.trim().to_string();
                ok.token = e.token.trim().to_string();
                if let Ok(x) = check_url(&e.url) {
                    ok.url = x;
                }
                e = ok.clone();
                if ok != before {
                    // Another certificate for the same server and token: the secret stays, Proxmox shows it only once.
                    let same = ok.url == before.url && ok.token == before.token;
                    let secret = self.proxmox.secrets.get(&before.binding()).cloned().filter(|_| same);
                    if ok.binding() != before.binding() {
                        self.pve_forget(&before.binding());
                        if before.keep && self.screenshot.is_none() && before.complete() {
                            let b = before.binding();
                            std::thread::spawn(move || keychain(&b).and_then(|e| e.delete_credential().map_err(|e| e.to_string())));
                        }
                        ok.keep = false;
                        if let Some(t) = secret {
                            let b = ok.binding();
                            if before.keep && self.screenshot.is_none() {
                                match keychain(&b).and_then(|k| k.set_password(&t).map_err(|e| e.to_string())) {
                                    Ok(()) => ok.keep = true,
                                    Err(x) => self.toast(format!("It isn't kept: {}", truncate(&x, 120)), true),
                                }
                            }
                            self.proxmox.secrets.insert(b, t);
                        }
                        e.keep = ok.keep;
                    }
                    let again = ok.clone();
                    self.prefs.proxmox[i] = ok;
                    self.pve_read(&again, true);
                    changed = true;
                }
            }
            if i < self.proxmox.edit.len() {
                // (What was ticked beside the secret is in there already.)
                e.keep = self.prefs.proxmox[i].keep;
                self.proxmox.edit[i] = e;
            }
        }
        if let Some(i) = remove {
            let c = self.prefs.proxmox.remove(i);
            self.pve_forget(&c.binding());
            if c.keep && self.screenshot.is_none() {
                let b = c.binding();
                std::thread::spawn(move || keychain(&b).and_then(|e| e.delete_credential().map_err(|e| e.to_string())));
            }
            self.proxmox.edit.clear();
            self.proxmox.typed.clear();
            self.proxmox.ca.clear();
            self.proxmox.confirm = None;
            changed = true;
        }
        if button(ui, if self.prefs.proxmox.is_empty() { "Add a Proxmox" } else { "Add another" }, self.prefs.proxmox.is_empty(), false) {
            self.prefs.proxmox.push(Conf::default());
            self.proxmox.edit.clear();
        }
        if changed {
            self.save();
        }
    }
}

fn pve_stores(ui: &mut Ui, w: &World, q: &str) {
    let mut items: Vec<ops::Item> = w.stores.iter().filter(|s| q.is_empty() || s.name.to_lowercase().contains(q) || s.node.to_lowercase().contains(q)).map(|s| {
        let part = if s.size > 0.0 { s.used / s.size } else { 0.0 };
        let tone = if !s.ok || part > 0.93 { Tone::Danger } else if part > 0.85 { Tone::Warning } else { Tone::Success };
        ops::Item::new(tone, vec![s.name.clone(), if s.ok { format!("{:.0}% full", part * 100.0) } else { "not available".into() }, format!("{} of {}", size(s.used), size(s.size)), if s.shared { "all hosts".into() } else { s.node.clone() }, s.kind.clone(), s.content.clone()])
    }).collect();
    ops::worst_first(&mut items);
    ops::table(ui, &format!("Storage ({})", items.len()), "what every host has of its own is listed per host", &[("Name", 0.2), ("State", 0.13), ("Used", 0.2), ("Where", 0.15), ("Kind", 0.12), ("Holds", 0.2)], &items, 200, "None with this filter.");
}

fn pve_tasks(ui: &mut Ui, data: &Value, q: &str) {
    task_table(ui, "Tasks", data["tasks"].as_array().cloned().unwrap_or_default(), q);
}

fn task_table(ui: &mut Ui, title: &str, l: Vec<Value>, q: &str) {
    let now = kube::now_secs();
    let items: Vec<ops::Item> = l.iter().filter(|t| !["vncproxy", "spiceproxy", "vncshell"].contains(&t["type"].as_str().unwrap_or(""))).map(|t| {
        let s = |k: &str| t[k].as_str().unwrap_or("").to_string();
        let (tone, state) = if t["endtime"].is_null() { (Tone::Info, "running".to_string()) } else if failed(t) { (Tone::Danger, s("status")) } else if s("status").starts_with("WARNINGS") { (Tone::Warning, s("status").to_lowercase()) } else { (Tone::Success, "done".into()) };
        let took = t["endtime"].as_i64().zip(t["starttime"].as_i64()).map(|(e, b)| kube::human_duration((e - b).max(0))).unwrap_or_default();
        ops::Item::new(tone, vec![format!("{} {}", task_word(&s("type")), s("id")), state, s("node"), s("user"), ops::ago(now, t["starttime"].as_i64()), took])
    }).filter(|i| q.is_empty() || i.cells.iter().any(|c| c.to_lowercase().contains(q))).collect();
    ops::table(ui, &format!("{title} ({})", items.len()), "the newest first", &[("What", 0.2), ("State", 0.36), ("Host", 0.12), ("Who", 0.14), ("Started", 0.1), ("Took", 0.08)], &items, 120, "None.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sizes() {
        let g = 1024f64.powi(3);
        assert_eq!((size(32.0 * g), size(1.5 * g), size(20000.0 * g), size(0.0)), ("32 Gi".into(), "1.5 Gi".into(), "20 Ti".into(), "0 Ki".into()));
    }

    #[test]
    fn addresses_and_tokens() {
        assert_eq!(check_url("proxmox.example.com").unwrap(), "https://proxmox.example.com:8006");
        assert_eq!(check_url("https://p.example.com:443/").unwrap(), "https://p.example.com:443");
        for bad in ["http://p.example.com", "https://p.example.com/api2", "https://a:b@p.example.com", ""] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
        assert!(check_token("kubedog@pve!reader").is_ok());
        for bad in ["kubedog@pve", "kubedog!reader", "a@b!c\nX: y", "a@b!", "", "a b@pve!x"] {
            assert!(check_token(bad).is_err(), "{bad}");
        }
        assert!(check_secret("0f8fad5b-d9cb-469f-a165-70867728950e").is_ok() && check_secret("a\r\nb").is_err() && check_secret("").is_err());
        let c = Conf { url: "https://a:8006".into(), token: "a@b!c".into(), ..Default::default() };
        assert_ne!(c.binding(), Conf { url: "https://b:8006".into(), ..c.clone() }.binding());
        assert_eq!(Conf::from_json(&c.json()), c);
        // No secret is ever in the settings.
        assert!(!c.json().to_string().contains("secret"));
    }

    fn world() -> World {
        World::read(&json!({"resources": [
            {"type": "node", "node": "h1", "status": "online", "cpu": 0.2, "maxcpu": 8, "mem": 95, "maxmem": 100, "disk": 1, "maxdisk": 10, "uptime": 10},
            {"type": "node", "node": "h2", "status": "offline"},
            {"type": "qemu", "vmid": 100, "name": "cp-1", "node": "h1", "status": "running", "maxmem": 60},
            {"type": "qemu", "vmid": 101, "name": "cp-2.lan", "node": "h1", "status": "running", "maxmem": 60},
            {"type": "qemu", "vmid": 102, "name": "cp-3", "node": "h2", "status": "stopped", "maxmem": 60},
            {"type": "qemu", "vmid": 9, "name": "cp-3", "node": "h2", "status": "stopped", "template": 1},
            {"type": "lxc", "vmid": 200, "name": "dns", "node": "h1", "status": "running", "lock": "backup"},
            {"type": "storage", "storage": "ceph", "node": "h1", "status": "available", "shared": 1, "disk": 95, "maxdisk": 100},
            {"type": "storage", "storage": "ceph", "node": "h2", "status": "available", "shared": 1, "disk": 95, "maxdisk": 100},
            {"type": "storage", "storage": "local", "node": "h2", "status": "unknown"}
        ]}))
    }

    fn kn(n: &str, id: &str) -> KNode {
        ("c".into(), n.into(), id.into(), true)
    }

    #[test]
    fn nodes_and_machines() {
        let w = world();
        assert_eq!((w.hosts.len(), w.guests.len(), w.stores.len()), (2, 5, 2));
        let l = links(&w, &[kn("whatever", "proxmox://lab/100"), kn("cp-2", ""), kn("CP-3", ""), kn("dns", "aws:///x/i-1"), kn("other", "")]);
        assert!(l[&100][0].1 && !l[&101][0].1 && l[&102][0].0 .1 == "CP-3");
        assert!(!l.contains_key(&200) && l.len() == 3);
        // Two machines of one name: not known which.
        let mut two = w.clone();
        two.guests.push(Guest { id: 300, name: "cp-1".into(), ..Default::default() });
        assert!(links(&two, &[kn("cp-1", "")]).is_empty());
    }

    #[test]
    fn what_stands_out() {
        let w = world();
        let l = links(&w, &[kn("cp-1", ""), kn("cp-2", ""), kn("cp-3", "")]);
        let v = json!({"status": [{"type": "cluster", "quorate": 0}], "ha": [{"type": "service", "sid": "vm:100", "state": "error"}], "nobackup": [{"name": "dns"}], "tasks": [
            {"type": "vzdump", "id": "100", "status": "job errors", "starttime": 1000, "endtime": 1100},
            {"type": "vzdump", "id": "101", "status": "OK", "starttime": 1000, "endtime": 1100},
            {"type": "vzdump", "id": "102", "status": "WARNINGS: 1", "starttime": 1000, "endtime": 1100},
            {"type": "qmstart", "id": "103", "starttime": 1000}
        ]});
        let f = findings(&v, &w, &l, 2000);
        let t = f.iter().map(|x| format!("{} / {}", x.what, x.more)).collect::<Vec<_>>().join("\n");
        for w in ["no quorum", "Host h2 is offline", "h1 is nearly out of memory", "promised more memory", "Storage ceph is 95% full", "Storage local isn't available", "vm:100 is in error", "cp-3 is stopped", "dns is locked", "Most control plane nodes of c are on host h1", "1 task failed", "1 machine in no backup"] {
            assert!(t.contains(w), "{w}\n{t}");
        }
        assert!(f[0].tone == Tone::Danger);
        assert!(findings(&json!({}), &World::default(), &HashMap::new(), 0).is_empty());
    }

    #[test]
    fn settings_without_secrets() {
        let v = known_settings(&json!({"cores": 4, "memory": "8192", "scsi0": "local:vm-1", "net0": "virtio=x", "cipassword": "made-up", "sshkeys": "made-up", "args": "made-up", "smbios1": "x", "scsihw": "virtio", "scsix": "made-up", "hookscript": "x"}));
        assert_eq!(v, json!({"cores": 4, "memory": "8192", "scsi0": "local:vm-1", "net0": "virtio=x", "scsihw": "virtio"}));
    }

    /// A stand-in for Proxmox that answers a number of requests.
    fn serve(n: usize, answer: impl Fn(&str) -> (u16, String) + Send + 'static) -> (Conf, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = Conf { url: format!("http://{}", l.local_addr().unwrap()), token: "a@pve!b".into(), ..Default::default() };
        let h = std::thread::spawn(move || {
            let mut got = vec![];
            for _ in 0..n {
                let (mut s, _) = l.accept().unwrap();
                let mut b = [0u8; 8192];
                let k = s.read(&mut b).unwrap();
                let t = String::from_utf8_lossy(&b[..k]).to_string();
                let path = t.split_whitespace().nth(1).unwrap_or("").to_string();
                let (code, body) = answer(&path);
                s.write_all(format!("HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
                got.push(t);
            }
            got
        });
        (c, h)
    }

    #[test]
    fn a_stand_in_server() {
        let (c, h) = serve(6, |p| if p.ends_with("/version") { (200, r#"{"data":{"version":"8.2"}}"#.into()) } else if p.ends_with("/resources") { (200, r#"{"data":[]}"#.into()) } else { (403, String::new()) });
        let v = read_all(&c, "made-up").unwrap();
        assert!(v["version"]["version"] == "8.2" && v["gone"]["tasks"].as_str().unwrap().contains("may not"));
        let got = h.join().unwrap();
        assert!(got.iter().all(|t| t.starts_with("GET /api2/json/") && t.to_lowercase().contains("authorization: pveapitoken=a@pve!b=made-up")));
        let (c, h) = serve(1, |_| (401, String::new()));
        assert!(read_all(&c, "made-up").unwrap_err().contains("refused"));
        h.join().unwrap();
        // Never sent on.
        let (c, h) = serve(1, |_| (301, String::new()));
        assert!(read_all(&c, "made-up").unwrap_err().contains("somewhere else"));
        h.join().unwrap();
        let odd = Sel { binding: String::new(), node: "../x".into(), kind: "qemu".into(), id: 1 };
        assert!(read_guest(&Conf { url: "http://127.0.0.1:9".into(), token: "a@pve!b".into(), ..Default::default() }, "x", &odd).is_err());
    }
}
