//! Node figures from a Grafana, as an option per cluster: for accounts that may not read nodes, and
//! for history. The password (or token) is asked for once per run, is only kept in memory and only
//! goes to the address it was typed for. The server's certificate is always checked: against the
//! certificate authority that was added for it, else the system's. Only GET requests, no
//! redirects, no proxies.

use super::*;
use std::sync::Arc;

// ---------- settings ----------

/// What's kept between runs. No password.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Conf {
    pub url: String,
    /// Empty: a service account token is used.
    pub user: String,
    pub token: bool,
    /// Certificate authorities (PEM) for this server only; empty: the system's.
    pub ca: String,
    /// The data source's uid.
    pub uid: String,
    /// Only series with this label, like `cluster="prod"`.
    pub label: String,
}

impl Conf {
    pub fn json(&self) -> Value {
        serde_json::json!({"url": self.url, "user": self.user, "token": self.token, "ca": self.ca, "uid": self.uid, "label": self.label})
    }
    pub fn from_json(v: &Value) -> Conf {
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        Conf { url: s("url"), user: s("user"), token: v["token"].as_bool().unwrap_or(false), ca: s("ca"), uid: s("uid"), label: s("label") }
    }
    /// What a typed password is for: it's forgotten when any of this changes.
    fn binding(&self) -> String {
        format!("{}\n{}\n{}\n{}", self.url, self.user, self.token, self.ca)
    }
    pub fn complete(&self) -> bool {
        check_url(&self.url).is_ok() && (self.token || !self.user.is_empty())
    }
}

/// A password or token. Never printed.
pub(super) struct Secret(String);

/// The address, tidied: https, or http on this computer only.
pub(super) fn check_url(s: &str) -> Result<String, String> {
    let s = s.trim().trim_end_matches('/');
    if s.is_empty() || s.ends_with(':') {
        return Err("Enter Grafana's address.".into());
    }
    let full = if s.contains("://") { s.to_string() } else { format!("https://{s}") };
    let uri: ureq::http::Uri = full.parse().map_err(|_| "That isn't a web address.".to_string())?;
    let host = uri.host().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_string();
    if host.is_empty() {
        return Err("That isn't a web address.".into());
    }
    if uri.authority().map(|a| a.as_str().contains('@')).unwrap_or(false) {
        return Err("Leave the name and password out of the address.".into());
    }
    if full.contains(['?', '#']) {
        return Err("Enter only the start of the address, without what follows ? or #.".into());
    }
    match uri.scheme_str() {
        Some("https") => Ok(full),
        Some("http") if matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") => Ok(full),
        Some("http") => Err("Use https: with http the password would travel unprotected.".into()),
        _ => Err("Use an address that starts with https://".into()),
    }
}

/// A label filter: `cluster="prod"`, or several with commas.
pub(super) fn check_label(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(String::new());
    }
    let ok = s.split(',').all(|p| {
        let Some((k, v)) = p.trim().split_once('=') else { return false };
        let name = !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !k.starts_with(|c: char| c.is_ascii_digit());
        name && v.len() >= 2 && v.starts_with('"') && v.ends_with('"') && !v[1..v.len() - 1].contains(['"', '\\', '{', '}']) && !v.chars().any(|c| c.is_control())
    });
    if ok { Ok(s.to_string()) } else { Err("Write it like cluster=\"prod\"".into()) }
}

// ---------- certificates ----------

/// Certificates to look at before trusting them.
#[derive(Clone, Debug)]
pub(super) struct Draft {
    pub pem: String,
    /// Each with its SHA-256 fingerprint.
    pub certs: Vec<(certs::CertInfo, String)>,
}

fn fingerprint(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der).as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

pub(super) fn pem_ders(text: &str) -> Vec<Option<Vec<u8>>> {
    let mut out = vec![];
    let mut rest = text;
    while let Some(i) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[i + 27..];
        let Some(end) = body.find("-----END CERTIFICATE-----") else {
            out.push(None);
            break;
        };
        out.push(b64_decode(&body[..end].split_whitespace().collect::<String>()));
        rest = &body[end..];
    }
    out
}

fn to_pem(der: &[u8]) -> String {
    let b = b64_encode(der);
    let lines: Vec<&str> = b.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

/// A certificate file (PEM, with one or many, or DER). Private keys are refused.
pub(super) fn read_ca(bytes: &[u8]) -> Result<Draft, String> {
    if bytes.len() > 2_000_000 {
        return Err("That's too big for certificates.".into());
    }
    let text = String::from_utf8_lossy(bytes);
    if text.contains("PRIVATE KEY") {
        return Err("That holds a private key. Only the certificate authority's certificate is needed; keep the key to yourself.".into());
    }
    let ders: Vec<Vec<u8>> = if bytes.first() == Some(&0x30) && !text.contains("-----BEGIN") {
        vec![bytes.to_vec()]
    } else {
        pem_ders(&text).into_iter().collect::<Option<Vec<_>>>().ok_or("A certificate in it is cut off or damaged.")?
    };
    if ders.is_empty() {
        return Err("There's no certificate in it (looking for -----BEGIN CERTIFICATE-----).".into());
    }
    let mut certs = vec![];
    for d in &ders {
        certs.push((certs::parse_cert(d).ok_or("A certificate in it can't be read.")?, fingerprint(d)));
    }
    Ok(Draft { pem: ders.iter().map(|d| to_pem(d)).collect(), certs })
}

// ---------- asking ----------

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Fail {
    /// The login was refused: it isn't tried again.
    Login(String),
    /// Something asking again by itself won't help with.
    Stop(String),
    Other(String),
}

impl Fail {
    pub fn text(&self) -> &str {
        match self {
            Fail::Login(s) | Fail::Stop(s) | Fail::Other(s) => s,
        }
    }
}

pub(super) struct Client {
    agent: ureq::Agent,
    conf: Conf,
    auth: String,
}

pub(super) fn explain(e: &ureq::Error, own_ca: bool) -> Fail {
    let t = e.to_string();
    let low = t.to_lowercase();
    if low.contains("unknownissuer") || low.contains("unknown issuer") || low.contains("not trusted") || low.contains("untrusted") {
        return Fail::Stop(if own_ca { "The server's certificate isn't signed by the certificate authority you added." } else { "This computer doesn't know who signed the server's certificate. Add your company's certificate authority." }.into());
    }
    if low.contains("notvalidforname") || low.contains("not valid for name") {
        return Fail::Stop("The server's certificate is for another name than this address.".into());
    }
    if low.contains("expired") {
        return Fail::Stop("The server's certificate has expired.".into());
    }
    if low.contains("certificate") {
        return Fail::Stop(format!("The server's certificate was refused: {}", truncate(&t, 160)));
    }
    match e {
        ureq::Error::HostNotFound => Fail::Other("That name can't be found from this computer.".into()),
        ureq::Error::ConnectionFailed => Fail::Other("Nothing answers at that address.".into()),
        ureq::Error::Timeout(_) => Fail::Other("It didn't answer in time.".into()),
        ureq::Error::Io(x) if x.kind() == std::io::ErrorKind::ConnectionRefused => Fail::Other("Nothing answers at that address.".into()),
        _ => Fail::Other(truncate(&t, 160)),
    }
}

impl Client {
    pub fn new(conf: &Conf, secret: &Secret) -> Result<Client, Fail> {
        let url = check_url(&conf.url).map_err(Fail::Stop)?;
        let roots = if conf.ca.is_empty() {
            ureq::tls::RootCerts::PlatformVerifier
        } else {
            let ders = pem_ders(&conf.ca).into_iter().collect::<Option<Vec<_>>>().filter(|d| !d.is_empty()).ok_or_else(|| Fail::Stop("The saved certificate can't be read.".into()))?;
            let list: Vec<_> = ders.iter().map(|d| ureq::tls::Certificate::from_der(d).to_owned()).collect();
            ureq::tls::RootCerts::new_with_certs(&list)
        };
        if secret.0.chars().any(|c| c == '\r' || c == '\n' || c == '\0') || conf.user.chars().any(|c| c.is_control() || c == ':') {
            return Err(Fail::Stop("The login has characters that can't be used.".into()));
        }
        let auth = if conf.token { format!("Bearer {}", secret.0) } else { format!("Basic {}", b64_encode(format!("{}:{}", conf.user, secret.0).as_bytes())) };
        let agent = ureq::Agent::config_builder()
            .https_only(url.starts_with("https://"))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(30)))
            .user_agent("Kubedog")
            .tls_config(ureq::tls::TlsConfig::builder().root_certs(roots).build())
            .build()
            .new_agent();
        Ok(Client { agent, conf: Conf { url, ..conf.clone() }, auth })
    }

    fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value, Fail> {
        let mut r = self.agent.get(format!("{}{path}", self.conf.url)).header("Authorization", &self.auth).header("Accept", "application/json");
        for (k, v) in query {
            r = r.query(k, v);
        }
        let mut resp = r.call().map_err(|e| explain(&e, !self.conf.ca.is_empty()))?;
        let code = resp.status().as_u16();
        match code {
            200 => {}
            401 => return Err(Fail::Login(if self.conf.token { "Grafana refused the token.".into() } else { "Grafana refused the user name or password.".into() })),
            403 => return Err(Fail::Stop("Grafana says this account may not read that.".into())),
            300..=399 => return Err(Fail::Stop("Grafana sends logins somewhere else (single sign-on?), so a password can't be used. A service account token may work.".into())),
            404 => return Err(Fail::Stop("Not found: check the address and the data source.".into())),
            400 | 422 => return Ok(Value::Null),
            c => return Err(Fail::Other(format!("Grafana answered {c}."))),
        }
        let text = resp.body_mut().with_config().limit(24 * 1024 * 1024).read_to_string().map_err(|e| explain(&e, !self.conf.ca.is_empty()))?;
        serde_json::from_str(&text).map_err(|_| Fail::Stop("What answers there isn't Grafana.".into()))
    }

    /// Prometheus data sources: (name, uid), the default one first.
    pub fn sources(&self) -> Result<Vec<(String, String)>, Fail> {
        let v = self.get("/api/frontend/settings", &[])?;
        let mut out: Vec<(bool, String, String)> = v["datasources"]
            .as_object()
            .ok_or_else(|| Fail::Stop("What answers there isn't Grafana.".into()))?
            .iter()
            .filter(|(_, d)| d["type"].as_str().map(|t| t.contains("prometheus") || t.contains("mimir") || t.contains("victoriametrics-metrics")).unwrap_or(false))
            .filter_map(|(n, d)| Some((d["isDefault"].as_bool() != Some(true), n.clone(), d["uid"].as_str()?.to_string())))
            .collect();
        out.sort();
        Ok(out.into_iter().map(|x| (x.1, x.2)).collect())
    }

    fn prom(&self, what: &str, query: &[(&str, &str)]) -> Result<Value, Fail> {
        if self.conf.uid.is_empty() || !self.conf.uid.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
            return Err(Fail::Stop("Choose a data source first.".into()));
        }
        self.get(&format!("/api/datasources/proxy/uid/{}/api/v1/{what}", self.conf.uid), query)
    }
}

// ---------- queries ----------

const FS: &str = r#"fstype!~"tmpfs|devtmpfs|ramfs|overlay|squashfs|nsfs|autofs|rootfs|iso9660|efivarfs|fuse.*|nfs.*|cifs|ceph",mountpoint!~"/(run|proc|sys|dev)(/.*)?|.*/kubelet/.*|.*/containerd/.*|.*/docker/.*|.*/containers/.*""#;
const NET: &str = r#"device!~"lo|veth.*|cali.*|cilium.*|lxc.*|docker.*|br-.*|cni.*|flannel.*|tunl.*|vxlan.*|geneve.*|genev_.*|ovs.*|ovn.*|kube-.*|nodelocaldns|dummy.*|tap.*|vnet.*|virbr.*|wg.*""#;

/// A metric with label filters.
fn m(name: &str, filter: &str, label: &str) -> String {
    let parts: Vec<&str> = [filter, label].into_iter().filter(|p| !p.is_empty()).collect();
    if parts.is_empty() { name.to_string() } else { format!("{name}{{{}}}", parts.join(",")) }
}

/// What's asked about now: (name, query).
fn queries(label: &str) -> Vec<(&'static str, String)> {
    let l = label;
    vec![
        ("uname", m("node_uname_info", "", l)),
        ("cpu", format!("1 - avg by (instance) (rate({}[5m]))", m("node_cpu_seconds_total", r#"mode="idle""#, l))),
        ("cores", format!("count by (instance) ({})", m("node_cpu_seconds_total", r#"mode="idle""#, l))),
        ("mem_total", m("node_memory_MemTotal_bytes", "", l)),
        ("mem_avail", m("node_memory_MemAvailable_bytes", "", l)),
        ("load", m("node_load1", "", l)),
        ("boot", m("node_boot_time_seconds", "", l)),
        ("fs_size", m("node_filesystem_size_bytes", FS, l)),
        ("fs_avail", m("node_filesystem_avail_bytes", FS, l)),
        ("fs_soon", format!("predict_linear({}[6h], 345600) < 0", m("node_filesystem_avail_bytes", FS, l))),
        // The busiest link, so a bond and its parts aren't added up.
        ("rx", format!("max by (instance) (rate({}[5m]))", m("node_network_receive_bytes_total", NET, l))),
        ("tx", format!("max by (instance) (rate({}[5m]))", m("node_network_transmit_bytes_total", NET, l))),
        // How full the table of connections is, and packets dropped a second.
        ("conntrack", format!("max by (instance) ({}) / max by (instance) ({})", m("node_nf_conntrack_entries", "", l), m("node_nf_conntrack_entries_limit", "", l))),
        ("drops", format!("sum by (instance) (rate({}[5m])) + sum by (instance) (rate({}[5m]))", m("node_network_receive_drop_total", NET, l), m("node_network_transmit_drop_total", NET, l))),
        ("info", m("kube_node_info", "", l)),
        ("ready", m("kube_node_status_condition", r#"condition="Ready",status="true""#, l)),
        ("cordon", m("kube_node_spec_unschedulable", "", l)),
    ]
}

fn history_queries(label: &str, rate: &str) -> Vec<(&'static str, String)> {
    vec![
        ("cpu", format!("1 - avg by (instance) (rate({}[{rate}]))", m("node_cpu_seconds_total", r#"mode="idle""#, label))),
        ("mem", format!("1 - max by (instance) ({}) / max by (instance) ({})", m("node_memory_MemAvailable_bytes", "", label), m("node_memory_MemTotal_bytes", "", label))),
        ("load", format!("max by (instance) ({})", m("node_load1", "", label))),
        ("rx", format!("max by (instance) (rate({}[{rate}]))", m("node_network_receive_bytes_total", NET, label))),
        ("tx", format!("max by (instance) (rate({}[{rate}]))", m("node_network_transmit_bytes_total", NET, label))),
    ]
}

/// (name, seconds back, step, rate window)
const WINDOWS: [(&str, i64, i64, &str); 4] = [("1 hour", 3600, 60, "5m"), ("6 hours", 21600, 180, "5m"), ("24 hours", 86400, 600, "10m"), ("7 days", 604800, 3600, "1h")];

type Labels = serde_json::Map<String, Value>;

fn number(v: &Value) -> Option<f64> {
    v.as_str().and_then(|s| s.parse::<f64>().ok()).or(v.as_f64()).filter(|x| x.is_finite())
}

/// The samples of an instant answer.
fn samples(v: &Value) -> Vec<(Labels, f64)> {
    v["data"]["result"].as_array().into_iter().flatten().filter_map(|r| Some((r["metric"].as_object()?.clone(), number(&r["value"][1])?))).collect()
}

/// The series of a range answer, by instance.
fn series(v: &Value) -> HashMap<String, Vec<(i64, f64)>> {
    v["data"]["result"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| Some((r["metric"]["instance"].as_str()?.to_string(), r["values"].as_array()?.iter().filter_map(|p| Some((p[0].as_f64()? as i64, number(&p[1])?))).collect())))
        .collect()
}

fn lab<'a>(l: &'a Labels, k: &str) -> &'a str {
    l.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// "10.1.2.3:9100" → "10.1.2.3", "[fd00::1]:9100" → "fd00::1".
fn host(instance: &str) -> &str {
    if let Some(r) = instance.strip_prefix('[') {
        return r.split(']').next().unwrap_or(r);
    }
    match instance.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|c| c.is_ascii_digit()) => h,
        _ => instance,
    }
}

fn short(name: &str) -> &str {
    // An IP address has no short form.
    if name.split('.').all(|p| p.parse::<u8>().is_ok()) { name } else { name.split('.').next().unwrap_or(name) }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Disk {
    pub mount: String,
    pub size: f64,
    pub avail: f64,
    /// At the pace of the last hours it's full within four days.
    pub soon: bool,
}

impl Disk {
    pub fn used(&self) -> f64 {
        1.0 - self.avail / self.size.max(1.0)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Node {
    pub instance: String,
    /// What the machine calls itself.
    pub uname: String,
    /// The Kubernetes name, when Prometheus knows it.
    pub kube: Option<String>,
    pub cpu: Option<f64>,
    pub cores: f64,
    pub mem_total: f64,
    pub mem_avail: f64,
    pub load: Option<f64>,
    pub boot: Option<f64>,
    pub rx: Option<f64>,
    pub tx: Option<f64>,
    pub conntrack: Option<f64>,
    pub drops: Option<f64>,
    pub disks: Vec<Disk>,
    pub ready: Option<bool>,
    pub cordoned: bool,
    pub kubelet: String,
}

impl Node {
    pub fn mem(&self) -> Option<f64> {
        (self.mem_total > 0.0).then(|| 1.0 - self.mem_avail / self.mem_total)
    }
    pub fn disk(&self) -> Option<&Disk> {
        self.disks.iter().max_by(|a, b| a.used().partial_cmp(&b.used()).unwrap_or(std::cmp::Ordering::Equal))
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Data {
    pub nodes: Vec<Node>,
    /// Values of a `cluster` label, when there are several.
    pub clusters: Vec<String>,
}

/// Everything about the nodes now.
fn collect(label: &str, mut ask: impl FnMut(&str, &str) -> Result<Value, Fail>) -> Result<Data, Fail> {
    let mut got: HashMap<&'static str, Vec<(Labels, f64)>> = HashMap::new();
    for (k, q) in queries(label) {
        match ask(k, &q) {
            Ok(v) => {
                got.insert(k, samples(&v));
            }
            // Without the first there's nothing; the others add to it.
            Err(e) if k == "uname" || matches!(e, Fail::Login(_)) => return Err(e),
            Err(Fail::Other(e)) => return Err(Fail::Other(e)),
            Err(_) => {}
        }
    }
    let empty = vec![];
    let of = |k: &str| got.get(k).unwrap_or(&empty);
    let one = |k: &str, i: &str| of(k).iter().find(|s| lab(&s.0, "instance") == i).map(|s| s.1);
    let mut clusters: Vec<String> = of("uname").iter().map(|s| lab(&s.0, "cluster").to_string()).filter(|c| !c.is_empty()).collect();
    clusters.sort();
    clusters.dedup();
    let mut nodes: Vec<Node> = vec![];
    for (l, _) in of("uname") {
        let i = lab(l, "instance").to_string();
        if i.is_empty() || nodes.iter().any(|n| n.instance == i) {
            continue;
        }
        let uname = lab(l, "nodename").to_string();
        let info = of("info").iter().find(|s| lab(&s.0, "internal_ip") == host(&i)).or_else(|| of("info").iter().find(|s| !uname.is_empty() && short(lab(&s.0, "node")) == short(&uname)));
        let kube = info.map(|s| lab(&s.0, "node").to_string()).or_else(|| Some(lab(l, "node").to_string())).filter(|s| !s.is_empty());
        let by_node = |k: &str| kube.as_ref().and_then(|n| of(k).iter().find(|s| lab(&s.0, "node") == n).map(|s| s.1));
        nodes.push(Node {
            cpu: one("cpu", &i).map(|x| x.clamp(0.0, 1.0)),
            cores: one("cores", &i).unwrap_or(0.0),
            mem_total: one("mem_total", &i).unwrap_or(0.0),
            mem_avail: one("mem_avail", &i).unwrap_or(0.0),
            load: one("load", &i),
            boot: one("boot", &i),
            rx: one("rx", &i),
            tx: one("tx", &i),
            conntrack: one("conntrack", &i),
            drops: one("drops", &i),
            disks: disks(&i, of("fs_size"), of("fs_avail"), of("fs_soon")),
            ready: by_node("ready").map(|x| x > 0.5),
            cordoned: by_node("cordon").map(|x| x > 0.5).unwrap_or(false),
            kubelet: info.map(|s| lab(&s.0, "kubelet_version").to_string()).unwrap_or_default(),
            instance: i,
            uname,
            kube,
        });
    }
    nodes.sort_by(|a, b| a.uname.cmp(&b.uname).then(a.instance.cmp(&b.instance)));
    Ok(Data { nodes, clusters: if clusters.len() > 1 { clusters } else { vec![] } })
}

/// A machine's real disks: one per device (where it's mounted highest up), fullest first.
fn disks(instance: &str, size: &[(Labels, f64)], avail: &[(Labels, f64)], soon: &[(Labels, f64)]) -> Vec<Disk> {
    let mut by_dev: HashMap<&str, Disk> = HashMap::new();
    for (l, s) in size.iter().filter(|x| lab(&x.0, "instance") == instance && x.1 >= 1073741824.0) {
        let (dev, mount) = (lab(l, "device"), lab(l, "mountpoint"));
        let same = |x: &&(Labels, f64)| lab(&x.0, "instance") == instance && lab(&x.0, "device") == dev && lab(&x.0, "mountpoint") == mount;
        let Some(a) = avail.iter().find(same).map(|x| x.1) else { continue };
        let d = Disk { mount: mount.to_string(), size: *s, avail: a, soon: soon.iter().any(|x| same(&x)) };
        match by_dev.get(dev) {
            Some(old) if old.mount.len() <= d.mount.len() => {}
            _ => {
                by_dev.insert(dev, d);
            }
        }
    }
    let mut v: Vec<Disk> = by_dev.into_values().collect();
    v.sort_by(|a, b| b.used().partial_cmp(&a.used()).unwrap_or(std::cmp::Ordering::Equal).then(a.mount.cmp(&b.mount)));
    v
}

/// Which Kubernetes node a machine is, as seen from the pods: by its address, else by name.
fn pod_node<'a>(n: &Node, by_ip: &'a HashMap<String, String>, names: &'a HashSet<String>) -> Option<&'a str> {
    let h = host(&n.instance);
    if let Some(x) = by_ip.get(h) {
        return Some(x);
    }
    let cands: Vec<&str> = [n.kube.as_deref().unwrap_or(""), n.uname.as_str(), h].into_iter().filter(|c| !c.is_empty()).collect();
    if let Some(x) = cands.iter().find_map(|c| names.get(*c)) {
        return Some(x);
    }
    // Short names only when they say which one.
    let mut hits = names.iter().filter(|x| cands.iter().any(|c| short(c) == short(x)));
    match (hits.next(), hits.next()) {
        (Some(x), None) => Some(x),
        _ => None,
    }
}

pub(super) type Hist = HashMap<&'static str, HashMap<String, Vec<(i64, f64)>>>;

/// What came back.
pub(super) enum Answer {
    Now(Result<Data, Fail>),
    Hist(usize, Result<Hist, Fail>),
    Sources(Result<Vec<(String, String)>, Fail>),
}

// ---------- state ----------

#[derive(Default)]
pub(super) struct Graf {
    loading: bool,
    fetched: Option<Instant>,
    pub data: Option<Data>,
    fail: Option<Fail>,
    hist: HashMap<usize, (Instant, Hist)>,
    hist_loading: bool,
    sources: Option<Vec<(String, String)>>,
}

#[derive(Default)]
pub(super) struct Grafana {
    state: HashMap<String, Graf>,
    /// context -> (what it's for, the password or token). Memory only.
    secrets: HashMap<String, (String, Arc<Secret>)>,
    typed: HashMap<String, String>,
    /// The machine whose page is open: (context, instance).
    pub sel: Option<(String, String)>,
    window: Option<usize>,
    mem: bool,
    /// Settings being edited, and certificates to look at.
    edit: HashMap<String, Conf>,
    notes: HashMap<String, String>,
    path: HashMap<String, String>,
    paste: HashMap<String, String>,
    draft: HashMap<String, Draft>,
    open: Option<String>,
    confirm_off: Option<String>,
}

impl KubedogApp {
    pub(super) fn grafana_conf(&self, ctx: &str) -> Option<&Conf> {
        self.prefs.grafana.get(ctx).filter(|c| c.complete())
    }

    pub(super) fn has_grafana(&self) -> bool {
        self.active.iter().any(|c| self.grafana_conf(c).is_some())
    }

    /// The password typed for a cluster, if what it was typed for hasn't changed.
    fn grafana_secret(&self, ctx: &str) -> Option<Arc<Secret>> {
        if self.screenshot.is_some() {
            return std::env::var("KUBEDOG_SHOT_GRAFANA").ok().map(|_| Arc::new(Secret(String::new())));
        }
        let conf = self.prefs.grafana.get(ctx)?;
        self.grafana.secrets.get(ctx).filter(|s| s.0 == conf.binding()).map(|s| s.1.clone())
    }

    fn grafana_forget(&mut self, ctx: &str) {
        self.grafana.secrets.remove(ctx);
        self.grafana.typed.remove(ctx);
        self.grafana.state.remove(ctx);
    }

    /// Nodes as Grafana sees them, when they've been read, the cluster is clear, and some of the
    /// nodes the pods run on are among them (else it watches another cluster).
    pub(super) fn grafana_nodes(&self, ctx: &str) -> &[Node] {
        let Some(d) = self.grafana.state.get(ctx).and_then(|g| g.data.as_ref()).filter(|d| d.clusters.is_empty()) else { return &[] };
        let (ips, names) = self.pod_hosts(ctx);
        if d.nodes.iter().any(|n| pod_node(n, &ips, &names).is_some()) {
            &d.nodes
        } else {
            &[]
        }
    }

    fn grafana_spawn(&mut self, ctx: &str, f: impl FnOnce(&Client) -> Answer + Send + 'static, fail: impl FnOnce(Fail) -> Answer + Send + 'static) -> bool {
        let Some(conf) = self.prefs.grafana.get(ctx).cloned() else { return false };
        let Some(secret) = self.grafana_secret(ctx) else { return false };
        let ctx = ctx.to_string();
        self.spawn(move |_| {
            let binding = conf.binding();
            let what = match Client::new(&conf, &secret) {
                Ok(c) => f(&c),
                Err(e) => fail(e),
            };
            Msg::Grafana { ctx, binding, what: Box::new(what) }
        });
        true
    }

    /// Pages that show node figures from Grafana.
    fn wants_grafana(&self, ctx: &str) -> bool {
        match self.view {
            View::Observatory | View::NetLab => true,
            View::ClusterOverview | View::Resource(Kind::Nodes) => self.refused(ctx, Kind::Nodes),
            _ => false,
        }
    }

    pub(super) fn refresh_grafana(&mut self, force: bool) {
        if self.power_off("grafana") {
            return;
        }
        if self.demo {
            return;
        }
        for c in self.active.clone() {
            if self.grafana_conf(&c).map(|x| x.uid.is_empty()).unwrap_or(true) || !self.wants_grafana(&c) || self.grafana_secret(&c).is_none() {
                continue;
            }
            if self.screenshot.is_some() {
                self.grafana_canned(&c);
                continue;
            }
            let label = self.prefs.grafana.get(&c).map(|x| x.label.clone()).unwrap_or_default();
            let win = self.grafana.window.unwrap_or(2);
            let g = self.grafana.state.entry(c.clone()).or_default();
            // A refused login isn't tried again: that could lock the account.
            if matches!(g.fail, Some(Fail::Login(_))) || (matches!(g.fail, Some(Fail::Stop(_))) && !force) {
                continue;
            }
            let now = !g.loading && (force || g.fetched.map(|t| t.elapsed() >= Duration::from_secs(60)).unwrap_or(true));
            let hist = self.view == View::Observatory && !g.hist_loading && g.data.is_some() && g.hist.get(&win).map(|h| h.0.elapsed() >= Duration::from_secs(300)).unwrap_or(true);
            g.loading |= now;
            g.hist_loading |= hist;
            if now {
                let l = label.clone();
                self.grafana_spawn(&c, move |cl| Answer::Now(collect(&l, |_, q| cl.prom("query", &[("query", q)]))), |e| Answer::Now(Err(e)));
            }
            if hist {
                self.grafana_spawn(
                    &c,
                    move |cl| {
                        let (_, back, step, rate) = WINDOWS[win];
                        let end = kube::now_secs();
                        let (start, end, step) = ((end - back).to_string(), end.to_string(), step.to_string());
                        let mut out: Hist = HashMap::new();
                        for (k, q) in history_queries(&label, rate) {
                            match cl.prom("query_range", &[("query", &q), ("start", &start), ("end", &end), ("step", &step)]) {
                                Ok(v) => {
                                    out.insert(k, series(&v));
                                }
                                Err(e) => return Answer::Hist(win, Err(e)),
                            }
                        }
                        Answer::Hist(win, Ok(out))
                    },
                    move |e| Answer::Hist(win, Err(e)),
                );
            }
        }
    }

    /// Test aid for screenshots: answers from a file (KUBEDOG_SHOT_GRAFANA) instead of a Grafana.
    fn grafana_canned(&mut self, ctx: &str) {
        if self.grafana.state.get(ctx).map(|g| g.data.is_some()).unwrap_or(false) {
            return;
        }
        let v: Value = std::env::var("KUBEDOG_SHOT_GRAFANA").ok().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        let g = self.grafana.state.entry(ctx.to_string()).or_default();
        g.data = collect("", |k, _| Ok(v["now"][k].clone())).ok();
        g.fetched = Some(Instant::now());
        let hist: Hist = history_queries("", "5m").into_iter().map(|(k, _)| (k, series(&v["hist"][k]))).collect();
        for w in 0..WINDOWS.len() {
            g.hist.insert(w, (Instant::now(), hist.clone()));
        }
        if let Ok(i) = std::env::var("KUBEDOG_SHOT_OBJ") {
            self.grafana.sel = Some((ctx.to_string(), i));
        }
    }

    pub(super) fn on_grafana(&mut self, ctx: &str, binding: &str, what: Answer) {
        // Only for the server and login that are set now, and while logged in.
        let current = self.prefs.grafana.get(ctx).map(|c| c.binding() == binding).unwrap_or(false) && self.grafana.secrets.contains_key(ctx);
        if !current {
            return;
        }
        let g = self.grafana.state.entry(ctx.to_string()).or_default();
        let mut fail = None;
        match what {
            Answer::Now(r) => {
                g.loading = false;
                g.fetched = Some(Instant::now());
                match r {
                    Ok(d) => {
                        g.fail = None;
                        g.data = Some(d);
                    }
                    Err(e) => fail = Some(e),
                }
            }
            Answer::Hist(w, r) => {
                g.hist_loading = false;
                match r {
                    Ok(h) => {
                        g.hist.insert(w, (Instant::now(), h));
                    }
                    Err(e) => {
                        // Not again for a while.
                        g.hist.insert(w, (Instant::now(), HashMap::new()));
                        fail = Some(e);
                    }
                }
            }
            Answer::Sources(r) => {
                g.loading = false;
                match r {
                    Ok(list) => {
                        g.fail = None;
                        g.sources = Some(list.clone());
                        if let Some(c) = self.prefs.grafana.get_mut(ctx) {
                            if c.uid.is_empty() && !list.is_empty() {
                                c.uid = list[0].1.clone();
                                self.grafana.edit.insert(ctx.to_string(), c.clone());
                                self.save();
                            }
                        }
                    }
                    Err(e) => fail = Some(e),
                }
            }
        }
        if let Some(e) = fail {
            if matches!(e, Fail::Login(_)) {
                self.grafana.secrets.remove(ctx);
            }
            self.grafana.state.entry(ctx.to_string()).or_default().fail = Some(e);
        }
    }

    fn grafana_login(&mut self, ctx: &str) {
        let Some(conf) = self.prefs.grafana.get(ctx).cloned() else { return };
        let Some(typed) = self.grafana.typed.remove(ctx).filter(|t| !t.is_empty()) else { return };
        self.grafana.state.insert(ctx.to_string(), Graf { loading: true, ..Default::default() });
        self.grafana.secrets.insert(ctx.to_string(), (conf.binding(), Arc::new(Secret(typed))));
        // Listing the data sources also checks the login, once.
        self.grafana_spawn(ctx, |c| Answer::Sources(c.sources()), |e| Answer::Sources(Err(e)));
    }

    /// Where pods run: address -> node, and the nodes' names.
    fn pod_hosts(&self, ctx: &str) -> (HashMap<String, String>, HashSet<String>) {
        let (mut ips, mut names) = (HashMap::new(), HashSet::new());
        for p in self.lists.get(&Self::list_key(ctx, Kind::Pods)).map(|l| l.items.as_slice()).unwrap_or(&[]) {
            if let Some(n) = p["spec"]["nodeName"].as_str() {
                names.insert(n.to_string());
                if let Some(ip) = p["status"]["hostIP"].as_str() {
                    ips.insert(ip.to_string(), n.to_string());
                }
            }
        }
        (ips, names)
    }

    // ---------- pages ----------

    /// The password box of a cluster's Grafana.
    fn grafana_login_row(&mut self, ui: &mut Ui, ctx: &str) {
        let conf = self.prefs.grafana.get(ctx).cloned().unwrap_or_default();
        let g = self.grafana.state.get(ctx);
        let (busy, fail) = (g.map(|g| g.loading).unwrap_or(false), g.and_then(|g| g.fail.clone()));
        let mut go = false;
        ui.horizontal(|ui| {
            let what = if conf.token { "Service account token".to_string() } else { format!("Password of {}", conf.user) };
            ui.label(RichText::new(what).size(z(13.0)).color(TEXT_MUTED()));
            let typed = self.grafana.typed.entry(ctx.to_string()).or_default();
            let r = ui.add(egui::TextEdit::singleline(typed).password(true).desired_width(u(240.0)));
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            go = (button(ui, "Log in", true, false) || enter) && !typed.is_empty() && !busy;
            if busy {
                ui.spinner();
            }
        });
        ui.label(RichText::new("Asked once each time Kubedog runs. It's kept in memory only, sent to this address only, and a refused login isn't tried again by itself.").size(z(11.5)).color(TEXT_PLACEHOLDER()));
        if let Some(f) = fail {
            ui.add(egui::Label::new(RichText::new(f.text()).size(z(13.0)).color(DANGER())).wrap());
        }
        if go {
            self.grafana_login(ctx);
        }
    }

    /// The way to the settings, where nodes can't be read and no Grafana is set up.
    pub(super) fn grafana_hint(&mut self, ui: &mut Ui, ctx: &str) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("A Grafana that watches this cluster can show the nodes themselves.").size(z(12.5)).color(TEXT_SUBTLE()));
            if ui.link(RichText::new("Set it up").size(z(12.5))).clicked() {
                self.grafana.open = Some(ctx.to_string());
                self.settings_section = "Special monitoring";
                self.set_view(View::Settings);
            }
        });
    }

    pub(super) fn observatory_view(&mut self, ui: &mut Ui) {
        self.header(ui, false, Some("Nodes from Grafana".into()), true);
        let ctxs: Vec<String> = self.active.iter().filter(|c| self.ctx_shown(c) && self.grafana_conf(c).is_some()).cloned().collect();
        self.page_scroll().show(ui, |ui| {
            for c in &ctxs {
                self.grafana_board(ui, c);
                ui.add_space(20.0);
            }
        });
    }

    /// A cluster's nodes as Grafana sees them.
    pub(super) fn grafana_board(&mut self, ui: &mut Ui, ctx: &str) {
        let Some(conf) = self.grafana_conf(ctx).cloned() else { return };
        ui.add_space(6.0);
        if self.grafana_secret(ctx).is_none() {
            card(ui, |ui| {
                ui.label(RichText::new(format!("Nodes of {} from Grafana", ctx_label(ctx))).size(z(15.0)).strong().color(TEXT_DEFAULT()));
                ui.label(RichText::new(&conf.url).size(z(12.5)).color(TEXT_SUBTLE()));
                ui.add_space(6.0);
                self.grafana_login_row(ui, ctx);
            });
            return;
        }
        let mut out = false;
        ui.horizontal(|ui| {
            let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
            ui.painter().circle_filled(d.center(), 3.5, context_color(ctx));
            ui.label(RichText::new(ctx_label(ctx)).size(z(14.0)).color(TEXT_DEFAULT()));
            let host = conf.url.split("://").nth(1).unwrap_or(&conf.url);
            ui.label(RichText::new(format!("whole nodes, from Grafana at {host}")).size(z(12.0)).color(TEXT_SUBTLE()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                out = button(ui, "Log out", false, false);
                ui.label(RichText::new(if conf.token { "reading with a token".to_string() } else { format!("reading as {}", conf.user) }).size(z(12.0)).color(TEXT_SUBTLE()));
            });
        });
        ui.add_space(6.0);
        if out {
            self.grafana_forget(ctx);
            return;
        }
        let Some(g) = self.grafana.state.get(ctx) else { return };
        if let Some(f) = &g.fail {
            ui.add(egui::Label::new(RichText::new(f.text()).size(z(13.0)).color(WARNING())).wrap());
            ui.add_space(6.0);
        }
        let Some(data) = g.data.clone() else {
            if conf.uid.is_empty() {
                let none = g.sources.as_ref().map(|s| s.is_empty()).unwrap_or(false);
                ui.label(RichText::new(if none { "This account sees no Prometheus data source. Enter its uid in Settings > Special monitoring, if you know it." } else { "Choosing a data source…" }).color(TEXT_SUBTLE()));
            } else if g.fail.is_none() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Asking Grafana…").color(TEXT_SUBTLE()));
                });
            }
            return;
        };
        if !data.clusters.is_empty() {
            ui.label(RichText::new("This data source watches several clusters. Which one is this?").color(WARNING()));
            let mut pick = None;
            ui.horizontal_wrapped(|ui| {
                for c in &data.clusters {
                    if button(ui, c, false, false) {
                        pick = check_label(&format!("cluster=\"{c}\"")).ok();
                    }
                }
            });
            if let Some(l) = pick {
                if let Some(c) = self.prefs.grafana.get_mut(ctx) {
                    c.label = l;
                    self.grafana.edit.remove(ctx);
                }
                self.save();
                self.grafana.state.remove(ctx);
                self.refresh_current(true);
            }
            return;
        }
        if data.nodes.is_empty() {
            ui.add(egui::Label::new(RichText::new(format!("No node figures found (no node_uname_info{}). Is this the data source with the node exporter's data?", if conf.label.is_empty() { String::new() } else { format!(" with {}", conf.label) })).color(WARNING())).wrap());
            return;
        }
        // Is it really this cluster?
        let (ips, names) = self.pod_hosts(ctx);
        let known: Vec<Option<String>> = data.nodes.iter().map(|n| pod_node(n, &ips, &names).map(String::from)).collect();
        let found = known.iter().flatten().collect::<HashSet<_>>().len();
        if !names.is_empty() {
            if found == 0 {
                Frame::new().fill(WARN_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(8)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(egui::Label::new(RichText::new(format!("None of the {} nodes your pods run on is among these {}: this looks like another cluster.", names.len(), data.nodes.len())).color(WARNING())).wrap());
                });
            } else {
                ui.label(RichText::new(format!("{found} of the {} nodes your pods run on are among these {}. Nodes without your pods can't be confirmed to be in this cluster.", names.len(), data.nodes.len())).size(z(12.0)).color(if found == names.len() { TEXT_SUBTLE() } else { WARNING() }));
            }
            ui.add_space(8.0);
        }
        if let Some(i) = self.grafana.sel.clone().filter(|s| s.0 == ctx).and_then(|s| data.nodes.iter().position(|n| n.instance == s.1 || known_name(n, None) == s.1)) {
            self.grafana_node_page(ui, ctx, &data.nodes[i], known[i].as_deref());
            return;
        }
        let search = self.search.to_lowercase();
        let shown: Vec<usize> = (0..data.nodes.len()).filter(|i| search.is_empty() || known_name(&data.nodes[*i], known[*i].as_deref()).to_lowercase().contains(&search) || data.nodes[*i].instance.contains(&search)).collect();
        let nodes: Vec<(&Node, String, bool)> = shown.iter().map(|i| (&data.nodes[*i], known_name(&data.nodes[*i], known[*i].as_deref()), known[*i].is_some())).collect();
        graf_tiles(ui, &data.nodes);
        ui.add_space(14.0);
        let mut open = graf_cards(ui, &nodes);
        open = graf_trouble(ui, &nodes).or(open);
        if self.view == View::Observatory {
            open = self.grafana_timeline(ui, ctx, &nodes).or(open);
        }
        if let Some(i) = open {
            self.grafana.sel = Some((ctx.to_string(), i));
            if self.view != View::Observatory {
                self.navigate(View::Observatory, None);
            }
            self.refresh_current(false);
        }
    }

    fn grafana_window(&mut self, ui: &mut Ui) {
        let cur = self.grafana.window.unwrap_or(2);
        for (i, w) in WINDOWS.iter().enumerate() {
            if ui.selectable_label(cur == i, w.0).clicked() && cur != i {
                self.grafana.window = Some(i);
                self.refresh_grafana(false);
            }
        }
    }

    /// Every node over time, as a band of colours.
    fn grafana_timeline(&mut self, ui: &mut Ui, ctx: &str, nodes: &[(&Node, String, bool)]) -> Option<String> {
        let mut open = None;
        ui.add_space(22.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Over time").size(z(17.0)).color(TEXT_DEFAULT()));
            ui.add_space(8.0);
            for (mem, t) in [(false, "CPU"), (true, "Memory")] {
                if ui.selectable_label(self.grafana.mem == mem, t).clicked() {
                    self.grafana.mem = mem;
                }
            }
            ui.add_space(14.0);
            self.grafana_window(ui);
        });
        ui.add_space(6.0);
        let win = self.grafana.window.unwrap_or(2);
        let g = self.grafana.state.get(ctx)?;
        let Some((_, h)) = g.hist.get(&win) else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Reading the history…").color(TEXT_SUBTLE()));
            });
            return None;
        };
        let empty = HashMap::new();
        let s = h.get(if self.grafana.mem { "mem" } else { "cpu" }).unwrap_or(&empty);
        let (_, back, step, _) = WINDOWS[win];
        let end = s.values().filter_map(|v| v.last().map(|p| p.0)).max();
        let Some(end) = end else {
            ui.label(RichText::new("No data for this time.").color(TEXT_SUBTLE()));
            return None;
        };
        let first = s.values().filter_map(|v| v.first().map(|p| p.0)).min().unwrap_or(end);
        let start = end - back;
        card(ui, |ui| {
            let (lw, rh) = (u(190.0).min(ui.available_width() * 0.28), u(24.0));
            let (area, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), rh * nodes.len() as f32 + u(20.0)), Sense::click());
            let p = ui.painter();
            let x0 = area.left() + lw;
            let w = area.right() - x0;
            let cw = w * step as f32 / back as f32;
            let hover = resp.hover_pos();
            let mut tip = None;
            for (i, (n, name, _)) in nodes.iter().enumerate() {
                let y = area.top() + rh * i as f32;
                label_at(ui, p, egui::pos2(area.left(), y + rh / 2.0), name, 12.5, PRIMARY_TEXT(), lw - 10.0);
                p.rect_filled(egui::Rect::from_min_size(egui::pos2(x0, y + 1.5), egui::vec2(w, rh - 3.0)), CornerRadius::ZERO, BG_MUTED());
                for (t, v) in s.get(&n.instance).into_iter().flatten().filter(|p| p.0 >= start) {
                    let x = x0 + w * (t - start) as f32 / back as f32;
                    let r = egui::Rect::from_min_size(egui::pos2((x - cw).max(x0), y + 1.5), egui::vec2(cw + 0.6, rh - 3.0));
                    p.rect_filled(r, CornerRadius::ZERO, hive::heat(*v));
                    if hover.map(|q| r.contains(q)).unwrap_or(false) {
                        tip = Some(format!("{name}\n{:.0}% {}", v * 100.0, ago(end - t)));
                    }
                }
                if resp.clicked() && hover.map(|q| q.y >= y && q.y < y + rh).unwrap_or(false) {
                    open = Some(n.instance.clone());
                }
            }
            for k in 0..=4 {
                let x = x0 + w * k as f32 / 4.0;
                let t = back - back * k / 4;
                let al = match k { 0 => egui::Align2::LEFT_BOTTOM, 4 => egui::Align2::RIGHT_BOTTOM, _ => egui::Align2::CENTER_BOTTOM };
                p.text(egui::pos2(x, area.bottom()), al, if t == 0 { "now".to_string() } else { format!("{} ago", kube::human_duration(t)) }, FontId::proportional(z(11.0)), TEXT_PLACEHOLDER());
            }
            let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
            if let Some(t) = tip {
                resp.on_hover_text_at_pointer(t);
            }
            if first > start + back / 10 {
                ui.label(RichText::new(format!("Grafana has nothing from before {} ago.", kube::human_duration(end - first))).size(z(11.5)).color(TEXT_PLACEHOLDER()));
            }
        });
        open
    }

    /// One machine: gauges, its disks, and its history.
    fn grafana_node_page(&mut self, ui: &mut Ui, ctx: &str, n: &Node, pod_name: Option<&str>) {
        let mut close = ui.input(|i| i.key_pressed(Key::Escape)) && self.dialog.is_none() && self.palette.is_none();
        ui.horizontal(|ui| {
            close |= back_button(ui).on_hover_text("All nodes (Esc)").clicked();
            ui.label(RichText::new(known_name(n, pod_name)).size(z(20.0)).color(TEXT_DEFAULT()));
            pg::pill(ui, host(&n.instance), INFO());
            if let Some(r) = n.ready {
                pg::pill(ui, if r { "Ready" } else { "Not ready" }, if r { SUCCESS() } else { DANGER() });
            }
            if n.cordoned {
                pg::pill(ui, "Cordoned", WARNING());
            }
            if !n.kubelet.is_empty() {
                ui.label(RichText::new(&n.kubelet).size(z(12.0)).color(TEXT_SUBTLE()));
            }
            self.ai_corner(ui, false);
        });
        if close {
            self.grafana.sel = None;
            return;
        }
        ui.add_space(8.0);
        graf_cards(ui, &[(n, known_name(n, pod_name), pod_name.is_some())]);
        let win = self.grafana.window.unwrap_or(2);
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("History").size(z(17.0)).color(TEXT_DEFAULT()));
            ui.add_space(8.0);
            self.grafana_window(ui);
        });
        let hist = self.grafana.state.get(ctx).and_then(|g| g.hist.get(&win));
        if hist.is_none() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Reading the history…").color(TEXT_SUBTLE()));
            });
        }
        if let Some((_, h)) = hist {
            let vals = |k: &str| -> Vec<f64> { h.get(k).and_then(|s| s.get(&n.instance)).map(|v| v.iter().map(|p| p.1).collect()).unwrap_or_default() };
            let pct = |x: f64| format!("{:.0}%", x * 100.0);
            let per = |x: f64| format!("{}/s", pg::bytes(x));
            let plot = |ui: &mut Ui, v: Vec<f64>, col: Color32, fmt: &dyn Fn(f64) -> String| {
                if v.len() < 2 {
                    nothing(ui, u(90.0), "No data for this time.", TEXT_SUBTLE());
                } else {
                    spark(ui, &v, u(90.0), col, fmt);
                }
            };
            let ph = u(94.0);
            ui.add_space(-16.0);
            pair(ui, &mut (), ("CPU", ph), ("Memory", ph), |ui, _| plot(ui, vals("cpu"), CPU_BAR(), &pct), |ui, _| plot(ui, vals("mem"), MEM_BAR(), &pct));
            pair(ui, &mut (), ("Received, busiest link", ph), ("Sent, busiest link", ph), |ui, _| plot(ui, vals("rx"), INFO(), &per), |ui, _| plot(ui, vals("tx"), PRIMARY_TEXT(), &per));
        }
        let mine: Vec<(String, String)> = match pod_name {
            Some(name) => self.lists.get(&Self::list_key(ctx, Kind::Pods)).map(|l| l.items.iter().filter(|p| p["spec"]["nodeName"].as_str() == Some(name) && p["status"]["phase"] == "Running").map(|p| (p["metadata"]["namespace"].as_str().unwrap_or("").to_string(), p["metadata"]["name"].as_str().unwrap_or("").to_string())).collect()).unwrap_or_default(),
            None => vec![],
        };
        let lh = u(27.0);
        let mut go: Option<Selected> = None;
        let mut hive = false;
        let disks = n.disks.clone();
        let usage = self.metrics.get(ctx);
        pair(
            ui,
            &mut (&mut go, &mut hive),
            ("Disks", lh * disks.len().clamp(1, 10) as f32),
            ("Your pods here", lh * mine.len().clamp(1, 10) as f32),
            |ui, _| {
                if disks.is_empty() {
                    nothing(ui, lh, "No disks reported.", TEXT_SUBTLE());
                }
                for d in disks.iter().take(10) {
                    let (r, _) = line(ui, lh, false);
                    let col = if d.used() >= 0.9 { DANGER() } else if d.used() >= 0.8 || d.soon { WARNING() } else { SUCCESS() };
                    at(ui, r, 0.0, 0.3, &d.mount, 12.5, TEXT_DEFAULT());
                    bar(ui, r, 0.31, 0.3, d.used(), col);
                    at_end(ui, r, 1.0, &format!("{:.0}% of {}{}", d.used() * 100.0, pg::bytes(d.size), if d.soon { ", full within 4 days" } else { "" }), 12.0, if d.soon { WARNING() } else { TEXT_MUTED() });
                }
            },
            |ui, st| {
                if mine.is_empty() {
                    nothing(ui, lh, if pod_name.is_some() { "None running." } else { "None of your pods run on it." }, TEXT_SUBTLE());
                }
                for (ns, name) in mine.iter().take(9) {
                    let (r, resp) = line(ui, lh, true);
                    at(ui, r, 0.0, 0.7, &format!("{ns}/{name}"), 12.5, PRIMARY_TEXT());
                    if let Some(x) = usage.and_then(|m| m.pods.get(&(ns.clone(), name.clone()))) {
                        at_end(ui, r, 1.0, &format!("{}  ·  {}", hive::cores(x.0), gib(x.1)), 12.0, TEXT_MUTED());
                    }
                    if resp.clicked() {
                        *st.0 = Some(Selected { ctx: ctx.to_string(), kind: Kind::Pods, ns: ns.clone(), name: name.clone() });
                    }
                }
                if mine.len() > 9 {
                    let (r, resp) = line(ui, lh, true);
                    at(ui, r, 0.0, 1.0, &format!("all {} in the hive", mine.len()), 12.5, PRIMARY_TEXT());
                    *st.1 = resp.clicked();
                }
            },
        );
        if let Some(s) = go {
            self.navigate(View::Resource(Kind::Pods), Some(s));
        } else if hive {
            self.open_hive(pod_name.map(String::from));
        }
    }

    // ---------- settings ----------

    pub(super) fn settings_monitoring(&mut self, ui: &mut Ui) {
        settings::title(ui, "Special monitoring", "Optional. Other systems that know more about your clusters than your own account may see. For now that's Grafana.");
        card(ui, |ui| {
            pg::panel(ui, "Grafana", "for nodes your account may not read, and for their history");
            let para = |ui: &mut Ui, t: &str| {
                ui.add(egui::Label::new(RichText::new(t).size(z(13.0)).color(TEXT_MUTED())).wrap());
            };
            let head = |ui: &mut Ui, t: &str| {
                ui.add_space(8.0);
                ui.label(RichText::new(t).size(z(13.5)).color(TEXT_DEFAULT()));
            };
            head(ui, "What you get");
            para(ui, "A page Nodes (Grafana) under Superpowers: CPU, memory, disk and network of the machines your cluster runs on, now and over time. It also works when your account is limited to a few namespaces.");
            head(ui, "What you need");
            para(ui, "•  A Grafana that watches the cluster's machines, and that this computer can reach.");
            para(ui, "•  In it a Prometheus data source with the node exporter's figures (they begin with node_).");
            para(ui, "•  A login that may look: a service account token with the role Viewer is best; your own name and password work too. Check that you may use it this way.");
            head(ui, "What to do");
            para(ui, "1.  In Grafana: Administration > Users and access > Service accounts > Add service account, role Viewer. Then Add service account token, and copy it.");
            para(ui, "2.  Below, at your cluster: Use a Grafana. Enter its address, such as https://grafana.example.com, and choose Service account token.");
            para(ui, "3.  If your company signs its own certificates, add its certificate authority.");
            para(ui, "4.  Paste the token and log in. It's kept in memory only, so it's asked for again the next time you start Kubedog.");
            para(ui, "5.  Choose the data source. If it watches several clusters, narrow it with a label, such as cluster=\"prod\".");
            para(ui, "6.  Open the nodes. Kubedog only reads from Grafana.");
        });
        ui.add_space(14.0);
        ui.label(RichText::new("Per cluster").size(z(15.0)).strong().color(TEXT_DEFAULT()));
        ui.add_space(6.0);
        let ctxs: Vec<String> = self.contexts.iter().map(|c| c.name.clone()).collect();
        if ctxs.is_empty() {
            ui.label(RichText::new("No clusters yet.").color(TEXT_SUBTLE()));
        }
        if self.screenshot.is_some() && self.grafana.open.is_none() {
            self.grafana.open = self.prefs.grafana.keys().next().cloned();
        }
        for c in ctxs {
            self.grafana_settings_card(ui, &c);
            ui.add_space(10.0);
        }
    }

    fn grafana_settings_card(&mut self, ui: &mut Ui, ctx: &str) {
        let set = self.prefs.grafana.get(ctx).cloned();
        let open = self.grafana.open.as_deref() == Some(ctx);
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
                ui.painter().circle_filled(d.center(), 3.5, context_color(ctx));
                ui.label(RichText::new(ctx_label(ctx)).size(z(14.5)).color(TEXT_DEFAULT())).on_hover_text(ctx);
                let state = match &set {
                    None => "off".to_string(),
                    Some(c) if c.url.is_empty() => "not filled in yet".into(),
                    Some(c) => c.url.clone(),
                };
                ui.label(RichText::new(state).size(z(12.5)).color(TEXT_SUBTLE()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if button(ui, if open { "Close" } else if set.is_some() { "Change" } else { "Use a Grafana" }, false, false) {
                        self.grafana.open = if open { None } else { Some(ctx.to_string()) };
                    }
                    if set.is_some() && open {
                        if self.grafana.confirm_off.as_deref() == Some(ctx) {
                            if button(ui, "Really turn off", false, true) {
                                self.prefs.grafana.remove(ctx);
                                self.grafana.edit.remove(ctx);
                                self.grafana.confirm_off = None;
                                self.grafana.open = None;
                                self.grafana_forget(ctx);
                                self.save();
                            }
                        } else if button(ui, "Turn off", false, false) {
                            self.grafana.confirm_off = Some(ctx.to_string());
                        }
                    }
                });
            });
            if open {
                ui.add_space(8.0);
                self.grafana_form(ui, ctx);
            }
        });
    }

    fn grafana_form(&mut self, ui: &mut Ui, ctx: &str) {
        let saved = self.prefs.grafana.get(ctx).cloned().unwrap_or_default();
        let mut e = self.grafana.edit.remove(ctx).unwrap_or_else(|| saved.clone());
        let mut done = false;
        let field = |ui: &mut Ui, label: &str, add: &mut dyn FnMut(&mut Ui)| {
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(u(150.0), u(24.0)), Sense::hover());
                label_at(ui, ui.painter(), r.left_center(), label, 13.0, TEXT_MUTED(), r.width());
                add(ui);
            });
        };
        let hint = |ui: &mut Ui, t: &str, col: Color32| {
            ui.horizontal(|ui| {
                ui.add_space(u(150.0) + 8.0);
                ui.add(egui::Label::new(RichText::new(t).size(z(11.5)).color(col)).wrap());
            });
        };
        field(ui, "Address", &mut |ui| done |= ui.add(egui::TextEdit::singleline(&mut e.url).hint_text("https://grafana.example.com").desired_width(u(420.0))).lost_focus());
        if !e.url.is_empty() {
            if let Err(t) = check_url(&e.url) {
                hint(ui, &t, WARNING());
            }
        }
        field(ui, "Log in with", &mut |ui| {
            done |= ui.radio_value(&mut e.token, false, "Password").changed();
            done |= ui.radio_value(&mut e.token, true, "Service account token").changed();
        });
        if !e.token {
            field(ui, "User name", &mut |ui| done |= ui.add(egui::TextEdit::singleline(&mut e.user).desired_width(u(240.0))).lost_focus());
        } else {
            hint(ui, "A token with the Viewer role is enough, and safer than your own password.", TEXT_PLACEHOLDER());
        }
        let sources = self.grafana.state.get(ctx).and_then(|g| g.sources.clone()).unwrap_or_default();
        field(ui, "Data source", &mut |ui| {
            if !sources.is_empty() {
                let cur = sources.iter().find(|s| s.1 == e.uid).map(|s| s.0.clone()).unwrap_or_else(|| "choose".into());
                egui::ComboBox::from_id_salt(("graf-ds", ctx)).selected_text(cur).width(u(200.0)).show_ui(ui, |ui| {
                    for (n, uid) in &sources {
                        done |= ui.selectable_value(&mut e.uid, uid.clone(), n).changed();
                    }
                });
            }
            done |= ui.add(egui::TextEdit::singleline(&mut e.uid).hint_text("its uid, found after logging in").desired_width(u(240.0))).lost_focus();
        });
        field(ui, "Only this label", &mut |ui| done |= ui.add(egui::TextEdit::singleline(&mut e.label).hint_text("optional, like cluster=\"prod\"").desired_width(u(240.0))).lost_focus());
        if let Err(t) = check_label(&e.label) {
            hint(ui, &t, WARNING());
        }
        ui.add_space(6.0);
        done |= self.grafana_ca(ui, ctx, &mut e);
        // Save what's valid once a field is left.
        if done {
            e.user = e.user.trim().to_string();
            e.uid = e.uid.trim().to_string();
            let mut ok = e.clone();
            ok.url = match check_url(&e.url) {
                Ok(x) => x,
                Err(_) => saved.url.clone(),
            };
            ok.label = check_label(&e.label).unwrap_or_else(|_| saved.label.clone());
            if check_url(&e.url).is_ok() {
                e.url = ok.url.clone();
            }
            if ok != saved {
                if ok.binding() != saved.binding() {
                    self.grafana_forget(ctx);
                } else if let Some(g) = self.grafana.state.get_mut(ctx) {
                    *g = Graf { sources: g.sources.take(), ..Default::default() };
                }
                self.prefs.grafana.insert(ctx.to_string(), ok);
                self.save();
            }
        }
        self.grafana.edit.insert(ctx.to_string(), e);
        ui.add_space(8.0);
        if self.grafana_conf(ctx).is_some() {
            if self.grafana_secret(ctx).is_some() {
                let g = self.grafana.state.get(ctx);
                let (busy, fail, n) = (g.map(|g| g.loading).unwrap_or(false), g.and_then(|g| g.fail.clone()), g.and_then(|g| g.sources.as_ref().map(|s| s.len())));
                let mut out = false;
                let mut go = false;
                ui.horizontal(|ui| {
                    if busy {
                        ui.spinner();
                    }
                    match (&fail, n) {
                        (Some(f), _) => {
                            ui.label(RichText::new(f.text()).color(DANGER()));
                        }
                        (None, Some(n)) => {
                            ui.label(RichText::new(format!("Logged in; {n} Prometheus data source{}", if n == 1 { "" } else { "s" })).color(SUCCESS()));
                        }
                        _ => {}
                    }
                    out = button(ui, "Log out", false, false);
                    go = self.connected && self.active.iter().any(|c| c == ctx) && button(ui, "Open the nodes", true, false);
                });
                if out {
                    self.grafana_forget(ctx);
                } else if go {
                    self.set_view(View::Observatory);
                }
            } else {
                self.grafana_login_row(ui, ctx);
            }
        }
    }

    /// The certificate authority part of the form. Returns whether it changed.
    pub(super) fn grafana_ca(&mut self, ui: &mut Ui, ctx: &str, e: &mut Conf) -> bool {
        let mut changed = false;
        ui.label(RichText::new("Certificate authority").size(z(13.5)).color(TEXT_DEFAULT()));
        ui.add(egui::Label::new(RichText::new("Needed when the certificate is signed by your own authority. It's only used for this server. A .pem, .crt or .cer file, chains too; never a private key.").size(z(11.5)).color(TEXT_PLACEHOLDER())).wrap());
        ui.add_space(4.0);
        if !e.ca.is_empty() {
            let list = read_ca(e.ca.as_bytes()).map(|d| d.certs).unwrap_or_default();
            show_certs(ui, &list);
            if button(ui, "Remove (use this computer's own list)", false, false) {
                e.ca.clear();
                changed = true;
            }
            ui.add_space(4.0);
        }
        let mut bytes: Option<Result<Vec<u8>, String>> = None;
        ui.horizontal(|ui| {
            let path = self.grafana.path.entry(ctx.to_string()).or_default();
            let r = ui.add(egui::TextEdit::singleline(path).hint_text("path of the file, or drop it on this window").desired_width(u(380.0)));
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            if (button(ui, "Read file", false, false) || enter) && !path.trim().is_empty() {
                let p = path.trim().trim_matches('"').to_string();
                let p = match p.strip_prefix("~/") {
                    Some(rest) => std::env::var("HOME").map(|h| format!("{h}/{rest}")).unwrap_or(p),
                    None => p,
                };
                bytes = Some(read_small(std::path::Path::new(&p)));
            }
            let pasting = self.grafana.paste.contains_key(ctx);
            if button(ui, if pasting { "Cancel" } else { "Paste text" }, false, false) {
                if pasting {
                    self.grafana.paste.remove(ctx);
                } else {
                    self.grafana.paste.insert(ctx.to_string(), String::new());
                }
            }
        });
        if let Some(text) = self.grafana.paste.get_mut(ctx) {
            ui.add(egui::TextEdit::multiline(text).hint_text("-----BEGIN CERTIFICATE-----").font(egui::TextStyle::Monospace).desired_rows(5).desired_width(u(560.0)));
            if button(ui, "Read this", false, false) && !text.trim().is_empty() {
                bytes = Some(Ok(text.clone().into_bytes()));
            }
        }
        for f in ui.input(|i| i.raw.dropped_files.clone()) {
            bytes = Some(read_small(f.path()));
        }
        if let Some(b) = bytes {
            match b.and_then(|b| read_ca(&b)) {
                Ok(d) => {
                    self.grafana.draft.insert(ctx.to_string(), d);
                    self.grafana.notes.remove(ctx);
                    self.grafana.paste.remove(ctx);
                }
                Err(t) => {
                    // A private key isn't kept around.
                    self.grafana.paste.remove(ctx);
                    self.grafana.draft.remove(ctx);
                    self.grafana.notes.insert(ctx.to_string(), t);
                }
            }
        }
        if let Some(t) = self.grafana.notes.get(ctx) {
            ui.add(egui::Label::new(RichText::new(t).color(WARNING())).wrap());
        }
        if let Some(d) = self.grafana.draft.get(ctx).cloned() {
            ui.add_space(6.0);
            Frame::new().stroke(Stroke::new(1.0, WARNING())).corner_radius(CornerRadius::same(8)).inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Trust this for this Grafana?").strong().color(TEXT_DEFAULT()));
                ui.add(egui::Label::new(RichText::new("Compare the fingerprint with what your company publishes.").size(z(12.0)).color(TEXT_SUBTLE())).wrap());
                show_certs(ui, &d.certs);
                let now = kube::now_secs();
                if d.certs.iter().all(|c| c.0.not_after.map(|t| t < now).unwrap_or(false)) {
                    ui.label(RichText::new("It has expired, so it won't work.").color(WARNING()));
                } else if !d.certs.iter().any(|c| c.0.is_ca) {
                    ui.label(RichText::new("None of these is a certificate authority, so it may not work.").color(WARNING()));
                }
                ui.horizontal(|ui| {
                    if button(ui, "Trust", true, false) {
                        e.ca = d.pem.clone();
                        changed = true;
                        self.grafana.draft.remove(ctx);
                    }
                    if button(ui, "Cancel", false, false) {
                        self.grafana.draft.remove(ctx);
                    }
                });
            });
        }
        changed
    }
}

fn read_small(p: &std::path::Path) -> Result<Vec<u8>, String> {
    match std::fs::metadata(p) {
        Ok(m) if !m.is_file() => Err("That isn't a file.".into()),
        Ok(m) if m.len() > 2_000_000 => Err("That's too big for certificates.".into()),
        Ok(_) => std::fs::read(p).map_err(|e| format!("Couldn't read it: {e}")),
        Err(_) => Err("There's no such file.".into()),
    }
}

fn show_certs(ui: &mut Ui, list: &[(certs::CertInfo, String)]) {
    let now = kube::now_secs();
    if list.len() > 6 {
        ui.label(RichText::new(format!("{} certificates; each of them may vouch for this server.", list.len())).size(z(12.5)).color(TEXT_MUTED()));
    }
    for (c, f) in list.iter().take(6) {
        let (word, tone) = certs::verdict(c, now);
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(&c.subject_full).size(z(13.0)).color(TEXT_DEFAULT()));
            ui.label(RichText::new(word).size(z(12.0)).color(tone_color(tone)));
            if let Some(t) = c.not_after {
                ui.label(RichText::new(format!("until {}", netmap::iso_date(t))).size(z(12.0)).color(TEXT_SUBTLE()));
            }
        });
        if c.issuer_full != c.subject_full {
            ui.label(RichText::new(format!("signed by {}", c.issuer_full)).size(z(12.0)).color(TEXT_SUBTLE()));
        }
        ui.add(egui::Label::new(RichText::new(format!("SHA-256 {f}")).monospace().size(z(11.0)).color(TEXT_SUBTLE())).wrap());
    }
    ui.add_space(4.0);
}

// ---------- drawing ----------

use super::dash::{at, at_end, bar, grid, line, nothing, pair, tile};
use super::pg::{label_at, spark};

fn ago(s: i64) -> String {
    if s < 60 { "now".into() } else { format!("{} ago", kube::human_duration(s)) }
}

fn known_name(n: &Node, pod: Option<&str>) -> String {
    pod.map(String::from).or_else(|| n.kube.clone()).filter(|s| !s.is_empty()).unwrap_or_else(|| if n.uname.is_empty() { n.instance.clone() } else { n.uname.clone() })
}

fn level(f: f64) -> Color32 {
    if f >= 0.9 {
        DANGER()
    } else if f >= 0.8 {
        WARNING()
    } else {
        SUCCESS()
    }
}

fn graf_tiles(ui: &mut Ui, nodes: &[Node]) {
    let sum = |f: &dyn Fn(&Node) -> f64| nodes.iter().map(f).fold(0.0, |a, b| a + b);
    let cores = sum(&|n| n.cores);
    let used = sum(&|n| n.cpu.unwrap_or(0.0) * n.cores);
    let (mt, ma) = (sum(&|n| n.mem_total), sum(&|n| n.mem_avail));
    let ready = nodes.iter().filter(|n| n.ready == Some(true)).count();
    let known = nodes.iter().any(|n| n.ready.is_some());
    let full = nodes.iter().filter_map(|n| n.disk().map(|d| (d.used(), n, d))).fold(None::<(f64, &Node, &Disk)>, |a, b| if a.map(|a| a.0 >= b.0).unwrap_or(false) { a } else { Some(b) });
    let (rx, tx) = (sum(&|n| n.rx.unwrap_or(0.0)), sum(&|n| n.tx.unwrap_or(0.0)));
    let frac = |a: f64, b: f64| if b > 0.0 { a / b } else { 0.0 };
    let tiles: Vec<(&str, String, String, Color32)> = vec![
        ("Nodes", if known { format!("{ready}/{}", nodes.len()) } else { nodes.len().to_string() }, if !known { "readiness isn't known here".into() } else if ready == nodes.len() { "all ready".into() } else { format!("{} not ready", nodes.len() - ready) }, if known && ready < nodes.len() { DANGER() } else { SUCCESS() }),
        ("CPU in use", if cores > 0.0 { format!("{:.0}%", frac(used, cores) * 100.0) } else { "–".into() }, format!("{used:.1} of {cores:.0} cores"), level(frac(used, cores))),
        ("Memory in use", if mt > 0.0 { format!("{:.0}%", frac(mt - ma, mt) * 100.0) } else { "–".into() }, format!("{} of {}", gib(mt - ma), gib(mt)), level(frac(mt - ma, mt))),
        ("Fullest disk", full.map(|f| format!("{:.0}%", f.0 * 100.0)).unwrap_or("–".into()), full.map(|f| format!("{} on {}", f.2.mount, known_name(f.1, None))).unwrap_or_default(), level(full.map(|f| f.0).unwrap_or(0.0))),
        ("Network", format!("{}/s", pg::bytes(rx + tx)), format!("in {}/s, out {}/s", pg::bytes(rx), pg::bytes(tx)), PRIMARY_TEXT()),
    ];
    grid(ui, tiles.len(), u(170.0), u(100.0), 14.0, |ui, i, r| {
        let t = &tiles[i];
        tile(ui, r, t.0, &t.1, &t.2, t.3);
    });
}

/// A card per machine. Returns the instance clicked.
fn graf_cards(ui: &mut Ui, nodes: &[(&Node, String, bool)]) -> Option<String> {
    let mut open = None;
    let now = kube::now_secs() as f64;
    grid(ui, nodes.len(), u(300.0), u(158.0), 12.0, |ui, i, r| {
        let (n, name, mine) = &nodes[i];
        let resp = ui.interact(r, egui::Id::new(("graf-node", &n.instance)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
        let p = ui.painter().clone();
        let bad = n.ready == Some(false);
        p.rect_filled(r, CornerRadius::same(10), if resp.hovered() { BG_HOVER() } else { BG_CARD() });
        p.rect_stroke(r, CornerRadius::same(10), Stroke::new(if bad { 2.0 } else { 1.0 }, if bad { DANGER() } else if resp.hovered() { PRIMARY_TEXT() } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
        let top = r.top() + u(19.0);
        p.circle_filled(egui::pos2(r.left() + 18.0, top), u(4.0), match n.ready { Some(true) => SUCCESS(), Some(false) => DANGER(), None => TEXT_PLACEHOLDER() });
        let note = if bad { "not ready" } else if n.cordoned { "cordoned" } else if *mine { "your pods" } else { "" };
        let g = p.layout_no_wrap(note.to_string(), FontId::proportional(z(11.0)), if bad { DANGER() } else if n.cordoned { WARNING() } else { TEXT_PLACEHOLDER() });
        let gw = g.size().x;
        p.galley(egui::pos2(r.right() - 14.0 - gw, top - g.size().y / 2.0), g, TEXT_PLACEHOLDER());
        label_at(ui, &p, egui::pos2(r.left() + 30.0, top), name, 13.5, TEXT_DEFAULT(), r.width() - 56.0 - gw);
        let disk = n.disk();
        for (k, (label, v, col)) in [("CPU", n.cpu, CPU_BAR()), ("Memory", n.mem(), MEM_BAR()), ("Disk", disk.map(|d| d.used()), INFO())].into_iter().enumerate() {
            let c = egui::pos2(r.left() + r.width() * (0.18 + 0.32 * k as f32), r.top() + u(72.0));
            let rad = u(27.0);
            p.circle_stroke(c, rad, Stroke::new(u(6.5), BG_MUTED()));
            if let Some(v) = v {
                let sweep = v.clamp(0.0, 1.0) as f32 * std::f32::consts::TAU;
                let pts: Vec<egui::Pos2> = (0..=48).map(|s| {
                    let a = -std::f32::consts::FRAC_PI_2 + sweep * s as f32 / 48.0;
                    c + egui::vec2(a.cos(), a.sin()) * rad
                }).collect();
                p.add(egui::Shape::line(pts, Stroke::new(u(6.5), if v >= 0.9 { DANGER() } else if v >= 0.8 { WARNING() } else { col })));
            }
            p.text(c, egui::Align2::CENTER_CENTER, v.map(|v| format!("{:.0}%", v * 100.0)).unwrap_or("–".into()), FontId::proportional(z(13.0)), TEXT_DEFAULT());
            p.text(c + egui::vec2(0.0, rad + u(13.0)), egui::Align2::CENTER_CENTER, label, FontId::proportional(z(11.0)), TEXT_SUBTLE());
        }
        let mut foot = vec![];
        if let Some(l) = n.load {
            foot.push(format!("load {l:.1} of {:.0}", n.cores));
        }
        if let (Some(a), Some(b)) = (n.rx, n.tx) {
            foot.push(format!("net {}/s", pg::bytes(a + b)));
        }
        if let Some(b) = n.boot {
            foot.push(format!("up {}", kube::human_duration((now - b).max(0.0) as i64)));
        }
        label_at(ui, &p, egui::pos2(r.left() + 14.0, r.bottom() - u(16.0)), &foot.join("  ·  "), 11.5, TEXT_SUBTLE(), r.width() - 28.0);
        if resp.on_hover_text(format!("{}\n{}\n{}", n.uname, n.instance, n.disks.iter().take(5).map(|d| format!("{} {:.0}% of {}", d.mount, d.used() * 100.0, pg::bytes(d.size))).collect::<Vec<_>>().join("\n"))).clicked() {
            open = Some(n.instance.clone());
        }
    });
    open
}

/// What needs a look: (how bad, machine, what).
fn trouble(nodes: &[(&Node, String, bool)]) -> Vec<(Tone, String, String, String)> {
    let mut out: Vec<(Tone, String, String, String)> = vec![];
    for (n, name, _) in nodes {
        let mut add = |t: Tone, what: String| out.push((t, name.clone(), what, n.instance.clone()));
        if n.ready == Some(false) {
            add(Tone::Danger, "not ready".into());
        }
        for d in &n.disks {
            if d.used() >= 0.9 {
                add(Tone::Danger, format!("{} is {:.0}% full", d.mount, d.used() * 100.0));
            } else if d.soon && d.used() >= 0.5 {
                add(Tone::Warning, format!("{} will be full within 4 days at this pace", d.mount));
            } else if d.used() >= 0.8 {
                add(Tone::Warning, format!("{} is {:.0}% full", d.mount, d.used() * 100.0));
            }
        }
        match n.mem() {
            Some(m) if m >= 0.95 => add(Tone::Danger, format!("memory {:.0}% in use", m * 100.0)),
            Some(m) if m >= 0.85 => add(Tone::Warning, format!("memory {:.0}% in use", m * 100.0)),
            _ => {}
        }
        if n.cpu.map(|c| c >= 0.9).unwrap_or(false) {
            add(Tone::Warning, format!("CPU {:.0}% in use", n.cpu.unwrap_or(0.0) * 100.0));
        }
        if n.cores > 0.0 && n.load.map(|l| l > n.cores * 1.5).unwrap_or(false) {
            add(Tone::Warning, format!("load {:.1} on {:.0} cores: work is waiting", n.load.unwrap_or(0.0), n.cores));
        }
    }
    out.sort_by_key(|t| t.0 != Tone::Danger);
    out
}

fn graf_trouble(ui: &mut Ui, nodes: &[(&Node, String, bool)]) -> Option<String> {
    let list = trouble(nodes);
    let mut open = None;
    dash::section(ui, "Needs a look", "");
    card(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        if list.is_empty() {
            let (r, _) = line(ui, u(27.0), false);
            at(ui, r, 0.0, 1.0, "Nothing: disks, memory, CPU and load are fine on every node.", 13.0, SUCCESS());
        }
        for (tone, name, what, inst) in list.iter().take(12) {
            let (r, resp) = line(ui, u(27.0), true);
            at(ui, r, 0.0, 0.34, name, 13.0, PRIMARY_TEXT());
            at(ui, r, 0.35, 0.65, what, 13.0, tone_color(*tone));
            if resp.clicked() {
                open = Some(inst.clone());
            }
        }
        if list.len() > 12 {
            let (r, _) = line(ui, u(24.0), false);
            at(ui, r, 0.0, 1.0, &format!("and {} more", list.len() - 12), 12.0, TEXT_SUBTLE());
        }
    });
    open
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    const GB: f64 = 1073741824.0;

    #[test]
    fn addresses_and_labels() {
        assert_eq!(check_url(" grafana.example.com/ ").unwrap(), "https://grafana.example.com");
        assert_eq!(check_url("https://h.example:3000/grafana/").unwrap(), "https://h.example:3000/grafana");
        assert!(check_url("http://localhost:3000").is_ok());
        for bad in ["", "http://grafana.example.com", "https://me:pw@h.example", "ftp://h", "https://h/?x=1", "https://", "http://localhost.evil.example"] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
        assert!(check_label("cluster=\"prod\", job=\"n\"").is_ok() && check_label("").is_ok());
        for bad in ["cluster=prod", "a=\"x\"} or up{b=\"", "1a=\"x\"", "x"] {
            assert!(check_label(bad).is_err(), "{bad}");
        }
        assert_eq!(m("up", "a=\"b\"", ""), "up{a=\"b\"}");
        assert_eq!(m("up", "", ""), "up");
    }

    #[test]
    fn nothing_secret_is_kept() {
        let c = Conf { url: "https://h".into(), user: "me".into(), ..Default::default() };
        let keys: Vec<String> = c.json().as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys.len(), 6);
        assert!(!keys.iter().any(|k| k.contains("pass") || k.contains("secret")));
        assert_eq!(Conf::from_json(&c.json()), c);
        // Another address, user or certificate: another login.
        for other in [Conf { url: "https://x".into(), ..c.clone() }, Conf { user: "x".into(), ..c.clone() }, Conf { ca: "x".into(), ..c.clone() }, Conf { token: true, ..c.clone() }] {
            assert_ne!(other.binding(), c.binding());
        }
        assert_eq!(Conf { uid: "x".into(), ..c.clone() }.binding(), c.binding());
    }

    #[test]
    fn joins() {
        assert_eq!((host("10.0.0.1:9100"), host("[fd00::1]:9100"), host("node-a:9100"), host("fd00::1")), ("10.0.0.1", "fd00::1", "node-a", "fd00::1"));
        assert_eq!((short("a.b.c"), short("10.0.0.1")), ("a", "10.0.0.1"));
        let ips: HashMap<String, String> = [("10.0.0.1".to_string(), "kube-a".to_string())].into();
        let names: HashSet<String> = ["kube-a", "kube-b.example", "x.one", "x.two"].map(String::from).into();
        let n = |i: &str, u: &str| Node { instance: i.into(), uname: u.into(), ..Default::default() };
        assert_eq!(pod_node(&n("10.0.0.1:9100", "other"), &ips, &names), Some("kube-a"));
        assert_eq!(pod_node(&n("10.0.0.2:9100", "kube-b"), &ips, &names), Some("kube-b.example"));
        assert_eq!(pod_node(&n("10.0.0.3:9100", "kube-c.example"), &ips, &names), None);
        // Two have that short name: not guessed.
        assert_eq!(pod_node(&n("10.0.0.4:9100", "x.three"), &ips, &names), None);
    }

    fn vec_of(rows: &[(Value, f64)]) -> Value {
        serde_json::json!({"status": "success", "data": {"resultType": "vector", "result": rows.iter().map(|(m, v)| serde_json::json!({"metric": m, "value": [1.0, v.to_string()]})).collect::<Vec<_>>()}})
    }

    fn answers(k: &str) -> Value {
        let i = |x: &str| serde_json::json!({"instance": format!("10.0.0.{x}:9100")});
        let fs = |mp: &str, dev: &str| serde_json::json!({"instance": "10.0.0.1:9100", "device": dev, "mountpoint": mp});
        match k {
            "uname" => vec_of(&[(serde_json::json!({"instance": "10.0.0.2:9100", "nodename": "b.example"}), 1.0), (serde_json::json!({"instance": "10.0.0.1:9100", "nodename": "a.example"}), 1.0)]),
            "cpu" => vec_of(&[(i("1"), 0.5), (i("2"), 1.2)]),
            "cores" => vec_of(&[(i("1"), 8.0)]),
            "mem_total" => vec_of(&[(i("1"), 100.0)]),
            "mem_avail" => vec_of(&[(i("1"), 4.0)]),
            "fs_size" => vec_of(&[(fs("/var/lib/data", "/dev/sda"), 100.0 * GB), (fs("/", "/dev/sda"), 100.0 * GB), (fs("/boot", "/dev/sdb"), 0.5 * GB), (fs("/data", "/dev/sdc"), 10.0 * GB)]),
            "fs_avail" => vec_of(&[(fs("/var/lib/data", "/dev/sda"), 40.0 * GB), (fs("/", "/dev/sda"), 40.0 * GB), (fs("/boot", "/dev/sdb"), 0.1 * GB), (fs("/data", "/dev/sdc"), 0.5 * GB)]),
            "fs_soon" => vec_of(&[(fs("/", "/dev/sda"), -1.0)]),
            "info" => vec_of(&[(serde_json::json!({"node": "kube-a", "internal_ip": "10.0.0.1", "kubelet_version": "v1"}), 1.0)]),
            "ready" => vec_of(&[(serde_json::json!({"node": "kube-a"}), 0.0)]),
            _ => serde_json::json!({"data": {"result": [{"metric": {}, "value": [0, "NaN"]}]}}),
        }
    }

    #[test]
    fn collects() {
        let d = collect("", |k, _| Ok(answers(k))).unwrap();
        assert_eq!(d.nodes.len(), 2);
        let a = &d.nodes[0];
        assert_eq!((a.uname.as_str(), a.kube.as_deref(), a.ready, a.cpu), ("a.example", Some("kube-a"), Some(false), Some(0.5)));
        assert_eq!(a.disks.iter().map(|d| (d.mount.as_str(), d.soon)).collect::<Vec<_>>(), vec![("/data", false), ("/", true)]);
        // Missing figures are missing, not zero; more than all is all.
        assert_eq!((d.nodes[1].mem(), d.nodes[1].load, d.nodes[1].cpu, d.nodes[1].ready), (None, None, Some(1.0), None));
        let list: Vec<(&Node, String, bool)> = d.nodes.iter().map(|n| (n, known_name(n, None), false)).collect();
        let t: Vec<String> = trouble(&list).into_iter().map(|t| t.2).collect();
        for want in ["not ready", "/data is 95% full", "/ will be full within 4 days at this pace", "memory 96% in use"] {
            assert!(t.iter().any(|x| x == want), "{want}: {t:?}");
        }
        // A refused login ends it at once; a part that can't be read doesn't.
        let mut n = 0;
        let e = collect("", |_, _| { n += 1; Err(Fail::Login("no".into())) });
        assert!(matches!(e, Err(Fail::Login(_))) && n == 1);
        assert!(collect("", |k, _| if k == "info" { Err(Fail::Stop("x".into())) } else { Ok(answers(k)) }).is_ok());
        let two = |k: &str, _: &str| Ok(if k == "uname" { vec_of(&[(serde_json::json!({"instance": "a", "cluster": "x"}), 1.0), (serde_json::json!({"instance": "b", "cluster": "y"}), 1.0)]) } else { Value::Null });
        assert_eq!(collect("", two).unwrap().clusters, vec!["x", "y"]);
        assert!(queries("cluster=\"p\"").iter().all(|q| q.1.contains("cluster=\"p\"")));
    }

    /// A certificate authority, and a server certificate for localhost signed by it.
    fn authority() -> (String, Vec<u8>, rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name.push(rcgen::DnType::CommonName, "Test Root");
        let ca = p.self_signed(&key).unwrap();
        let skey = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&p, &key);
        let srv = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap().signed_by(&skey, &issuer).unwrap();
        (ca.pem(), ca.der().to_vec(), srv.der().clone(), skey.serialize_der())
    }

    /// A small HTTPS server; returns its port and what it was asked.
    fn server(cert: rustls::pki_types::CertificateDer<'static>, key: Vec<u8>) -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
        let conf = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], rustls::pki_types::PrivatePkcs8KeyDer::from(key).into())
            .unwrap();
        let conf = Arc::new(conf);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(vec![]));
        let log = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (conf, log) = (conf.clone(), log.clone());
                std::thread::spawn(move || {
                    let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(conf).unwrap(), s);
                    let mut buf = vec![];
                    let mut b = [0u8; 2048];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut b) {
                            Ok(n) if n > 0 => buf.extend_from_slice(&b[..n]),
                            _ => return,
                        }
                    }
                    let text = String::from_utf8_lossy(&buf).to_string();
                    log.lock().unwrap().push(text.clone());
                    let path = text.split(' ').nth(1).unwrap_or("").to_string();
                    let want = format!("basic {}", b64_encode(b"me:p\"a:s\\s")).to_lowercase();
                    let auth = text.lines().find_map(|l| l.to_lowercase().strip_prefix("authorization: ").map(String::from)).unwrap_or_default();
                    let (code, extra, body) = if path.starts_with("/sso") {
                        ("302 Found", format!("Location: https://localhost:{port}/api/frontend/settings\r\n"), String::new())
                    } else if path.starts_with("/page") {
                        ("200 OK", String::new(), "<html>".into())
                    } else if auth != want && auth != "bearer tok" {
                        ("401 Unauthorized", String::new(), "{}".into())
                    } else if path.starts_with("/api/frontend/settings") {
                        ("200 OK", String::new(), r#"{"datasources":{"-- Mixed --":{"type":"datasource","uid":"m"},"Loki":{"type":"loki","uid":"l"},"B":{"type":"prometheus","uid":"b"},"Main":{"type":"prometheus","uid":"main","isDefault":true}}}"#.into())
                    } else if path.starts_with("/api/datasources/proxy/uid/main/api/v1/query?query=") {
                        ("200 OK", String::new(), vec_of(&[(serde_json::json!({"instance": "a:1", "nodename": "a"}), 1.0)]).to_string())
                    } else {
                        ("403 Forbidden", String::new(), "{}".into())
                    };
                    let _ = tls.write_all(format!("HTTP/1.1 {code}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        (port, seen)
    }

    #[test]
    fn talks_to_a_server() {
        let (ca, ca_der, cert, key) = authority();
        let (other, _, _, _) = authority();
        let (port, seen) = server(cert, key);
        let conf = Conf { url: format!("https://localhost:{port}"), user: "me".into(), ca: ca.clone(), uid: "main".into(), ..Default::default() };
        let pw = Secret("p\"a:s\\s".into());
        let c = Client::new(&conf, &pw).ok().unwrap();
        assert_eq!(c.sources().unwrap(), vec![("Main".to_string(), "main".to_string()), ("B".to_string(), "b".to_string())]);
        let d = collect("", |_, q| c.prom("query", &[("query", q)])).unwrap();
        assert_eq!(d.nodes[0].uname, "a");
        assert!(seen.lock().unwrap().iter().all(|r| r.starts_with("GET ")));
        // A token.
        let t = Client::new(&Conf { token: true, ..conf.clone() }, &Secret("tok".into())).ok().unwrap();
        assert!(t.sources().is_ok());
        // A wrong password, and the error doesn't hold it.
        let bad = Client::new(&conf, &Secret("sesame-wrong".into())).ok().unwrap();
        let e = bad.sources().unwrap_err();
        assert!(matches!(e, Fail::Login(_)) && !format!("{e:?}").contains("sesame"));
        // Another authority, or the system's: refused before anything is sent.
        let before = seen.lock().unwrap().len();
        for ca in [other, String::new()] {
            let e = Client::new(&Conf { ca, ..conf.clone() }, &pw).ok().unwrap().sources().unwrap_err();
            assert!(matches!(e, Fail::Stop(_)), "{e:?}");
        }
        // The right authority, but the certificate is for another name.
        let e = Client::new(&Conf { url: format!("https://127.0.0.1:{port}"), ..conf.clone() }, &pw).ok().unwrap().sources().unwrap_err();
        assert!(matches!(e, Fail::Stop(_)), "{e:?}");
        assert_eq!(seen.lock().unwrap().len(), before);
        // Redirects aren't followed.
        let e = Client::new(&Conf { url: format!("https://localhost:{port}/sso"), ..conf.clone() }, &pw).ok().unwrap().sources().unwrap_err();
        assert!(matches!(e, Fail::Stop(_)));
        assert_eq!(seen.lock().unwrap().len(), before + 1);
        // Something else lives there; a data source that may not be read; a name that isn't one.
        assert!(matches!(Client::new(&Conf { url: format!("https://localhost:{port}/page"), ..conf.clone() }, &pw).ok().unwrap().sources(), Err(Fail::Stop(_))));
        assert!(matches!(Client::new(&Conf { uid: "b".into(), ..conf.clone() }, &pw).ok().unwrap().prom("query", &[]), Err(Fail::Stop(_))));
        assert!(matches!(Client::new(&Conf { uid: "../x".into(), ..conf.clone() }, &pw).ok().unwrap().prom("query", &[]), Err(Fail::Stop(_))));
        assert!(Client::new(&conf, &Secret("a\r\nX: y".into())).is_err());
        // The certificate as a file: PEM, DER, a chain; never a key.
        let d = read_ca(ca.as_bytes()).unwrap();
        assert!(d.certs[0].0.is_ca && d.certs[0].0.subject_full.contains("Test Root"));
        assert_eq!(d.certs[0].1, fingerprint(&ca_der));
        assert_eq!(d.certs[0].1.len(), 95);
        let der = read_ca(&ca_der).unwrap();
        assert_eq!(der.pem, d.pem);
        assert_eq!(read_ca(format!("# my bundle\r\n{}\n{}", ca.replace('\n', "\r\n"), ca).as_bytes()).unwrap().certs.len(), 2);
        assert!(Client::new(&Conf { ca: der.pem, ..conf.clone() }, &pw).ok().unwrap().sources().is_ok());
        for bad in ["", "hello", "-----BEGIN CERTIFICATE-----\nAAAA", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"] {
            assert!(read_ca(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(read_ca(format!("{ca}-----BEGIN RSA PRIVATE KEY-----\nx").as_bytes()).unwrap_err().contains("private key"));
    }

    #[test]
    fn history() {
        let v = serde_json::json!({"data": {"result": [{"metric": {"instance": "a:1"}, "values": [[10, "0.5"], [20, "NaN"], [30, "0.7"]]}]}});
        assert_eq!(series(&v)["a:1"], vec![(10, 0.5), (30, 0.7)]);
        assert!(series(&Value::Null).is_empty());
    }
}
