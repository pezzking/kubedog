//! Network Lab: tests from this computer. A name, a connection, TLS and a web answer, step by step, and
//! where it stops. Certificates are always checked: the chain that the server showed is only noted on its
//! way to the system's own check, so a bad one still ends the test before anything is sent. Redirects
//! aren't followed. Only to addresses that a person chose.

use super::certs::{parse_cert, CertInfo};
use super::*;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};

/// How long each part may take.
const NAME: Duration = Duration::from_secs(6);
const CONNECT: Duration = Duration::from_secs(4);
const TALK: Duration = Duration::from_secs(8);
/// Addresses of one name that are tried, and tests at once.
const ADDRESSES: usize = 4;
pub(super) const AT_ONCE: usize = 6;
/// Tests in one go.
pub(super) const MOST: usize = 200;

/// How far a test goes.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Mode {
    Tcp,
    Tls,
    Http,
    Https,
}

impl Mode {
    pub fn word(self) -> &'static str {
        match self {
            Mode::Tcp => "connection",
            Mode::Tls => "TLS",
            Mode::Http => "HTTP",
            Mode::Https => "HTTPS",
        }
    }
    fn tls(self) -> bool {
        matches!(self, Mode::Tls | Mode::Https)
    }
    fn web(self) -> bool {
        matches!(self, Mode::Http | Mode::Https)
    }
}

/// What's tested.
#[derive(Clone, PartialEq, Debug)]
pub(super) struct Target {
    pub host: String,
    pub port: u16,
    pub mode: Mode,
    pub path: String,
    /// What it's of, in words: "Route shop/web".
    pub of: String,
    /// The addresses the cluster says it has, when it says.
    pub expect: Vec<String>,
}

impl Target {
    pub fn label(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match self.mode {
            Mode::Https if self.port == 443 => format!("https://{h}{}", self.path),
            Mode::Http if self.port == 80 => format!("http://{h}{}", self.path),
            Mode::Https => format!("https://{h}:{}{}", self.port, self.path),
            Mode::Http => format!("http://{h}:{}{}", self.port, self.path),
            _ => format!("{h}:{}", self.port),
        }
    }
}

/// A name or an address, and nothing else.
fn good_host(h: &str) -> bool {
    if h.parse::<IpAddr>().is_ok() {
        return true;
    }
    !h.is_empty() && h.len() <= 253 && h.split('.').all(|p| !p.is_empty() && p.len() <= 63 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') && !p.starts_with('-'))
}

/// A path that can be put in a request as it is; else the top.
pub(super) fn good_path(p: &str) -> String {
    if p.starts_with('/') && p.len() < 500 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-._~%+@:,".contains(&b)) { p.to_string() } else { "/".into() }
}

/// What a person typed: an address, host:port, or a name.
pub(super) fn read_target(t: &str) -> Result<Target, String> {
    let t = t.trim();
    let (scheme, rest) = match t.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => (String::new(), t),
    };
    let (place, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if place.contains('@') {
        return Err("Leave the name and password out of the address.".into());
    }
    if path.contains(['?', '#']) {
        return Err("Leave out what follows ? or #: it can hold secrets, and the path is enough.".into());
    }
    let (host, port) = if let Some(r) = place.strip_prefix('[') {
        let (h, p) = r.split_once(']').ok_or("That address has no ].")?;
        (h, p.strip_prefix(':'))
    } else if place.parse::<IpAddr>().is_ok() {
        (place, None)
    } else {
        match place.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (place, None),
        }
    };
    let host = host.trim_end_matches('.').to_lowercase();
    if !good_host(&host) {
        return Err("Write a name or an address, like web.example.com, web.example.com:5432 or https://web.example.com/health".into());
    }
    let port = match port {
        Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0).ok_or("The port is a number from 1 to 65535.")?),
        None => None,
    };
    let (mode, port) = match (scheme.as_str(), port) {
        ("https", p) => (Mode::Https, p.unwrap_or(443)),
        ("http", p) => (Mode::Http, p.unwrap_or(80)),
        ("tls", p) => (Mode::Tls, p.unwrap_or(443)),
        ("tcp", Some(p)) => (Mode::Tcp, p),
        ("tcp", None) => return Err("Give a port.".into()),
        ("", None) => (Mode::Https, 443),
        ("", Some(443)) => (Mode::Https, 443),
        ("", Some(80)) => (Mode::Http, 80),
        ("", Some(p)) => (Mode::Tcp, p),
        (s, _) => return Err(format!("{s}:// can't be tested: use https, http, tls or tcp.")),
    };
    let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
    if mode.web() && good_path(&path) != path {
        return Err("That path has signs in it that can't be sent as they are.".into());
    }
    Ok(Target { host, port, mode, path, of: "typed here".into(), expect: vec![] })
}

/// One step of a test.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Step {
    pub what: &'static str,
    pub tone: Tone,
    pub said: String,
    pub ms: Option<u64>,
    pub more: Vec<String>,
}

#[derive(Clone, Debug)]
pub(super) struct Done {
    pub target: Target,
    pub at: i64,
    pub steps: Vec<Step>,
    /// What the server showed, its own certificate first.
    pub chain: Vec<CertInfo>,
}

impl Done {
    pub fn tone(&self) -> Tone {
        for t in [Tone::Danger, Tone::Warning] {
            if self.steps.iter().any(|s| s.tone == t) {
                return t;
            }
        }
        Tone::Success
    }
    /// The step that says most: the worst, else the last.
    pub fn head(&self) -> Option<&Step> {
        let t = self.tone();
        self.steps.iter().find(|s| s.tone == t && t != Tone::Success).or(self.steps.last())
    }
    pub fn ms(&self) -> u64 {
        self.steps.iter().filter_map(|s| s.ms).sum()
    }
}

fn step(what: &'static str, tone: Tone, said: impl Into<String>, t: Option<Instant>) -> Step {
    Step { what, tone, said: said.into(), ms: t.map(|t| t.elapsed().as_millis() as u64), more: vec![] }
}

// ---------- certificates ----------

/// Passes everything on to the real check, and notes what the server showed.
#[derive(Debug)]
struct Noting {
    real: Arc<dyn ServerCertVerifier>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for Noting {
    fn verify_server_cert(&self, end: &CertificateDer<'_>, others: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut s) = self.seen.lock() {
            *s = std::iter::once(end).chain(others).take(12).map(|c| c.as_ref().to_vec()).collect();
        }
        self.real.verify_server_cert(end, others, name, ocsp, now)
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.real.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.real.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.real.supported_verify_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The system's own check.
fn system_check() -> Result<Arc<dyn ServerCertVerifier>, String> {
    rustls_platform_verifier::Verifier::new(provider()).map(|v| Arc::new(v) as Arc<dyn ServerCertVerifier>).map_err(|e| e.to_string())
}

/// Is a certificate's name for this host? ("*.example.com" is for one level.)
fn name_fits(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.trim_end_matches('.').to_lowercase(), host.to_lowercase());
    match p.strip_prefix("*.") {
        Some(rest) => h.split_once('.').map(|x| x.1 == rest).unwrap_or(false),
        None => p == h,
    }
}

/// What's wrong with a chain, as far as reading it tells: (what, what to do).
pub(super) fn chain_faults(chain: &[CertInfo], host: &str, now: i64) -> Vec<(String, String)> {
    let mut v = vec![];
    let Some(c) = chain.first() else { return v };
    if let Some(t) = c.not_after.filter(|t| *t < now) {
        v.push((format!("it expired {} ago", kube::human_duration(now - t)), "Renew it, and check what should have done that (cert-manager, the operator, a person).".into()));
    }
    if let Some(t) = c.not_before.filter(|t| *t > now) {
        v.push((format!("it's valid only from {} on", netmap::iso_date(t)), "Look at the clock of this computer and of what issued it.".into()));
    }
    if let Some(x) = chain.iter().skip(1).find(|x| x.not_after.map(|t| t < now).unwrap_or(false)) {
        v.push((format!("the certificate of its issuer “{}” has expired", x.subject), "Send the new one along with it.".into()));
    }
    let ip = host.parse::<IpAddr>().ok().map(|i| i.to_string());
    let fits = c.alt_names.iter().any(|(k, n)| match (&ip, *k) {
        (Some(i), "IP") => n == i,
        (None, "DNS") => name_fits(n, host),
        _ => false,
    });
    if !fits {
        let names: Vec<String> = c.alt_names.iter().filter(|x| matches!(x.0, "DNS" | "IP")).take(4).map(|x| x.1.clone()).collect();
        v.push((format!("it's for {}, not for {host}", if names.is_empty() { format!("“{}”", c.subject) } else { names.join(", ") }), "On OpenShift this is often the router's own certificate: nothing answers for this name there, or the route has none of its own.".into()));
    }
    if chain.len() == 1 && c.issuer_full == c.subject_full {
        v.push(("it's signed by itself".into(), "Nobody vouches for it. Use one from an authority, or add it to the trust of those who need it.".into()));
    }
    v
}

/// Why a handshake failed, in words.
fn tls_trouble(e: &rustls::Error, chain: &[CertInfo], host: &str, now: i64) -> (String, Vec<String>) {
    use rustls::{AlertDescription, CertificateError, Error};
    match e {
        Error::InvalidCertificate(c) => {
            let mut more: Vec<String> = vec![];
            let faults = chain_faults(chain, host, now);
            let said = match faults.first() {
                Some(_) => format!("The certificate isn't good: {}", faults.iter().map(|x| x.0.clone()).collect::<Vec<_>>().join("; ")),
                None => match c {
                    CertificateError::UnknownIssuer => {
                        let who = chain.first().map(|c| if c.issuer.is_empty() { c.issuer_full.clone() } else { c.issuer.clone() }).unwrap_or_default();
                        if chain.len() == 1 {
                            more.push("The server sends only its own certificate. When its issuer isn't known here, the one in between may be missing from what it sends.".into());
                        }
                        format!("This computer doesn't trust who signed the certificate (“{who}”)")
                    }
                    CertificateError::BadSignature => {
                        more.push("Happens when an authority was made anew under its old name: the certificate, or what this computer trusts, is from before.".into());
                        "The certificate wasn't signed by the authority it names".into()
                    }
                    CertificateError::Revoked => "The certificate was withdrawn by who issued it".into(),
                    x => format!("The certificate was refused by this computer: {}", truncate(&format!("{x:?}"), 160)),
                },
            };
            more.splice(0..0, faults.into_iter().map(|x| x.1));
            (said, more)
        }
        Error::AlertReceived(a) => match a {
            AlertDescription::UnrecognisedName => ("The server doesn't know this name (TLS: unrecognized name)".into(), vec!["It chooses its certificate by the name that's asked for: is this the right address for it?".into()]),
            AlertDescription::HandshakeFailure => ("The server has no way to talk that both know (TLS: handshake failure)".into(), vec!["Often: only old ciphers, or it wants a client certificate.".into()]),
            AlertDescription::ProtocolVersion => ("The server only talks a TLS that's too old".into(), vec!["This test speaks TLS 1.2 and 1.3.".into()]),
            AlertDescription::CertificateRequired | AlertDescription::BadCertificate => ("The server wants a certificate from whoever connects".into(), vec!["That's mutual TLS; this test has none to show.".into()]),
            a => (format!("The server ended TLS: {a:?}"), vec![]),
        },
        Error::InvalidMessage(_) => ("What answers there doesn't talk TLS".into(), vec!["A plain HTTP service behind this port, or a route whose TLS setting doesn't fit what the app talks.".into()]),
        Error::PeerIncompatible(p) => (format!("Nothing both sides can talk: {p:?}"), vec!["This test speaks TLS 1.2 and 1.3.".into()]),
        e => (format!("TLS failed: {}", truncate(&e.to_string(), 160)), vec![]),
    }
}

// ---------- the test ----------

/// A connection that has to be done by a certain time, however slowly the other side sends.
struct Timed {
    s: TcpStream,
    until: Instant,
}

impl Timed {
    fn left(&self) -> std::io::Result<Duration> {
        self.until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(std::io::ErrorKind::TimedOut.into())
    }
}

impl Read for Timed {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.s.set_read_timeout(Some(self.left()?))?;
        self.s.read(b)
    }
}

impl Write for Timed {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.s.set_write_timeout(Some(self.left()?))?;
        self.s.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.s.flush()
    }
}

/// Why something didn't connect, in words.
fn io_trouble(e: &std::io::Error) -> (String, Vec<String>) {
    use std::io::ErrorKind as K;
    let text = e.to_string().to_lowercase();
    match e.kind() {
        K::ConnectionRefused => ("refused: the machine is there, but nothing listens on that port".into(), vec!["A firewall can also answer like this.".into()]),
        K::TimedOut | K::WouldBlock => ("no answer in time".into(), vec!["Usually a firewall that drops it, a wrong address, or no route (VPN?).".into()]),
        K::ConnectionReset | K::ConnectionAborted | K::BrokenPipe => ("the other side hung up".into(), vec!["A firewall, a load balancer without anything behind it, or an app that doesn't talk this.".into()]),
        K::UnexpectedEof => ("the other side hung up without a word".into(), vec![]),
        _ if text.contains("no route") || text.contains("unreachable") => ("there's no route to it from this computer".into(), vec!["Is the VPN on?".into()]),
        _ => (truncate(&e.to_string(), 160), vec![]),
    }
}

/// The addresses of a name; the system's own look-up can't be told to hurry, so it's left behind.
fn addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let h = host.to_string();
    std::thread::spawn(move || {
        let _ = tx.send((h.as_str(), port).to_socket_addrs().map(|i| i.collect::<Vec<_>>()));
    });
    match rx.recv_timeout(NAME) {
        Ok(Ok(l)) if l.is_empty() => Err("it has no address".into()),
        Ok(Ok(l)) => {
            let mut v: Vec<SocketAddr> = vec![];
            l.into_iter().for_each(|a| {
                if !v.contains(&a) {
                    v.push(a)
                }
            });
            Ok(v)
        }
        Ok(Err(_)) => Err("that name can't be found".into()),
        Err(_) => Err("the name servers don't answer in time".into()),
    }
}

/// The start of a web answer: (code, where it points).
fn read_answer(head: &str) -> Option<(u16, Option<String>)> {
    let mut l = head.lines();
    let first = l.next()?;
    let code = first.strip_prefix("HTTP/")?.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let to = l.filter_map(|x| x.split_once(':')).find(|x| x.0.trim().eq_ignore_ascii_case("location")).map(|x| {
        // What follows ? can hold a session or a token.
        truncate(x.1.trim().split(['?', '#']).next().unwrap_or(""), 200)
    });
    Some((code, to))
}

fn answer_step(code: u16, to: Option<String>, t: Instant) -> Step {
    let (tone, said) = match code {
        200..=299 => (Tone::Success, format!("{code}: it answers")),
        300..=399 => (Tone::Success, match &to {
            Some(x) => format!("{code}: it points to {x}"),
            None => format!("{code}: it points somewhere else"),
        }),
        401 | 403 | 407 => (Tone::Success, format!("{code}: it answers, and wants a login or refuses this path")),
        404 => (Tone::Warning, "404: it answers, but has nothing at this path".into()),
        429 => (Tone::Warning, "429: too many requests, it says".into()),
        502 => (Tone::Danger, "502: what's in front can't talk to the app behind it".into()),
        503 => (Tone::Danger, "503: nothing behind it can answer".into()),
        504 => (Tone::Danger, "504: the app behind it didn't answer in time".into()),
        500..=599 => (Tone::Danger, format!("{code}: the app failed")),
        _ => (Tone::Warning, format!("{code}")),
    };
    let mut s = step("Answer", tone, said, Some(t));
    if code == 503 {
        s.more.push("An OpenShift router says this when no pod behind the route is ready, or when it has no route for this name and path.".into());
    }
    if (300..=399).contains(&code) {
        s.more.push("It isn't followed. Test that address too if it matters.".into());
    }
    s
}

/// Asks for a page and reads the start of the answer.
fn ask_web<S: Read + Write>(s: &mut S, t: &Target) -> Step {
    let began = Instant::now();
    let host = match (t.host.contains(':'), t.mode, t.port) {
        (true, _, p) => format!("[{}]:{p}", t.host),
        (_, Mode::Http, 80) | (_, Mode::Https, 443) => t.host.clone(),
        (_, _, p) => format!("{}:{p}", t.host),
    };
    let q = format!("GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Kubedog\r\nAccept: */*\r\nConnection: close\r\n\r\n", t.path);
    let mut got: Vec<u8> = vec![];
    let r = s.write_all(q.as_bytes()).and_then(|_| s.flush()).and_then(|_| {
        let mut b = [0u8; 4096];
        loop {
            let n = s.read(&mut b)?;
            got.extend_from_slice(&b[..n]);
            if n == 0 || got.len() > 64 * 1024 || got.windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok(());
            }
        }
    });
    let head = String::from_utf8_lossy(&got);
    match (read_answer(&head), r) {
        (Some((code, to)), _) => answer_step(code, to, began),
        (None, Err(e)) => {
            let (said, more) = io_trouble(&e);
            Step { more, ..step("Answer", Tone::Danger, format!("No answer: {said}"), Some(began)) }
        }
        (None, Ok(())) if got.is_empty() => step("Answer", Tone::Danger, "It hung up without answering", Some(began)),
        (None, Ok(())) => step("Answer", Tone::Warning, "Something answers, but not a web server", Some(began)),
    }
}

/// The whole test.
pub(super) fn run(t: &Target) -> Done {
    run_with(t, system_check(), kube::now_secs())
}

fn run_with(t: &Target, check: Result<Arc<dyn ServerCertVerifier>, String>, now: i64) -> Done {
    let mut d = Done { target: t.clone(), at: now, steps: vec![], chain: vec![] };
    // The name.
    let began = Instant::now();
    let is_ip = t.host.parse::<IpAddr>().is_ok();
    let addrs = match addresses(&t.host, t.port) {
        Ok(a) => a,
        Err(e) => {
            let mut s = step("Name", Tone::Danger, format!("The name fails: {e}"), Some(began));
            s.more.push("This is what the name servers of this computer say; others (inside the cluster, without the VPN) can differ.".into());
            d.steps.push(s);
            return d;
        }
    };
    if !is_ip {
        let ips: Vec<String> = addrs.iter().map(|a| a.ip().to_string()).collect();
        let mut s = step("Name", Tone::Success, ips.join(", "), Some(began));
        if !t.expect.is_empty() && !ips.iter().any(|i| t.expect.contains(i)) {
            s.more.push(format!("The cluster says {}: something else may be in front of it, or the name points to the wrong place.", t.expect.join(", ")));
        }
        d.steps.push(s);
    }
    // The connection: the first address that takes it, like other programs do.
    let began = Instant::now();
    let mut tcp = None;
    let mut failed: Vec<String> = vec![];
    let mut last = None;
    for a in addrs.iter().take(ADDRESSES) {
        match TcpStream::connect_timeout(a, CONNECT) {
            Ok(s) => {
                tcp = Some((s, *a));
                break;
            }
            Err(e) => {
                failed.push(format!("{}: {}", a.ip(), io_trouble(&e).0));
                last = Some(e);
            }
        }
    }
    let Some((tcp, a)) = tcp else {
        let (said, more) = last.as_ref().map(io_trouble).unwrap_or_default();
        let mut s = step("Connection", Tone::Danger, format!("Port {}: {said}", t.port), Some(began));
        s.more = more;
        if failed.len() > 1 {
            s.more.extend(failed);
        }
        d.steps.push(s);
        return d;
    };
    let mut s = step("Connection", if failed.is_empty() { Tone::Success } else { Tone::Warning }, if failed.is_empty() { format!("to {}, port {}", a.ip(), t.port) } else { format!("to {}, port {}, after {} of its addresses failed", a.ip(), t.port, failed.len()) }, Some(began));
    s.more = failed;
    d.steps.push(s);
    let mut tcp = Timed { s: tcp, until: Instant::now() + TALK };
    if t.mode == Mode::Http {
        let s = ask_web(&mut tcp, t);
        d.steps.push(s);
    }
    if !t.mode.tls() {
        return d;
    }
    // TLS, and only over it the question.
    let began = Instant::now();
    let seen = Arc::new(Mutex::new(vec![]));
    let made = check.and_then(|real| {
        let name = ServerName::try_from(t.host.clone()).map_err(|e| e.to_string())?;
        let conf = rustls::ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().map_err(|e| e.to_string())?.dangerous().with_custom_certificate_verifier(Arc::new(Noting { real, seen: seen.clone() })).with_no_client_auth();
        rustls::ClientConnection::new(Arc::new(conf), name).map_err(|e| e.to_string())
    });
    let mut conn = match made {
        Ok(c) => c,
        Err(e) => {
            d.steps.push(step("TLS", Tone::Danger, format!("It couldn't be started: {e}"), None));
            return d;
        }
    };
    let mut trouble: Option<(String, Vec<String>)> = None;
    while conn.is_handshaking() && trouble.is_none() {
        if let Err(e) = conn.complete_io(&mut tcp) {
            let chain: Vec<CertInfo> = seen.lock().map(|s| s.iter().filter_map(|c| parse_cert(c)).collect()).unwrap_or_default();
            trouble = Some(match e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
                Some(x) => tls_trouble(x, &chain, &t.host, now),
                None => {
                    let (a, b) = io_trouble(&e);
                    (format!("TLS didn't get through: {a}"), b)
                }
            });
        }
    }
    d.chain = seen.lock().map(|s| s.iter().filter_map(|c| parse_cert(c)).collect()).unwrap_or_default();
    if let Some((said, more)) = trouble {
        let mut s = step("TLS", Tone::Danger, said, Some(began));
        s.more = more;
        if !d.chain.is_empty() {
            s.more.push("Nothing was sent over it.".into());
        }
        d.steps.push(s);
        return d;
    }
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        _ => "TLS",
    };
    let left = d.chain.first().and_then(|c| c.not_after).map(|t| t - now);
    let soon = left.map(|l| l < 14 * 86400).unwrap_or(false);
    let words = match left {
        Some(l) => format!("{version}, good certificate, {} for {}", if soon { "only" } else { "valid" }, kube::human_duration(l)),
        None => format!("{version}, good certificate"),
    };
    d.steps.push(step("TLS", if soon { Tone::Warning } else { Tone::Success }, words, Some(began)));
    if t.mode == Mode::Https {
        tcp.until = Instant::now() + TALK;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        let a = ask_web(&mut s, t);
        d.steps.push(a);
    }
    d
}

// ---------- as JSON, between threads ----------

fn tone_word(t: Tone) -> &'static str {
    match t {
        Tone::Danger => "bad",
        Tone::Warning => "warn",
        Tone::Success => "good",
        _ => "info",
    }
}

const STEPS: [&str; 4] = ["Name", "Connection", "TLS", "Answer"];

pub(super) fn to_json(d: &Done) -> Value {
    serde_json::json!({
        "host": d.target.host, "port": d.target.port, "mode": d.target.mode.word(), "path": d.target.path, "of": d.target.of, "expect": d.target.expect, "at": d.at,
        "steps": d.steps.iter().map(|s| serde_json::json!({"what": s.what, "tone": tone_word(s.tone), "said": s.said, "ms": s.ms, "more": s.more})).collect::<Vec<_>>(),
        "chain": d.chain.iter().map(|c| serde_json::json!({"subject": c.subject, "full": c.subject_full, "issuer": c.issuer, "ifull": c.issuer_full, "key": c.key, "from": c.not_before, "until": c.not_after, "names": c.alt_names.iter().take(40).map(|n| serde_json::json!([n.0, n.1])).collect::<Vec<_>>()})).collect::<Vec<_>>(),
    })
}

pub(super) fn from_json(v: &Value) -> Option<Done> {
    let s = |v: &Value| v.as_str().unwrap_or("").to_string();
    let list = |v: &Value| -> Vec<String> { v.as_array().into_iter().flatten().map(s).collect() };
    let mode = [Mode::Tcp, Mode::Tls, Mode::Http, Mode::Https].into_iter().find(|m| v["mode"] == m.word())?;
    Some(Done {
        target: Target { host: s(&v["host"]), port: v["port"].as_u64()? as u16, mode, path: s(&v["path"]), of: s(&v["of"]), expect: list(&v["expect"]) },
        at: v["at"].as_i64().unwrap_or(0),
        steps: v["steps"].as_array()?.iter().filter_map(|x| Some(Step { what: STEPS.into_iter().find(|w| x["what"] == *w)?, tone: match x["tone"].as_str() { Some("bad") => Tone::Danger, Some("warn") => Tone::Warning, Some("good") => Tone::Success, _ => Tone::Muted }, said: s(&x["said"]), ms: x["ms"].as_u64(), more: list(&x["more"]) })).collect(),
        chain: v["chain"].as_array().into_iter().flatten().map(|c| CertInfo { subject: s(&c["subject"]), subject_full: s(&c["full"]), issuer: s(&c["issuer"]), issuer_full: s(&c["ifull"]), key: s(&c["key"]), not_before: c["from"].as_i64(), not_after: c["until"].as_i64(), alt_names: c["names"].as_array().into_iter().flatten().map(|n| (match n[0].as_str() { Some("DNS") => "DNS", Some("IP") => "IP", Some("URI") => "URI", _ => "Email" }, s(&n[1]))).collect(), ..Default::default() }).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn target(host: &str, port: u16, mode: Mode) -> Target {
        Target { host: host.into(), port, mode, path: "/".into(), of: String::new(), expect: vec![] }
    }

    /// An authority that's trusted in these tests.
    struct Ca {
        key: rcgen::KeyPair,
        params: rcgen::CertificateParams,
        der: CertificateDer<'static>,
    }

    fn ca() -> Ca {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "Test Root");
        let der = params.self_signed(&key).unwrap().der().clone();
        Ca { key, params, der }
    }

    fn trust(c: &Ca) -> Result<Arc<dyn ServerCertVerifier>, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(c.der.clone()).unwrap();
        Ok(rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build().unwrap())
    }

    /// Serves TLS with a certificate for `names`; answers one line. Returns the port and what was asked.
    fn serve(c: &Ca, names: &[&str], days: (i64, i64), answer: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
        // (rcgen takes dates.)
        let date = |back: i64| {
            let d = netmap::iso_date(kube::now_secs() + back * 86400);
            rcgen::date_time_ymd(d[..4].parse().unwrap(), d[5..7].parse().unwrap(), d[8..10].parse().unwrap())
        };
        p.not_before = date(days.0);
        p.not_after = date(days.1);
        let cert = p.signed_by(&key, &rcgen::Issuer::from_params(&c.params, &c.key)).unwrap();
        let conf = rustls::ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![cert.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap();
        let conf = Arc::new(conf);
        let seen = Arc::new(Mutex::new(vec![]));
        let log = seen.clone();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(conf.clone()).unwrap(), s);
                let mut b = [0u8; 2048];
                if let Ok(n) = tls.read(&mut b) {
                    if n > 0 {
                        log.lock().unwrap().push(String::from_utf8_lossy(&b[..n]).to_string());
                        let _ = tls.write_all(answer.as_bytes());
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                    }
                }
            }
        });
        (port, seen)
    }

    /// Plain TCP: does what it's told with each connection.
    fn plain(f: impl Fn(TcpStream) + Send + 'static) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || l.incoming().flatten().for_each(&f));
        port
    }

    #[test]
    fn typed() {
        let t = |s: &str| read_target(s).map(|t| (t.host, t.port, t.mode, t.path));
        assert_eq!(t("web.example.com"), Ok(("web.example.com".into(), 443, Mode::Https, "/".into())));
        assert_eq!(t(" HTTPS://Web.example.com:8443/health "), Ok(("web.example.com".into(), 8443, Mode::Https, "/health".into())));
        assert_eq!(t("db.example.com:5432"), Ok(("db.example.com".into(), 5432, Mode::Tcp, "/".into())));
        assert_eq!(t("tls://192.0.2.1"), Ok(("192.0.2.1".into(), 443, Mode::Tls, "/".into())));
        assert_eq!(t("[2001:db8::1]:80").unwrap().0, "2001:db8::1");
        assert_eq!(t("2001:db8::1").unwrap().0, "2001:db8::1");
        assert_eq!(read_target("http://[2001:db8::1]/").unwrap().label(), "http://[2001:db8::1]/");
        for bad in ["", "a b", "https://me:pw@example.com", "ftp://example.com", "tcp://example.com", "example.com:0", "example.com:99999", "https://example.com/a?token=x", "-x.example.com", "https://example.com/a b", "https://example.com/a\r\nX: y", "file:///etc/passwd"] {
            assert!(t(bad).is_err(), "{bad}");
        }
        assert_eq!(good_path("/a(/|$)(.*)"), "/");
        assert_eq!(good_path("/api/v1"), "/api/v1");
    }

    #[test]
    fn good_certificate_and_answer() {
        let c = ca();
        let (port, seen) = serve(&c, &["localhost"], (-10, 90), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let d = run_with(&target("localhost", port, Mode::Https), trust(&c), kube::now_secs());
        // (localhost can have two addresses, and the server is on one.)
        assert!(d.steps[2..].iter().all(|s| s.tone == Tone::Success), "{:?}", d.steps);
        assert_eq!(d.steps.iter().map(|s| s.what).collect::<Vec<_>>(), vec!["Name", "Connection", "TLS", "Answer"]);
        assert!(d.steps[2].said.starts_with("TLS 1.3, good certificate"));
        assert!(seen.lock().unwrap()[0].starts_with(&format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\n")));
        assert_eq!(d.chain[0].alt_names[0].1, "localhost");
        // Only TLS: nothing is asked.
        let n = seen.lock().unwrap().len();
        assert_eq!(run_with(&target("localhost", port, Mode::Tls), trust(&c), kube::now_secs()).steps.len(), 3);
        assert_eq!(seen.lock().unwrap().len(), n);
        // And back from JSON.
        let j = from_json(&to_json(&d)).unwrap();
        assert_eq!((j.steps, j.chain[0].not_after, j.target), (d.steps, d.chain[0].not_after, d.target));
    }

    #[test]
    fn bad_certificates_end_it() {
        let (c, other) = (ca(), ca());
        let now = kube::now_secs();
        let ok = "HTTP/1.1 200 OK\r\n\r\n";
        for (names, days, check, want) in [
            (vec!["localhost"], (-90, -5), trust(&c), "it expired"),
            (vec!["other.example.com"], (-9, 90), trust(&c), "it's for other.example.com, not for localhost"),
            (vec!["localhost"], (-9, 90), trust(&other), "wasn't signed by the authority it names"),
            (vec!["localhost"], (5, 90), trust(&c), "valid only from"),
            // The system knows none of these either.
            (vec!["localhost"], (-9, 90), system_check(), "doesn't trust who signed"),
        ] {
            let (port, seen) = serve(&c, &names, days, ok);
            let d = run_with(&target("localhost", port, Mode::Https), check, now);
            let s = d.head().unwrap();
            assert_eq!((s.what, s.tone), ("TLS", Tone::Danger));
            assert!(s.said.contains(want), "{want}: {} {:?}", s.said, s.more);
            // The chain is there to look at, and nothing was sent.
            assert_eq!(d.chain.len(), 1);
            std::thread::sleep(Duration::from_millis(50));
            assert!(seen.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn chains_read() {
        let now = 1_000_000;
        let c = |names: &[&str], until: i64| CertInfo { subject: "x".into(), subject_full: "CN=x".into(), issuer_full: "CN=y".into(), alt_names: names.iter().map(|n| ("DNS", n.to_string())).collect(), not_before: Some(0), not_after: Some(until), ..Default::default() };
        let f = |l: &[CertInfo], h: &str| chain_faults(l, h, now).into_iter().map(|x| x.0).collect::<Vec<_>>().join("; ");
        assert_eq!(f(&[c(&["*.example.com"], now + 1)], "a.example.com"), "");
        assert!(f(&[c(&["*.example.com"], now + 1)], "a.b.example.com").starts_with("it's for *.example.com"));
        assert!(f(&[c(&["*.example.com"], now + 1)], "example.com").starts_with("it's for"));
        assert!(f(&[c(&["a"], now + 1), c(&[], now - 1)], "a").contains("issuer"));
        let own = CertInfo { issuer_full: "CN=x".into(), ..c(&["a"], now + 1) };
        assert_eq!(f(&[own], "a"), "it's signed by itself");
        let ip = CertInfo { alt_names: vec![("IP", "192.0.2.1".into())], ..c(&[], now + 1) };
        assert_eq!(f(&[ip.clone()], "192.0.2.1"), "");
        assert!(f(&[ip], "192.0.2.2").contains("not for 192.0.2.2"));
    }

    #[test]
    fn where_it_stops() {
        let none = || Err("not needed".to_string());
        let now = kube::now_secs();
        // A name that can't be (RFC 2606).
        let d = run_with(&target("nothing.invalid", 443, Mode::Https), none(), now);
        assert_eq!((d.steps.len(), d.steps[0].what, d.tone()), (1, "Name", Tone::Danger));
        // Nothing listens.
        // (Another test may take a port that was just freed: a few are tried.)
        let refused = (0..8).any(|_| {
            let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            run_with(&target("127.0.0.1", port, Mode::Tcp), none(), now).steps[0].said.contains("refused")
        });
        assert!(refused);
        // Only a connection.
        let open = plain(|_| {});
        let d = run_with(&target("127.0.0.1", open, Mode::Tcp), none(), now);
        assert_eq!((d.steps.len(), d.tone()), (1, Tone::Success));
        // A web answer that points elsewhere: shown without its query, not followed.
        let asked = Arc::new(Mutex::new(0));
        let n = asked.clone();
        let web = plain(move |mut s| {
            *n.lock().unwrap() += 1;
            let _ = s.read(&mut [0; 1024]);
            let _ = s.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://login.example.com/in?state=secret#x\r\n\r\n");
        });
        let d = run_with(&target("127.0.0.1", web, Mode::Http), none(), now);
        assert_eq!((d.tone(), d.steps[1].said.as_str()), (Tone::Success, "302: it points to https://login.example.com/in"));
        assert_eq!(*asked.lock().unwrap(), 1);
        // What the router says.
        let web = plain(|mut s| {
            let _ = s.read(&mut [0; 1024]);
            let _ = s.write_all(b"HTTP/1.0 503 Service Unavailable\r\n\r\n<html>");
        });
        assert!(run_with(&target("127.0.0.1", web, Mode::Http), none(), now).steps[1].said.starts_with("503"));
        // Not TLS; not a web server; hangs up.
        let c = ca();
        let odd = plain(|mut s| {
            let _ = s.write_all(b"SSH-2.0-OpenSSH\r\n\r\n");
            let _ = s.read(&mut [0; 1024]);
        });
        assert_eq!(run_with(&target("127.0.0.1", odd, Mode::Tls), trust(&c), now).head().unwrap().said, "What answers there doesn't talk TLS");
        assert_eq!(run_with(&target("127.0.0.1", odd, Mode::Http), none(), now).head().unwrap().said, "Something answers, but not a web server");
        let shut = plain(drop);
        assert_eq!(run_with(&target("127.0.0.1", shut, Mode::Http), none(), now).tone(), Tone::Danger);
    }

    #[test]
    fn slow_ones_are_given_up() {
        // One byte at a time would otherwise go on for ever.
        let port = plain(|mut s| {
            for _ in 0..200 {
                if s.write_all(b"H").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(60));
            }
        });
        let mut s = Timed { s: TcpStream::connect(("127.0.0.1", port)).unwrap(), until: Instant::now() + Duration::from_millis(400) };
        let began = Instant::now();
        let a = ask_web(&mut s, &target("127.0.0.1", port, Mode::Http));
        assert!(began.elapsed() < Duration::from_secs(2));
        assert_eq!((a.tone, a.said.as_str()), (Tone::Danger, "No answer: no answer in time"));
    }

    #[test]
    fn answers() {
        assert_eq!(read_answer("HTTP/1.1 200 OK\r\nServer: x"), Some((200, None)));
        assert_eq!(read_answer("HTTP/2 301\r\nlocation:/new?a=1\r\n"), Some((301, Some("/new".into()))));
        assert_eq!(read_answer("220 mail ready"), None);
    }
}
