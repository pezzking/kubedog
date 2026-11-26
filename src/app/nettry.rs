//! Network Lab: tests from inside a pod, with what its container has. Only behind the lock and after a
//! confirmation; every one gets a line in the list of what was run. The result stands next to the path as
//! it should be: the difference is the find.

use super::dash::line;
use super::face::{many, Face, Fact, Side};
use super::incident::chip_button;
use super::nethelp::{self, Make};
use super::netpath::{self, End, PathStep, Say};
use super::nettest::{Mode, Step};
use super::ops::{ago, table, text, Item};
use super::pg::{label_at, panel, pill};
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;
use std::collections::VecDeque;

/// The limits of a matrix.
pub(super) const SOURCES: usize = 10;
pub(super) const TRIES: usize = 200;
const AT_ONCE: usize = 4;

/// What runs in the container. Host, port, way and path are its arguments, never part of it. It looks at
/// what the container has and uses the best; every part ends by itself (there's no `timeout` everywhere).
const SCRIPT: &str = r#"h=$1; p=$2; m=$3; u=$4
has() { command -v "$1" >/dev/null 2>&1; }
lim() { s=$1; shift; "$@" </dev/null & c=$!; ( sleep "$s"; kill "$c" ) >/dev/null 2>&1 & w=$!; wait "$c"; r=$?; kill "$w" >/dev/null 2>&1; return "$r"; }
T=; for x in getent nslookup curl bash nc python3 wget openssl; do if has "$x"; then T="$T $x"; fi; done
echo "KD tools$T"
part() { echo "KD begin $1 $2"; shift 2; lim "$@" 2>&1; e=$?; echo; echo "KD end $e"; }
if has getent; then part name getent 6 getent ahosts "$h"
elif has nslookup; then part name nslookup 6 nslookup "$h"
elif has python3; then part name python3 6 python3 -c 'import socket,sys
for a in socket.getaddrinfo(sys.argv[1],None): print(a[4][0])' "$h"; fi
case "$h" in *:*) a="[$h]";; *) a="$h";; esac
if has bash; then part tcp bash 5 bash -c 'exec 3<>"/dev/tcp/$0/$1" && echo connected' "$h" "$p"
elif has python3; then part tcp python3 6 python3 -c 'import socket,sys
socket.create_connection((sys.argv[1],int(sys.argv[2])),4); print("connected")' "$h" "$p"
elif has nc && nc -h 2>&1 | grep -q -e '-z'; then part tcp nc 6 nc -v -z -w 4 "$h" "$p"
elif has curl && curl -V 2>/dev/null | grep -q telnet; then part tcp curl 7 curl -sv --noproxy '*' --connect-timeout 4 -m 5 "telnet://$a:$p"; fi
case "$m" in
TLS) if has openssl; then part tls openssl 8 openssl s_client -connect "$a:$p" -servername "$h" -verify_hostname "$h" -showcerts; fi;;
HTTP) if has curl; then part web curl 9 curl -s -o /dev/null --noproxy '*' --connect-timeout 4 -m 8 -w 'code=%{http_code} to=%{redirect_url}' "http://$a:$p$u"; fi;;
HTTPS) if has curl; then part web curl 9 curl -sS -o /dev/null --noproxy '*' --connect-timeout 4 -m 8 -w 'code=%{http_code} to=%{redirect_url}' "https://$a:$p$u"; fi;;
esac
echo "KD done"
"#;

#[derive(Clone, PartialEq, Debug)]
pub(super) struct Try {
    pub ctx: String,
    pub from: Selected,
    pub pod: String,
    pub container: String,
    pub to: End,
    /// How the other end is called on the page.
    pub label: String,
    pub host: String,
    pub port: u16,
    pub mode: Mode,
    /// With a helper: how.
    pub helper: Option<Helper>,
}

/// A helper that runs the test.
#[derive(Clone, PartialEq, Debug)]
pub(super) struct Helper {
    pub image: String,
    pub openshift: bool,
    /// A pod of its own; else a container beside the app's, as this user.
    pub make: Option<Make>,
    pub user: Option<i64>,
    /// Where its pod is made.
    pub ns: String,
}

impl Try {
    fn command(&self) -> Vec<String> {
        ["sh", "-c", SCRIPT, "try", &self.host, &self.port.to_string(), self.mode.word(), "/"].iter().map(|s| s.to_string()).collect()
    }
    pub fn run(&self, k: &Kubectl) -> Result<String, String> {
        match &self.helper {
            None => k.run_for(&self.args(), Duration::from_secs(60)),
            Some(h) => match &h.make {
                None => nethelp::run_beside(k, &self.ctx, &self.from.ns, &self.pod, h.user, &h.image, &self.command()),
                Some(m) => {
                    let name = nethelp::new_name("test");
                    nethelp::run_in_pod(k, &self.ctx, &h.ns, &name, &nethelp::pod_json(&name, &h.ns, &h.image, m, 60, h.openshift), &self.command(), 60)
                }
            },
        }
    }
    fn key(&self) -> String {
        format!("{}|{}/{}|{}", self.ctx, self.from.ns, self.from.name, self.column())
    }
    fn column(&self) -> String {
        format!("{}:{} {}", self.label, self.port, self.mode.word())
    }
    pub fn args(&self) -> Vec<String> {
        ["--context", &self.ctx, "-n", &self.from.ns, "exec", &self.pod, "-c", &self.container, "--"].iter().map(|s| s.to_string()).chain(self.command()).collect()
    }
}

/// What came of it.
#[derive(Clone)]
pub(super) struct Tried {
    pub t: Try,
    pub at: i64,
    pub expected: Say,
    pub path: Vec<PathStep>,
    pub steps: Vec<Step>,
    pub tools: Vec<String>,
    /// It couldn't be run at all.
    pub failed: Option<String>,
}

/// Where it starts, in words.
fn from_label(s: &Selected) -> String {
    match s.kind {
        Kind::Namespaces => format!("namespace {}", s.name),
        Kind::Nodes => format!("node {}", s.name),
        _ => format!("{}/{}", s.ns, s.name),
    }
}

/// Did it connect? None: not known.
fn connected(steps: &[Step]) -> Option<bool> {
    let s = steps.iter().find(|s| s.what == "Connection")?;
    match s.tone {
        Tone::Success => Some(true),
        Tone::Danger => Some(false),
        _ => None,
    }
}

impl Tried {
    /// The find: what's said of it, next to what was expected.
    pub fn verdict(&self) -> (Tone, &'static str) {
        if self.failed.is_some() {
            return (Tone::Muted, "couldn't be tried");
        }
        let later = self.steps.iter().any(|s| s.tone == Tone::Danger && !matches!(s.what, "Name" | "Connection"));
        match (connected(&self.steps), self.expected) {
            (None, _) if self.steps.iter().any(|s| s.what == "Name" && s.tone == Tone::Danger) => (Tone::Danger, "the name fails"),
            (None, _) => (Tone::Muted, "not known"),
            (Some(true), Say::No) => (Tone::Warning, "works, though it shouldn't"),
            (Some(true), _) if later => (Tone::Warning, "connects, but fails later"),
            (Some(true), _) => (Tone::Success, "works"),
            (Some(false), Say::No) => (Tone::Info, "stopped, as expected"),
            (Some(false), Say::Yes) => (Tone::Danger, "fails, though it should work"),
            (Some(false), _) => (Tone::Danger, "fails"),
        }
    }
}

/// A line in the list of what was run.
#[derive(Clone)]
pub(super) struct Ran {
    pub at: i64,
    pub ctx: String,
    pub what: String,
    pub place: String,
}

#[derive(Default)]
pub(super) struct Tries {
    from: Vec<Selected>,
    to: Vec<(End, u16)>,
    find_from: String,
    find_to: String,
    port: String,
    address: String,
    mode: usize,
    queue: VecDeque<Try>,
    running: usize,
    total: usize,
    /// Under way, by number.
    out: HashMap<u64, Try>,
    last: u64,
    pub done: Vec<Tried>,
    pub open: Option<usize>,
    /// What was run from this page, the newest last.
    pub ran: Vec<Ran>,
}

const MODES: [Mode; 4] = [Mode::Tcp, Mode::Tls, Mode::Http, Mode::Https];

// ---------- reading what came back ----------

/// The parts of the answer: (what, with which program, its text, how it ended).
fn parts(out: &str) -> Vec<(String, String, String, i64)> {
    let mut v = vec![];
    let mut now: Option<(String, String, String)> = None;
    for l in out.lines() {
        if let Some(r) = l.strip_prefix("KD begin ") {
            let (a, b) = r.split_once(' ').unwrap_or((r, ""));
            now = Some((a.into(), b.into(), String::new()));
        } else if let Some(r) = l.strip_prefix("KD end ") {
            if let Some((a, b, t)) = now.take() {
                v.push((a, b, t, r.trim().parse().unwrap_or(-1)));
            }
        } else if let Some(x) = now.as_mut() {
            if x.2.len() < 40_000 {
                x.2.push_str(l);
                x.2.push('\n');
            }
        }
    }
    v
}

fn st(what: &'static str, tone: Tone, said: impl Into<String>) -> Step {
    Step { what, tone, said: said.into(), ms: None, more: vec![] }
}

/// The addresses in a look-up's answer. (`nslookup` begins with the name server's own.)
fn ips(tool: &str, t: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    let mut answer = tool != "nslookup";
    for l in t.lines() {
        if tool == "nslookup" && (l.starts_with("Name:") || l.contains("answer:")) {
            answer = true;
        }
        if !answer {
            continue;
        }
        for w in l.split_whitespace() {
            if w.parse::<std::net::IpAddr>().is_ok() && !v.iter().any(|x| x == w) {
                v.push(w.to_string());
            }
        }
    }
    v
}

/// Why a connection failed, from what the program said and how it ended.
fn no_connection(t: &str, code: i64) -> (Tone, String) {
    let low = t.to_lowercase();
    if low.contains("refused") {
        (Tone::Danger, "refused: it's reached, but nothing listens on that port".into())
    } else if low.contains("timed out") || low.contains("timeout") || low.contains("terminated") || matches!(code, 28 | 124 | 137 | 143) {
        (Tone::Danger, "no answer in time: usually a policy or firewall that drops it".into())
    } else if low.contains("no route") || low.contains("unreachable") {
        (Tone::Danger, "there's no route to it".into())
    } else if low.contains("resolve") || low.contains("bad address") || low.contains("not known") || low.contains("unknown host") || code == 6 {
        (Tone::Danger, "its name can't be found".into())
    } else if low.contains("not supported") || low.contains("invalid option") || low.contains("usage:") || low.contains("no such file or directory") {
        (Tone::Muted, "not known: the program in the container can't do this".into())
    } else if code == 1 && t.trim().is_empty() {
        // nc says nothing.
        (Tone::Danger, "it doesn't connect".into())
    } else {
        (Tone::Danger, format!("it doesn't connect: {}", truncate(t.trim().lines().last().unwrap_or(""), 120)))
    }
}

/// (the programs it has, the steps)
pub(super) fn read(out: &str, t: &Try) -> (Vec<String>, Vec<Step>) {
    let tools: Vec<String> = out.lines().find_map(|l| l.strip_prefix("KD tools")).map(|l| l.split_whitespace().map(String::from).collect()).unwrap_or_default();
    let p = parts(out);
    let part = |w: &str| p.iter().find(|x| x.0 == w);
    let mut v = vec![];
    let is_ip = t.host.parse::<std::net::IpAddr>().is_ok();
    if !is_ip {
        v.push(match part("name") {
            None => st("Name", Tone::Muted, "not looked up by itself: no program for it in the container"),
            Some((_, tool, x, code)) => {
                let l = ips(tool, x);
                if l.is_empty() {
                    st("Name", Tone::Danger, if matches!(code, 137 | 143) { "the name servers don't answer in time" } else { "the name can't be found from this pod" })
                } else {
                    st("Name", Tone::Success, l.join(", "))
                }
            }
        });
    }
    v.push(match part("tcp") {
        None => st("Connection", Tone::Muted, "not tried: nothing in the container can connect (curl, bash, nc, python3)"),
        Some((_, tool, x, code)) => {
            let low = x.to_lowercase();
            let yes = match tool.as_str() {
                "curl" => low.contains("* connected to") || low.contains("established connection to"),
                "nc" => *code == 0,
                _ => low.lines().any(|l| l == "connected"),
            };
            if yes {
                st("Connection", Tone::Success, format!("connected to port {}", t.port))
            } else {
                let (tone, w) = no_connection(x, *code);
                st("Connection", tone, w)
            }
        }
    });
    // Some look-up programs (BusyBox) don't search like others do: if it connects by its name, that's found.
    if connected(&v) == Some(true) || v.iter().any(|s| s.what == "Connection" && s.tone == Tone::Danger && !s.said.contains("name can't")) {
        if let (Some(n), Some((_, tool, _, _))) = (v.iter_mut().find(|s| s.what == "Name" && s.tone == Tone::Danger), part("name")) {
            *n = st("Name", Tone::Muted, format!("found, though {tool} in the container doesn't find it"));
        }
    }
    let went = connected(&v) != Some(false);
    if t.mode == Mode::Tls && went {
        v.push(match part("tls") {
            None => st("TLS", Tone::Muted, "not tried: no openssl in the container"),
            Some((_, _, x, _)) => {
                let code = x.lines().filter_map(|l| l.trim().strip_prefix("Verify return code: ")).next_back();
                let ver = x.lines().find_map(|l| l.trim().strip_prefix("New, ")).map(|l| l.split(',').next().unwrap_or("").trim().to_string()).unwrap_or_default();
                match code {
                    Some(c) if c.starts_with("0 ") => st("TLS", Tone::Success, format!("{ver}, the container trusts the certificate")),
                    Some(c) if x.contains("BEGIN CERTIFICATE") => st("TLS", Tone::Danger, format!("The container doesn't accept the certificate: {}", truncate(c, 80))),
                    _ => st("TLS", Tone::Danger, "TLS fails: no certificate came"),
                }
            }
        });
    }
    if matches!(t.mode, Mode::Http | Mode::Https) && went {
        v.push(match part("web") {
            None => st("Answer", Tone::Muted, "not asked: no curl in the container"),
            Some((_, _, x, code)) => {
                let n: i64 = x.split("code=").nth(1).and_then(|r| r.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()).unwrap_or(0);
                let to = x.split(" to=").nth(1).map(|r| r.split_whitespace().next().unwrap_or("").split(['?', '#']).next().unwrap_or("").to_string()).filter(|r| !r.is_empty());
                match (n, code) {
                    (0, 60 | 51) => st("TLS", Tone::Danger, format!("The container doesn't accept the certificate: {}", truncate(x.lines().find(|l| l.contains("curl:")).unwrap_or("").trim_start_matches("curl: "), 140))),
                    (0, 35) => st("TLS", Tone::Danger, "TLS fails: what answers there may not talk TLS"),
                    (0, 52) => st("Answer", Tone::Danger, "it hung up without answering"),
                    (0, 28 | 143) => st("Answer", Tone::Danger, "no answer in time"),
                    (0, _) => st("Answer", Tone::Danger, "no web answer"),
                    (c, _) if c >= 500 => st("Answer", Tone::Danger, format!("{c}: the server failed")),
                    (404, _) => st("Answer", Tone::Warning, "404: it answers, but has nothing at this path"),
                    (c, _) => st("Answer", Tone::Success, match to { Some(x) => format!("{c}: it points to {}", truncate(&x, 120)), None => format!("{c}: it answers") }),
                }
            }
        });
    }
    (tools, v)
}

/// Why it couldn't be run.
fn not_run(e: &str) -> String {
    let low = e.to_lowercase();
    if low.contains("executable file not found") || low.contains("no such file or directory") || low.contains("exit code 127") || low.contains("exit code 126") {
        return "this container has no shell: it can only be tested from with a helper".into();
    }
    if is_refusal(e) {
        return "your account may not run commands in this pod".into();
    }
    truncate(e, 200)
}

impl KubedogApp {
    /// A test from a pod, with the path as it should be. Nothing is run yet.
    fn make_try(&self, from: &Selected, to: &End, port: u16, mode: Mode) -> Result<(Try, Say, Vec<PathStep>), String> {
        let path = self.net_path(&from.ctx, &End::Object(from.clone()), to, port as i64, "TCP");
        let Some(p) = &path.from_pod else { return Err(format!("{} has no running pod", from.name)) };
        if path.host.is_empty() {
            return Err("The other end has no address to try.".into());
        }
        let label = match to {
            End::Object(s) => format!("{}/{}", s.ns, s.name),
            End::Address(h) => h.clone(),
            End::Outside => return Err("Give an address outside.".into()),
        };
        // Not in the mesh's own container.
        let c = p["spec"]["containers"].as_array().into_iter().flatten().find(|c| !matches!(c["name"].as_str(), Some("istio-proxy" | "linkerd-proxy"))).map(|c| text(&c["name"])).unwrap_or_default();
        Ok((Try { ctx: from.ctx.clone(), from: from.clone(), pod: name_of(p).into(), container: c, to: to.clone(), label, host: path.host.clone(), port, mode, helper: self.needed_helper(from)? }, netpath::sum(&path.steps), path.steps))
    }

    /// From a namespace or a node it only goes with a helper.
    fn needed_helper(&self, from: &Selected) -> Result<Option<Helper>, String> {
        let (make, ns) = match from.kind {
            Kind::Namespaces => (Make::Plain, from.name.clone()),
            Kind::Nodes => (Make::NodeNet(from.name.clone()), self.helper_home()),
            _ => return Ok(None),
        };
        Ok(Some(Helper { image: self.helper_ready(&from.ctx)?, openshift: self.is_openshift(&from.ctx), make: Some(make), user: None, ns }))
    }

    /// The same test again, from a container beside the app's.
    fn ask_beside(&mut self, d: &Tried) {
        if self.screenshot.is_some() {
            return;
        }
        let image = match self.helper_ready(&d.t.ctx) {
            Ok(i) => i,
            Err(e) => return self.toast(e, true),
        };
        // As the app's own user, so the same rules are for it.
        let pod = self.refs(&d.t.ctx, Kind::Pods, &d.t.from.ns).unwrap_or_default().into_iter().find(|p| name_of(p) == d.t.pod);
        let user = pod.and_then(|p| p["spec"]["containers"][0]["securityContext"]["runAsUser"].as_i64().or(p["spec"]["securityContext"]["runAsUser"].as_i64()));
        let t = Try { helper: Some(Helper { image: image.clone(), openshift: self.is_openshift(&d.t.ctx), make: None, user, ns: d.t.from.ns.clone() }), ..d.t.clone() };
        let body = format!("Test {} on port {} from pod “{}” in namespace “{}”, with a helper container beside the app's, from image {image}? It shares the pod's network, so it's the true test. It ends by itself, but stays listed in the pod (ended) until the pod restarts.", t.host, t.port, t.pod, t.from.ns);
        self.request(Action::NetTry { tries: vec![t] }, "Test with a helper".into(), body, "Run", false);
    }

    /// Asks for the lock and a confirmation; only then it's run.
    pub(super) fn ask_tries(&mut self, l: Vec<(Selected, End, u16)>, mode: Mode) {
        if self.screenshot.is_some() {
            return;
        }
        let mut v = vec![];
        for (f, t, p) in l.into_iter().take(TRIES) {
            match self.make_try(&f, &t, p, mode) {
                Ok(x) => v.push(x.0),
                Err(e) => self.toast(e, true),
            }
        }
        let Some(first) = v.first().cloned() else { return };
        let mut pods: Vec<String> = v.iter().map(|t| format!("{}/{}", t.from.ns, t.pod)).collect();
        pods.sort();
        pods.dedup();
        let what = match mode {
            Mode::Tcp => "It looks the name up and opens a connection and closes it again; nothing is sent.",
            Mode::Tls => "It looks the name up, opens a connection and starts TLS; nothing is asked over it.",
            _ => "It looks the name up, connects and asks for the page “/”; the answer isn't kept.",
        };
        let body = if v.len() == 1 {
            format!("Test {} on port {} from pod “{}”, container “{}”, in namespace “{}”? A short command runs in that container (kubectl exec). {what}", first.host, first.port, first.pod, first.container, first.from.ns)
        } else {
            let mut ends: Vec<String> = v.iter().map(|t| format!("{}:{}", t.host, t.port)).collect();
            ends.sort();
            ends.dedup();
            format!("Run {} from {}: {}? To: {}. A short command runs in each of these pods (kubectl exec), {AT_ONCE} at a time. {what}", many(v.len() as i64, "test"), many(pods.len() as i64, "pod"), pods.join(", "), truncate(&ends.join(", "), 500))
        };
        // What's made, when something is.
        let mut made: Vec<String> = v
            .iter()
            .filter_map(|t| t.helper.as_ref())
            .filter_map(|h| {
                let m = h.make.as_ref()?;
                let control = matches!(m, Make::NodeNet(n) if self.control_plane(&first.ctx, n));
                Some(nethelp::in_words(m, &h.image, 60, &h.ns, control))
            })
            .collect();
        made.sort();
        made.dedup();
        let body = if made.is_empty() { body } else { format!("{body}\n\n{}", made.join("\n")) };
        self.request(Action::NetTry { tries: v }, "Test from a pod".into(), body, "Run", false);
    }

    /// Confirmed.
    pub(super) fn start_tries(&mut self, v: Vec<Try>) {
        let t = &mut self.netlab.tries;
        if t.queue.is_empty() && t.running == 0 {
            t.total = 0;
        }
        let now = kube::now_secs();
        for x in v {
            t.total += 1;
            t.ran.push(Ran { at: now, ctx: x.ctx.clone(), what: format!("test of {}:{} ({})", x.host, x.port, x.mode.word()), place: match x.helper.as_ref().map(|h| (&h.make, &h.image)) {
                None => format!("pod {}/{}, container {}", x.from.ns, x.pod, x.container),
                Some((None, i)) => format!("pod {}/{}, with a helper from {i}", x.from.ns, x.pod),
                Some((Some(Make::Plain), i)) => format!("a helper pod in {}, from {i}", x.from.name),
                Some((Some(_), i)) => format!("a helper pod on node {}, from {i}", x.from.name),
            } });
            t.queue.push_back(x);
        }
        self.pump_tries();
    }

    fn pump_tries(&mut self) {
        while self.netlab.tries.running < AT_ONCE {
            let Some(t) = self.netlab.tries.queue.pop_front() else { return };
            self.netlab.tries.running += 1;
            self.netlab.tries.last += 1;
            let id = self.netlab.tries.last;
            self.netlab.tries.out.insert(id, t.clone());
            self.spawn(move |k| Msg::Text { key: format!("nettry|{id}"), result: t.run(k) });
        }
    }

    pub(super) fn on_tried(&mut self, key: &str, r: &Result<String, String>) -> bool {
        let Some(id) = key.strip_prefix("nettry|").and_then(|i| i.parse::<u64>().ok()) else { return false };
        let Some(t) = self.netlab.tries.out.remove(&id) else { return true };
        self.netlab.tries.running = self.netlab.tries.running.saturating_sub(1);
        let (expected, path) = self.make_try(&t.from, &t.to, t.port, t.mode).map(|x| (x.1, x.2)).unwrap_or((Say::Unknown, vec![]));
        let mut d = Tried { at: kube::now_secs(), expected, path, steps: vec![], tools: vec![], failed: None, t };
        match r {
            Ok(out) if out.contains("KD done") => (d.tools, d.steps) = read(out, &d.t),
            Ok(_) => d.failed = Some("it broke off".into()),
            Err(e) => d.failed = Some(not_run(e)),
        }
        let l = &mut self.netlab.tries.done;
        match l.iter_mut().find(|x| x.t.key() == d.t.key()) {
            Some(x) => *x = d,
            None => l.push(d),
        }
        self.pump_tries();
        true
    }

    /// The result of a test between two ends, if there is one.
    pub(super) fn tried(&self, a: &Selected, b: &End, port: i64) -> Option<&Tried> {
        self.netlab.tries.done.iter().filter(|d| d.t.from == *a && d.t.to == *b && d.t.port as i64 == port).max_by_key(|d| d.at)
    }

    pub(super) fn net_from_pod(&mut self, ui: &mut Ui) -> Option<Go> {
        // For pictures: made-up results.
        if self.screenshot.is_some() && self.netlab.tries.done.is_empty() {
            if let Ok(p) = std::env::var("KUBEDOG_SHOT_NETTRY") {
                self.made_up_tries(&p);
            }
        }
        if let Some(d) = self.netlab.tries.open.and_then(|i| self.netlab.tries.done.get(i)).cloned() {
            return self.tried_page(ui, &d);
        }
        self.pick_tries(ui);
        ui.add_space(10.0);
        if !self.netlab.tries.done.is_empty() || self.netlab.tries.running > 0 {
            self.tries_matrix(ui);
            ui.add_space(10.0);
        }
        let a = self.leftovers(ui);
        self.ran_list(ui).or(a)
    }

    pub(super) fn control_plane(&self, ctx: &str, node: &str) -> bool {
        self.refs(ctx, Kind::Nodes, "").unwrap_or_default().into_iter().filter(|n| name_of(n) == node).any(|n| ["node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master"].iter().any(|k| !n["metadata"]["labels"][*k].is_null()))
    }

    fn pick_tries(&mut self, ui: &mut Ui) {
        let mut drop_from = None;
        let mut drop_to = None;
        card(ui, |ui| {
            panel(ui, "From", &format!("workloads or pods, up to {SOURCES}; one running pod of each is used"));
            (!self.netlab.tries.from.is_empty()).then(|| ui.horizontal_wrapped(|ui| {
                for (i, s) in self.netlab.tries.from.iter().enumerate() {
                    if chip_button(ui, &format!("{}  ×", from_label(s)), true) {
                        drop_from = Some(i);
                    }
                }
            }));
            filter_box(ui, &mut self.netlab.tries.find_from, "name", u(320.0));
            if !self.netlab.tries.find_from.is_empty() || self.netlab.tries.from.is_empty() {
                let mut kinds = vec![Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::Pods];
                // With a helper also from a namespace or a node.
                if !self.netlab.tries.find_from.is_empty() && self.active.iter().any(|c| self.helpers_on(c)) {
                    kinds.extend([Kind::Namespaces, Kind::Nodes]);
                }
                let l: Vec<Selected> = self.find_ends(&self.netlab.tries.find_from, &kinds).into_iter().filter(|s| !matches!(s.kind, Kind::Namespaces | Kind::Nodes) || self.helpers_on(&s.ctx)).collect();
                ui.horizontal_wrapped(|ui| {
                    for s in l {
                        if chip_button(ui, &if s.ns.is_empty() { from_label(&s) } else { format!("{}/{} · {}", s.ns, s.name, s.kind.singular()) }, false) && !self.netlab.tries.from.contains(&s) && self.netlab.tries.from.len() < SOURCES {
                            // One cluster at a time.
                            if self.netlab.tries.from.first().map(|f| f.ctx != s.ctx).unwrap_or(false) {
                                self.netlab.tries.from.clear();
                                self.netlab.tries.to.retain(|t| matches!(t.0, End::Address(_)));
                            }
                            self.netlab.tries.from.push(s);
                            self.netlab.tries.find_from.clear();
                        }
                    }
                });
            }
        });
        ui.add_space(8.0);
        card(ui, |ui| {
            panel(ui, "To", "services, or an address with its port");
            (!self.netlab.tries.to.is_empty()).then(|| ui.horizontal_wrapped(|ui| {
                for (i, (e, p)) in self.netlab.tries.to.iter().enumerate() {
                    let n = match e {
                        End::Object(s) => format!("{}/{}", s.ns, s.name),
                        End::Address(h) => h.clone(),
                        End::Outside => String::new(),
                    };
                    if chip_button(ui, &format!("{n}:{p}  ×"), true) {
                        drop_to = Some(i);
                    }
                }
            }));
            ui.horizontal_wrapped(|ui| {
                filter_box(ui, &mut self.netlab.tries.find_to, "service", u(320.0));
                ui.add(egui::TextEdit::singleline(&mut self.netlab.tries.port).hint_text("port").desired_width(u(70.0))).on_hover_text("Empty: every TCP port of the service");
                ui.add_space(12.0);
                let r = ui.add(egui::TextEdit::singleline(&mut self.netlab.tries.address).hint_text("or host:port").desired_width(u(220.0)));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if button(ui, "Add", false, false) || enter {
                    match nettest::read_target(&self.netlab.tries.address) {
                        Ok(t) => {
                            let e = (End::Address(t.host), t.port);
                            if !self.netlab.tries.to.contains(&e) {
                                self.netlab.tries.to.push(e);
                            }
                            self.netlab.tries.address.clear();
                        }
                        Err(e) => self.toast(e, true),
                    }
                }
            });
            if !self.netlab.tries.find_to.is_empty() || self.netlab.tries.to.is_empty() {
                let ctx = self.netlab.tries.from.first().map(|f| f.ctx.clone());
                let l = self.find_ends(&self.netlab.tries.find_to, &[Kind::Services]);
                ui.horizontal_wrapped(|ui| {
                    for s in l.into_iter().filter(|s| ctx.as_ref().map(|c| *c == s.ctx).unwrap_or(true)) {
                        if chip_button(ui, &format!("{}/{}", s.ns, s.name), false) {
                            let own: Vec<u16> = self.object_of(&s).map(|o| o["spec"]["ports"].as_array().into_iter().flatten().filter(|p| p["protocol"].as_str().unwrap_or("TCP") == "TCP").filter_map(|p| p["port"].as_u64().and_then(|p| u16::try_from(p).ok())).collect()).unwrap_or_default();
                            let l = match self.netlab.tries.port.trim().parse::<u16>() {
                                Ok(p) => vec![p],
                                Err(_) => own,
                            };
                            for p in l {
                                let e = (End::Object(s.clone()), p);
                                if !self.netlab.tries.to.contains(&e) {
                                    self.netlab.tries.to.push(e);
                                }
                            }
                            self.netlab.tries.find_to.clear();
                        }
                    }
                });
            }
        });
        if let Some(i) = drop_from {
            self.netlab.tries.from.remove(i);
        }
        if let Some(i) = drop_to {
            self.netlab.tries.to.remove(i);
        }
        ui.add_space(8.0);
        let n = self.netlab.tries.from.len() * self.netlab.tries.to.len();
        let mut go = false;
        ui.horizontal_wrapped(|ui| {
            for (i, m) in MODES.iter().enumerate() {
                if chip_button(ui, m.word(), self.netlab.tries.mode == i) {
                    self.netlab.tries.mode = i;
                }
            }
            ui.add_space(12.0);
            if n > TRIES {
                said(ui, &format!("{n} tests: {TRIES} at most. Take some away."), WARNING());
            } else if n > 0 {
                go = button(ui, &if n == 1 { "Test it".to_string() } else { format!("Run {n} tests") }, true, false);
            }
            said(ui, "Runs a short command in each pod, after you confirm, with what its container has.", TEXT_PLACEHOLDER());
        });
        if go {
            let t = &self.netlab.tries;
            let l = t.from.iter().flat_map(|f| t.to.iter().map(move |(e, p)| (f.clone(), e.clone(), *p))).collect();
            let m = MODES[t.mode.min(3)];
            self.ask_tries(l, m);
        }
    }

    /// Who can reach what: a row for each source, a column for each end.
    fn tries_matrix(&mut self, ui: &mut Ui) {
        let done = self.netlab.tries.done.clone();
        let busy = self.netlab.tries.running + self.netlab.tries.queue.len();
        let mut rows: Vec<String> = vec![];
        let mut cols: Vec<String> = vec![];
        for d in &done {
            let r = from_label(&d.t.from);
            let c = d.t.column();
            if !rows.contains(&r) {
                rows.push(r);
            }
            if !cols.contains(&c) {
                cols.push(c);
            }
        }
        let mut open = None;
        let (mut stop, mut clear) = (false, false);
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Results").size(z(14.5)).strong().color(TEXT_DEFAULT()));
                let odd = done.iter().filter(|d| d.verdict().1.contains("though")).count();
                if odd > 0 {
                    pill(ui, &format!("{odd} not as expected"), DANGER());
                }
                if busy > 0 {
                    ui.spinner();
                    ui.label(RichText::new(format!("{busy} of {} to go", self.netlab.tries.total)).size(z(12.5)).color(TEXT_MUTED()));
                    stop = button(ui, "Stop", false, false);
                } else {
                    clear = button(ui, "Clear", false, false);
                }
            });
            ui.add_space(6.0);
            egui::ScrollArea::horizontal().id_salt("tries").show(ui, |ui| {
                let (w0, w, h) = (u(230.0), u(190.0).max((ui.available_width() - u(230.0)) / cols.len().max(1) as f32).min(u(300.0)), u(32.0));
                let (area, _) = ui.allocate_exact_size(egui::vec2(w0 + w * cols.len() as f32, h * (rows.len() + 1) as f32), Sense::hover());
                for (j, c) in cols.iter().enumerate() {
                    let x = area.left() + w0 + w * j as f32;
                    label_at(ui, ui.painter(), egui::pos2(x + 8.0, area.top() + h / 2.0), c, 12.0, TEXT_SUBTLE(), w - 14.0);
                }
                for (i, r) in rows.iter().enumerate() {
                    let y = area.top() + h * (i + 1) as f32;
                    label_at(ui, ui.painter(), egui::pos2(area.left(), y + h / 2.0), r, 13.0, TEXT_DEFAULT(), w0 - 10.0);
                    for (j, c) in cols.iter().enumerate() {
                        let cell = egui::Rect::from_min_size(egui::pos2(area.left() + w0 + w * j as f32, y), egui::vec2(w, h)).shrink(2.0);
                        let Some(k) = done.iter().position(|d| from_label(&d.t.from) == *r && d.t.column() == *c) else {
                            ui.painter().rect_filled(cell, CornerRadius::same(5), BG_MUTED().gamma_multiply(0.5));
                            continue;
                        };
                        let (t, word) = done[k].verdict();
                        let col = if t == Tone::Muted { TEXT_SUBTLE() } else { tone_color(t) };
                        let resp = ui.interact(cell, ui.id().with(("try", i, j)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                        ui.painter().rect(cell, CornerRadius::same(5), col.gamma_multiply(if resp.hovered() { 0.3 } else { 0.16 }), Stroke::new(1.0, col.gamma_multiply(0.5)), egui::StrokeKind::Inside);
                        label_at(ui, ui.painter(), egui::pos2(cell.left() + 8.0, cell.center().y), word, 12.0, col, w - 18.0);
                        let tip = done[k].failed.clone().unwrap_or(done[k].steps.iter().map(|s| format!("{}: {}", s.what, s.said)).collect::<Vec<_>>().join("\n"));
                        if resp.on_hover_text(format!("{r} to {c}\n{tip}")).clicked() {
                            open = Some(k);
                        }
                    }
                }
            });
        });
        if stop {
            self.netlab.tries.queue.clear();
        }
        if clear {
            self.netlab.tries.done.clear();
        }
        if open.is_some() {
            self.netlab.tries.open = open;
        }
    }

    fn tried_page(&mut self, ui: &mut Ui, d: &Tried) -> Option<Go> {
        let mut go: Option<Go> = None;
        let (mut close, mut again, mut beside) = (false, false, false);
        ui.horizontal(|ui| {
            close = button(ui, "← All tests", false, false);
            again = button(ui, "Test again", false, false);
            let short = d.failed.is_some() || d.steps.iter().any(|s| s.tone == Tone::Muted && s.said.starts_with("not "));
            beside = short && d.t.helper.is_none() && button(ui, "With a helper", false, false);
        });
        ui.add_space(8.0);
        let (tone, word) = d.verdict();
        let mut notes = vec![];
        if let Some(f) = &d.failed {
            notes.push(f.clone());
        }
        match word {
            "fails, though it should work" => notes.push("What the cluster says lets it through, but it doesn't get through: look at what isn't in the objects (the app itself, the network, a firewall on the nodes).".into()),
            "works, though it shouldn't" => notes.push("What the cluster says stops it, but it gets through: the network may not keep to this policy, or something isn't understood here.".into()),
            _ => notes.extend(d.steps.iter().find(|s| s.tone == Tone::Danger).map(|s| format!("{}: {}", s.what, s.said))),
        }
        let mut f: Vec<char> = word.chars().collect();
        f[0] = f[0].to_ascii_uppercase();
        face::show(ui, &Face { tone, head: f.into_iter().collect(), sub: format!("{} to {}, {}", from_label(&d.t.from), d.t.column(), ago(kube::now_secs(), Some(d.at))), notes, pills: vec![], facts: vec![Fact::new("Ran in", format!("{} / {}", d.t.pod, d.t.container)), Fact::new("The container has", if d.tools.is_empty() { "nothing to test with".into() } else { d.tools.join(", ") }), Fact::new("Expected", match d.expected { Say::Yes => "it works", Say::No => "it's stopped", _ => "not sure" })] }, Side::None);
        ui.add_space(10.0);
        steps_card(ui, "As it was", "tried from the pod", &d.steps);
        ui.add_space(10.0);
        let l: Vec<Item> = d.path.iter().map(|s| Item::new(s.say.tone(), vec![s.text.clone(), s.say.word().into()]).tip(s.text.clone()).go(s.go.clone())).collect();
        go = table(ui, "As it should be", "from what the cluster's objects say", &[("Step", 0.86), ("Says", 0.14)], &l, 40, "Not known.").or(go);
        self.trace_part(ui, &d.t.ctx, &End::Object(d.t.from.clone()), &d.t.to, d.t.port as i64, "TCP");
        if close {
            self.netlab.tries.open = None;
        }
        if beside {
            self.ask_beside(d);
        }
        if again {
            self.ask_tries(vec![(d.t.from.clone(), d.t.to.clone(), d.t.port)], d.t.mode);
        }
        go
    }

    /// What was run in the cluster from the Network Lab, so it can be told afterwards.
    pub(super) fn ran_list(&mut self, ui: &mut Ui) -> Option<Go> {
        if self.netlab.tries.ran.is_empty() {
            return None;
        }
        let now = kube::now_secs();
        let l: Vec<Item> = self.netlab.tries.ran.iter().rev().map(|r| Item::new(Tone::Muted, vec![pod::when(r.at), r.what.clone(), r.place.clone(), ctx_label(&r.ctx)]).tip(format!("{}\n{}\n{}", ago(now, Some(r.at)), r.what, r.place))).collect();
        table(ui, &format!("What Kubedog ran ({})", l.len()), "since it was started; each after a confirmation", &[("When", 0.18), ("What", 0.34), ("Where", 0.34), ("Cluster", 0.14)], &l, 60, "")
    }

    fn made_up_tries(&mut self, p: &str) {
        let Some(v) = std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) else { return };
        for x in v.as_array().into_iter().flatten() {
            let sel = Selected { ctx: "made-up".into(), kind: Kind::Deployments, ns: "shop".into(), name: text(&x["from"]) };
            let t = Try { ctx: "made-up".into(), from: sel, pod: format!("{}-7d9f", text(&x["from"])), container: "app".into(), to: End::Outside, label: text(&x["to"]), host: text(&x["to"]), port: x["port"].as_u64().unwrap_or(80) as u16, mode: Mode::Tcp, helper: None };
            let (tools, steps) = read(x["out"].as_str().unwrap_or(""), &t);
            self.netlab.tries.done.push(Tried { expected: match x["expected"].as_str() { Some("yes") => Say::Yes, Some("no") => Say::No, _ => Say::Unknown }, at: kube::now_secs() - 40, path: vec![PathStep { say: Say::Yes, text: "Service db sends port 5432 to port 5432 of its pods".into(), go: None }, PathStep { say: Say::No, text: "In db: May not come in: policy closed is about it and none lets it through".into(), go: None }], steps, tools, failed: x["failed"].as_str().map(String::from), t });
        }
        self.netlab.tries.ran.push(Ran { at: kube::now_secs() - 40, ctx: "made-up".into(), what: "test of db.shop.svc:5432 (connection)".into(), place: "pod shop/web-7d9f, container app".into() });
        self.netlab.tries.open = std::env::var("KUBEDOG_SHOT_OBJ").ok().and_then(|t| t.parse().ok());
    }
}

/// Steps in a card.
pub(super) fn steps_card(ui: &mut Ui, title: &str, hint: &str, steps: &[Step]) {
    card(ui, |ui| {
        panel(ui, title, hint);
        if steps.is_empty() {
            said(ui, "Nothing came of it.", TEXT_SUBTLE());
        }
        for s in steps {
            let (r, resp) = line(ui, u(30.0), false);
            let col = if s.tone == Tone::Muted { TEXT_PLACEHOLDER() } else { tone_color(s.tone) };
            ui.painter().circle_filled(egui::pos2(r.left() + u(6.0), r.center().y), u(5.0), col);
            label_at(ui, ui.painter(), egui::pos2(r.left() + u(20.0), r.center().y), s.what, 13.0, TEXT_DEFAULT(), u(90.0));
            label_at(ui, ui.painter(), egui::pos2(r.left() + u(112.0), r.center().y), &s.said, 13.0, if s.tone == Tone::Success { TEXT_MUTED() } else { col }, r.width() - u(116.0));
            resp.on_hover_text(&s.said);
        }
    });
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::app) fn made(host: &str, mode: Mode) -> Try {
        let s = Selected { ctx: "c".into(), kind: Kind::Pods, ns: "shop".into(), name: "web-1".into() };
        Try { ctx: "c".into(), from: s, pod: "web-1".into(), container: "web".into(), to: End::Address(host.into()), label: host.into(), host: host.into(), port: 5432, mode, helper: None }
    }

    #[test]
    fn arguments() {
        let t = Try { host: "db.shop.svc; rm -rf /".into(), ..made("x", Mode::Tcp) };
        let a = t.args();
        // What's asked for is an argument of the script, not part of it.
        let i = a.iter().position(|x| x == "-c" ).unwrap();
        assert_eq!(a[i + 1], "web");
        let s = a.iter().position(|x| x == SCRIPT).unwrap();
        assert_eq!(&a[s - 3..s], &["--".to_string(), "sh".into(), "-c".into()]);
        assert_eq!(&a[s + 1..], &["try".to_string(), "db.shop.svc; rm -rf /".into(), "5432".into(), "connection".into(), "/".into()]);
        assert!(!SCRIPT.contains("eval") && !SCRIPT.contains("-k ") && !SCRIPT.contains(" -L"));
    }

    fn out(tools: &str, l: &[(&str, &str, &str, i64)]) -> String {
        let mut s = format!("KD tools {tools}\n");
        for (a, b, t, c) in l {
            s += &format!("KD begin {a} {b}\n{t}\n\nKD end {c}\n");
        }
        s + "KD done\n"
    }
    fn said_of(t: &Try, o: &str) -> Vec<(String, Tone)> {
        read(o, t).1.into_iter().map(|s| (s.said, s.tone)).collect()
    }

    #[test]
    fn reads_answers() {
        let t = made("db.shop.svc", Mode::Tcp);
        let o = out("getent curl", &[("name", "getent", "172.30.0.9 STREAM db.shop.svc\n172.30.0.9 DGRAM", 0), ("tcp", "curl", "* Connected to db.shop.svc (172.30.0.9) port 5432", 143)]);
        assert_eq!(said_of(&t, &o), vec![("172.30.0.9".to_string(), Tone::Success), ("connected to port 5432".into(), Tone::Success)]);
        assert_eq!(read(&o, &t).0, vec!["getent", "curl"]);
        for (tool, text, code, want, tone) in [
            ("curl", "* connect to 172.30.0.9 port 5432 failed: Connection refused", 7, "refused", Tone::Danger),
            ("curl", "* Connection timed out after 4001 milliseconds", 28, "no answer in time", Tone::Danger),
            ("bash", "bash: connect: Connection refused", 1, "refused", Tone::Danger),
            ("bash", "", 143, "no answer in time", Tone::Danger),
            ("bash", "bash: connect: No route to host", 1, "no route", Tone::Danger),
            ("nc", "", 1, "it doesn't connect", Tone::Danger),
            ("nc", "nc: bad address 'db'", 1, "name can't be found", Tone::Danger),
            ("nc", "nc: invalid option -- 'z'", 1, "not known", Tone::Muted),
            ("python3", "ConnectionRefusedError: [Errno 111] Connection refused", 1, "refused", Tone::Danger),
        ] {
            let r = said_of(&made("192.0.2.1", Mode::Tcp), &out(tool, &[("tcp", tool, text, code)]));
            assert!(r.len() == 1 && r[0].0.contains(want) && r[0].1 == tone, "{tool} {text}: {r:?}");
        }
        // Nothing to test with.
        let r = said_of(&t, &out("", &[]));
        assert!(r.iter().all(|x| x.1 == Tone::Muted) && r.len() == 2);
        // nslookup's own server isn't the answer.
        let r = said_of(&t, &out("nslookup", &[("name", "nslookup", "Server:\t172.30.0.10\nAddress:\t172.30.0.10:53\n\nName:\tdb.shop.svc\nAddress: 172.30.0.9\n", 0)]));
        assert_eq!(r[0].0, "172.30.0.9");
        let r = said_of(&t, &out("nslookup", &[("name", "nslookup", "Server:\t172.30.0.10\nAddress:\t172.30.0.10:53\n\n** server can't find db: NXDOMAIN", 1)]));
        assert_eq!(r[0], ("the name can't be found from this pod".to_string(), Tone::Danger));
    }

    #[test]
    fn reads_tls_and_web() {
        let up = ("tcp", "bash", "connected", 0);
        let w = |m, l: &[(&str, &str, &str, i64)]| said_of(&made("192.0.2.1", m), &out("x", l)).pop().unwrap();
        assert_eq!(w(Mode::Http, &[up, ("web", "curl", "code=302 to=https://login.example.com/x?state=secret", 0)]).0, "302: it points to https://login.example.com/x");
        assert_eq!(w(Mode::Http, &[up, ("web", "curl", "code=000 to=", 52)]).1, Tone::Danger);
        assert_eq!(w(Mode::Https, &[up, ("web", "curl", "curl: (60) SSL certificate problem: self-signed certificate\ncode=000 to=", 60)]).0, "The container doesn't accept the certificate: (60) SSL certificate problem: self-signed certificate");
        assert_eq!(w(Mode::Http, &[up, ("web", "curl", "code=503 to=", 0)]).1, Tone::Danger);
        assert_eq!(w(Mode::Http, &[up]).1, Tone::Muted);
        assert_eq!(w(Mode::Tls, &[up, ("tls", "openssl", "-----BEGIN CERTIFICATE-----\nNew, TLSv1.3, Cipher is X\nVerify return code: 0 (ok)", 0)]).0, "TLSv1.3, the container trusts the certificate");
        assert_eq!(w(Mode::Tls, &[up, ("tls", "openssl", "-----BEGIN CERTIFICATE-----\nVerify return code: 10 (certificate has expired)", 0)]).1, Tone::Danger);
        // A name that the look-up program misses but the connection finds.
        let r = said_of(&made("web.db.svc", Mode::Tcp), &out("nslookup nc", &[("name", "nslookup", "Server: 10.96.0.10\n** server can't find web.db.svc: NXDOMAIN", 1), ("tcp", "nc", "", 0)]));
        assert_eq!((r[0].1, r[1].1), (Tone::Muted, Tone::Success));
        // Not further when it doesn't connect.
        assert_eq!(said_of(&made("192.0.2.1", Mode::Http), &out("x", &[("tcp", "nc", "", 1)])).len(), 1);
    }

    #[test]
    fn finds() {
        let d = |steps: Vec<Step>, e: Say| Tried { t: made("x", Mode::Tcp), at: 0, expected: e, path: vec![], steps, tools: vec![], failed: None }.verdict();
        let (yes, no, dunno) = (vec![st("Connection", Tone::Success, "")], vec![st("Connection", Tone::Danger, "")], vec![st("Connection", Tone::Muted, "")]);
        assert_eq!(d(yes.clone(), Say::Yes), (Tone::Success, "works"));
        assert_eq!(d(yes.clone(), Say::No), (Tone::Warning, "works, though it shouldn't"));
        assert_eq!(d(no.clone(), Say::No), (Tone::Info, "stopped, as expected"));
        assert_eq!(d(no.clone(), Say::Yes), (Tone::Danger, "fails, though it should work"));
        assert_eq!(d(no, Say::Unknown), (Tone::Danger, "fails"));
        assert_eq!(d(dunno, Say::Yes).0, Tone::Muted);
        let mut late = yes;
        late.push(st("Answer", Tone::Danger, ""));
        assert_eq!(d(late, Say::Yes), (Tone::Warning, "connects, but fails later"));
        assert!(not_run("OCI runtime exec failed: exec: \"sh\": executable file not found in $PATH").contains("no shell"));
    }

    /// A command that hangs is stopped.
    #[cfg(unix)]
    #[test]
    fn hanging_ones_are_stopped() {
        let k = Kubectl { bin: Some("/bin/sh".into()), ..Kubectl::detect() };
        let run = |s: &str, t| k.run_for(&["-c".to_string(), s.to_string()], Duration::from_millis(t));
        let began = Instant::now();
        assert!(run("exec sleep 20", 300).unwrap_err().contains("longer than"));
        assert!(began.elapsed() < Duration::from_secs(5));
        // More than fits in a pipe, and both ways it can end.
        assert_eq!(run("head -c 300000 /dev/zero | tr '\\0' x; echo e >&2", 8000).unwrap().len(), 300000);
        assert_eq!(run("echo why >&2; exit 3", 5000), Err("why".into()));
    }

    /// The script itself, on this computer's own shell, against a port that's open and one that isn't.
    #[cfg(unix)]
    #[test]
    fn script_runs() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = l.local_addr().unwrap().port();
        std::thread::spawn(move || for s in l.incoming() { drop(s) });
        let shut = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        // (Another test may take the port that was just freed: another one then.)
        let shut = (0..8).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()).find(|p| std::net::TcpStream::connect(("127.0.0.1", *p)).is_err()).unwrap_or(shut);
        for (port, want) in [(open, Some(true)), (shut, Some(false))] {
            let o = std::process::Command::new("sh").args(["-c", SCRIPT, "try", "127.0.0.1", &port.to_string(), "connection", "/"]).output().unwrap();
            let t = Try { port, ..made("127.0.0.1", Mode::Tcp) };
            let o = String::from_utf8_lossy(&o.stdout).to_string();
            assert!(o.contains("KD done"));
            assert_eq!(connected(&read(&o, &t).1), want, "{o}");
        }
    }

    /// In the throwaway cluster only: KUBEDOG_KIND is its own kubeconfig, KUBEDOG_TRY is
    /// "namespace pod container host port way".
    #[test]
    #[ignore]
    fn in_kind() {
        let k = nethelp::tests::kind();
        let w = std::env::var("KUBEDOG_TRY").unwrap();
        let w: Vec<&str> = w.split(' ').collect();
        let mode = MODES.into_iter().find(|m| m.word() == w[5]).unwrap();
        let from = Selected { ctx: "kind-kubedog-netlab".into(), kind: Kind::Pods, ns: w[0].into(), name: w[1].into() };
        let mut t = Try { ctx: from.ctx.clone(), from, pod: w[1].into(), container: w[2].into(), port: w[4].parse().unwrap(), ..made(w[3], mode) };
        // "beside", "plain" or "node:name".
        if let Some(h) = w.get(6) {
            let make = match *h {
                "plain" => Some(Make::Plain),
                h if h.starts_with("node:") => Some(Make::NodeNet(h[5..].into())),
                _ => None,
            };
            t.helper = Some(Helper { image: std::env::var("KUBEDOG_IMAGE").unwrap_or("nicolaka/netshoot:v0.13".into()), openshift: false, make, user: None, ns: w[0].into() });
        }
        match t.run(&k) {
            Ok(o) => println!("{:?}", read(&o, &t)),
            Err(e) => println!("not run: {} ({e})", not_run(&e)),
        }
    }
}
