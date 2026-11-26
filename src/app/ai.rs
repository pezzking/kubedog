//! Asking an AI: which one, what it may be told, and the asking. Off by default; one gate decides
//! whether anything may happen at all.

use super::aifacts::{Class, Facts, Standins};
use super::aiharness::{self, Kind as Harness};
use super::face::many;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Where a question ends up.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(super) enum Place {
    Here,
    Server,
    #[default]
    Cloud,
}

pub(super) const PLACES: [(Place, &str); 3] = [(Place::Here, "This computer"), (Place::Server, "Your own server"), (Place::Cloud, "Cloud")];

/// (id, name, what it is).
pub(super) const BACKENDS: [(&str, &str, &str); 7] = [
    ("claude", "Claude Code", "the program is here, its model in a cloud; your own login, without tools"),
    ("codex", "Codex", "the program is here, its model in a cloud; your own login, kept away from your files"),
    ("ollama", "Ollama", "port 11434; some of its models run in a cloud"),
    ("lmstudio", "LM Studio", "port 1234"),
    ("server", "Own server", "anything that speaks the OpenAI way"),
    ("anthropic", "Anthropic", "the cloud service, with a key"),
    ("command", "Own command", "a program you trust: the question on its input, the answer on its output"),
];

pub(super) const AGENT: [(&str, &str); 3] = [("off", "Off"), ("ask", "Ask me each time"), ("auto", "By itself")];

pub(super) fn label(id: &str) -> &'static str {
    BACKENDS.iter().find(|b| b.0 == id).map(|b| b.1).unwrap_or("Auto")
}

#[derive(Clone, PartialEq, Debug)]
pub(super) struct AiPrefs {
    pub on: bool,
    /// The note on the start page was sent away.
    pub hide_note: bool,
    /// "auto" or a backend.
    pub choice: String,
    pub models: HashMap<String, String>,
    pub url: String,
    pub command: String,
    /// A harness that can read files may be used.
    pub files_ok: bool,
    /// It may suggest a change, as text.
    pub suggest: bool,
    /// Here, server, cloud.
    pub facts: [bool; 3],
    pub logs: [bool; 3],
    pub values: [bool; 3],
    pub names: [bool; 3],
    /// Per cluster: a backend, or "never".
    pub clusters: HashMap<String, String>,
    /// Look-ups by the AI: "off", "ask" or "auto".
    pub agent: String,
    /// Per cluster: "watch", or "ai" to let the AI look into new problems by itself. Missing: off.
    pub watch: HashMap<String, String>,
    /// Investigations by itself, an hour.
    pub watch_cap: u32,
}

impl Default for AiPrefs {
    fn default() -> Self {
        AiPrefs {
            on: false,
            hide_note: false,
            choice: "auto".into(),
            models: HashMap::new(),
            url: String::new(),
            command: String::new(),
            files_ok: false,
            suggest: true,
            facts: [true, true, true],
            logs: [true, true, false],
            values: [true, false, false],
            names: [false, false, true],
            clusters: HashMap::new(),
            agent: "off".into(),
            watch: HashMap::new(),
            watch_cap: 3,
        }
    }
}

impl AiPrefs {
    pub fn json(&self) -> Value {
        serde_json::json!({"on": self.on, "hide_note": self.hide_note, "choice": self.choice, "models": self.models, "url": self.url, "command": self.command, "files_ok": self.files_ok, "suggest": self.suggest, "facts": self.facts, "logs": self.logs, "values": self.values, "names": self.names, "clusters": self.clusters, "agent": self.agent, "watch": self.watch, "watch_cap": self.watch_cap})
    }

    pub fn from_json(v: &Value) -> AiPrefs {
        let d = AiPrefs::default();
        let b = |k: &str, x: bool| v[k].as_bool().unwrap_or(x);
        let three = |k: &str, x: [bool; 3]| [0, 1, 2].map(|i| v[k][i].as_bool().unwrap_or(x[i]));
        let map = |k: &str| -> HashMap<String, String> { v[k].as_object().map(|m| m.iter().filter_map(|(a, x)| Some((a.clone(), x.as_str()?.to_string()))).collect()).unwrap_or_default() };
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        let known = |x: &str| BACKENDS.iter().any(|b| b.0 == x);
        AiPrefs {
            on: b("on", false),
            hide_note: b("hide_note", false),
            choice: Some(s("choice")).filter(|x| known(x)).unwrap_or(d.choice),
            models: map("models"),
            url: s("url"),
            command: s("command"),
            files_ok: b("files_ok", false),
            suggest: b("suggest", true),
            facts: three("facts", d.facts),
            logs: three("logs", d.logs),
            values: three("values", d.values),
            names: three("names", d.names),
            // A choice that isn't known any more counts as never.
            clusters: map("clusters").into_iter().map(|(k, x)| (k, if known(&x) { x } else { "never".into() })).collect(),
            agent: Some(s("agent")).filter(|x| x == "ask" || x == "auto").unwrap_or("off".into()),
            watch: map("watch").into_iter().filter(|x| x.1 == "watch" || x.1 == "ai").collect(),
            watch_cap: v["watch_cap"].as_u64().unwrap_or(3).min(20) as u32,
        }
    }

    pub fn may(&self, c: Class, p: Place) -> bool {
        let i = p as usize;
        match c {
            Class::State => self.facts[i],
            Class::Log => self.logs[i],
            Class::Value => self.values[i],
        }
    }
}

/// What was found on this computer.
#[derive(Clone, Default, Debug)]
pub(super) struct Seen {
    pub claude: Option<aiharness::Found>,
    pub codex: Option<aiharness::Found>,
    /// Models, and whether each runs in a cloud after all. None: not running.
    pub ollama: Option<Vec<(String, bool)>>,
    pub lmstudio: Option<Vec<String>>,
}

/// The way a question goes.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Use {
    pub id: &'static str,
    pub model: String,
    pub place: Place,
}

/// The one gate: without it nothing is looked for, asked or sent.
pub(super) fn gate(on: bool, screenshot: bool) -> Result<(), String> {
    if screenshot {
        return Err("Not while taking a picture.".into());
    }
    if !on {
        return Err("AI is off. Turn it on in Settings > AI.".into());
    }
    Ok(())
}

fn host_of(url: &str) -> String {
    url.parse::<ureq::http::Uri>().ok().and_then(|u| u.host().map(|h| h.trim_matches(|c| c == '[' || c == ']').to_lowercase())).unwrap_or_default()
}

fn loopback(h: &str) -> bool {
    h == "localhost" || h.parse::<std::net::IpAddr>().map(|a| a.is_loopback()).unwrap_or(false)
}

/// A name that says the model runs in a cloud.
pub(super) fn cloud_name(model: &str) -> bool {
    let m = model.to_lowercase();
    m.ends_with(":cloud") || m.ends_with("-cloud")
}

/// Your own server's address, tidied, and where that is.
pub(super) fn check_server(s: &str) -> Result<(String, Place), String> {
    let s = s.trim().trim_end_matches('/');
    if s.is_empty() {
        return Err("Enter its address.".into());
    }
    let full = if s.contains("://") { s.to_string() } else { format!("https://{s}") };
    let uri: ureq::http::Uri = full.parse().map_err(|_| "That isn't a web address.".to_string())?;
    let h = host_of(&full);
    if h.is_empty() {
        return Err("That isn't a web address.".into());
    }
    if uri.authority().map(|a| a.as_str().contains('@')).unwrap_or(false) || full.contains(['?', '#']) {
        return Err("Leave logins, ? and # out of the address.".into());
    }
    let private = match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_private(),
        _ => false,
    };
    match uri.scheme_str() {
        Some("https") => {}
        Some("http") if loopback(&h) || private => {}
        Some("http") => return Err("Use https: with http the question and the key would travel unprotected. (http is fine for this computer and for private addresses such as 10.x.)".into()),
        _ => return Err("Use an address that starts with https://".into()),
    }
    if loopback(&h) && matches!(uri.port_u16(), Some(11434 | 1234)) {
        return Err("That's Ollama or LM Studio: choose those instead, so Kubedog can see which models run here.".into());
    }
    let public = ["openai.com", "anthropic.com", "googleapis.com", "azure.com", "mistral.ai", "groq.com", "openrouter.ai", "together.xyz", "together.ai", "deepseek.com", "x.ai", "cohere.com", "cohere.ai", "fireworks.ai", "ollama.com", "huggingface.co", "amazonaws.com", "perplexity.ai", "replicate.com", "nvidia.com", "cloudflare.com", "cerebras.ai", "sambanova.ai", "moonshot.cn", "z.ai", "bigmodel.cn", "aliyuncs.com", "databricks.com", "watsonx.ai", "ibm.com"];
    let place = if public.iter().any(|p| h == *p || h.ends_with(&format!(".{p}"))) { Place::Cloud } else { Place::Server };
    let url = if full.ends_with("/v1") || full.contains("/openai") || full.ends_with("/api") { full } else { format!("{full}/v1") };
    Ok((url, place))
}

fn codex_ok(p: &AiPrefs, f: &aiharness::Found) -> Result<(), String> {
    if f.problem.is_some() && !p.files_ok {
        return Err(f.problem.clone().unwrap_or_default());
    }
    if !f.walled && !p.files_ok {
        return Err("Codex can read files here. Allow that in Settings > AI, or choose another one.".into());
    }
    Ok(())
}

/// Where Auto, a choice or a cluster's own rule leads. With several clusters the strictest applies.
pub(super) fn route(p: &AiPrefs, seen: &Seen, ctxs: &[String]) -> Result<Use, String> {
    let mut want: Option<&str> = None;
    for c in ctxs {
        match p.clusters.get(c).map(|s| s.as_str()) {
            Some("never") => return Err("This cluster is set to \"never\" in Settings > AI.".into()),
            Some(x) => {
                if want.map(|w| w != x).unwrap_or(false) {
                    return Err("These clusters are set to different AIs, so they can't be in one question.".into());
                }
                want = Some(x);
            }
            None => {}
        }
    }
    let choice = want.unwrap_or(&p.choice);
    let model = |id: &str| p.models.get(id).cloned().unwrap_or_default();
    let one = |id: &str| -> Result<Use, String> {
        let m = model(id);
        match id {
            "claude" => {
                let f = seen.claude.as_ref().ok_or("Claude Code wasn't found on this computer.")?;
                if let Some(e) = &f.problem {
                    return Err(e.clone());
                }
                if f.login == Some(false) {
                    return Err("Claude Code isn't logged in: run claude in a terminal and log in.".into());
                }
                Ok(Use { id: "claude", model: m, place: Place::Cloud })
            }
            "codex" => {
                let f = seen.codex.as_ref().ok_or("Codex wasn't found on this computer.")?;
                codex_ok(p, f)?;
                if f.login == Some(false) {
                    return Err("Codex isn't logged in: run codex login in a terminal.".into());
                }
                Ok(Use { id: "codex", model: m, place: Place::Cloud })
            }
            "ollama" => {
                let l = seen.ollama.as_ref().ok_or("Ollama isn't running on this computer.")?;
                // The chosen model, else one that runs here, else none by itself when it's a cloud.
                let pick = if m.is_empty() { l.iter().find(|x| !x.1).or(l.first()).cloned() } else { l.iter().find(|x| x.0 == m).cloned() };
                let (m, remote) = pick.ok_or("Ollama has no such model.")?;
                Ok(Use { id: "ollama", place: if remote || cloud_name(&m) { Place::Cloud } else { Place::Here }, model: m })
            }
            "lmstudio" => {
                let l = seen.lmstudio.as_ref().ok_or("LM Studio's server isn't running on this computer.")?;
                let m = if m.is_empty() { l.first().cloned() } else { l.iter().find(|x| **x == m).cloned() }.ok_or("LM Studio has no such model.")?;
                Ok(Use { id: "lmstudio", place: if cloud_name(&m) { Place::Cloud } else { Place::Here }, model: m })
            }
            "server" => {
                let (_, place) = check_server(&p.url).map_err(|e| format!("Your own server isn't set up: {e}"))?;
                if m.is_empty() {
                    return Err("Enter your server's model in Settings > AI.".into());
                }
                Ok(Use { id: "server", place: if cloud_name(&m) { Place::Cloud } else { place }, model: m })
            }
            "anthropic" => {
                if m.is_empty() {
                    return Err("Enter the model in Settings > AI.".into());
                }
                Ok(Use { id: "anthropic", model: m, place: Place::Cloud })
            }
            "command" => {
                if !p.files_ok {
                    return Err("Your own command can read files. Allow that in Settings > AI first.".into());
                }
                if p.command.trim().is_empty() {
                    return Err("Enter the command in Settings > AI.".into());
                }
                Ok(Use { id: "command", model: String::new(), place: Place::Cloud })
            }
            _ => Err("That choice isn't known.".into()),
        }
    };
    if choice != "auto" {
        return one(choice);
    }
    for id in ["claude", "codex", "ollama", "lmstudio"] {
        if let Ok(u) = one(id) {
            return Ok(u);
        }
    }
    Err("No Claude Code, Codex, Ollama or LM Studio that's ready was found. Set one up in Settings > AI.".into())
}

/// Where an AI's questions would end up, whether or not it's ready. None: it depends on the model.
pub(super) fn place_of(id: &str, p: &AiPrefs, seen: &Seen) -> Option<Place> {
    let m = p.models.get(id).cloned().unwrap_or_default();
    match id {
        "ollama" => match &seen.ollama {
            Some(l) => {
                let x = if m.is_empty() { l.iter().find(|x| !x.1).or(l.first()) } else { l.iter().find(|x| x.0 == m) };
                x.map(|x| if x.1 || cloud_name(&x.0) { Place::Cloud } else { Place::Here })
            }
            None if cloud_name(&m) => Some(Place::Cloud),
            None => None,
        },
        "lmstudio" => Some(if cloud_name(&m) { Place::Cloud } else { Place::Here }),
        "server" => Some(match check_server(&p.url) {
            _ if cloud_name(&m) => Place::Cloud,
            Ok((_, pl)) => pl,
            Err(_) => Place::Server,
        }),
        _ => Some(Place::Cloud),
    }
}

/// Who is used for which clusters: (cluster, the way or why not). The first is without a cluster.
fn ways(p: &AiPrefs, seen: &Seen, ctxs: &[String]) -> Vec<(String, Result<Use, String>)> {
    std::iter::once((String::new(), route(p, seen, &[]))).chain(ctxs.iter().map(|c| (c.clone(), route(p, seen, std::slice::from_ref(c))))).collect()
}

/// The AIs whose questions now go to a place.
fn used_at(l: &[(String, Result<Use, String>)], at: Place) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = vec![];
    for u in l.iter().filter_map(|x| x.1.as_ref().ok()).filter(|u| u.place == at) {
        if !out.contains(&u.id) {
            out.push(u.id);
        }
    }
    out
}

// ---------- asking ----------

pub(super) type Turns = Vec<(bool, String)>;

fn agent(url: &str) -> ureq::Agent {
    let mut b = ureq::Agent::config_builder()
        .https_only(url.starts_with("https://"))
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(8)))
        .timeout_global(Some(Duration::from_secs(180)))
        .user_agent("Kubedog")
        .tls_config(ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build());
    if !url.contains("api.anthropic.com") {
        b = b.proxy(None);
    }
    b.build().new_agent()
}

fn trouble(e: &ureq::Error) -> String {
    let low = e.to_string().to_lowercase();
    if low.contains("certificate") || low.contains("unknownissuer") {
        return "The server's certificate isn't trusted by this computer.".into();
    }
    match e {
        ureq::Error::HostNotFound => "That name can't be found from this computer.".into(),
        ureq::Error::ConnectionFailed => "Nothing answers at that address.".into(),
        ureq::Error::Timeout(_) => "It didn't answer in time.".into(),
        ureq::Error::Io(x) if x.kind() == std::io::ErrorKind::ConnectionRefused => "Nothing answers at that address.".into(),
        _ => truncate(&e.to_string(), 160),
    }
}

/// One line of a streamed answer: a piece of text, or an error.
fn piece(line: &str) -> Result<Option<String>, String> {
    let l = line.trim();
    let l = l.strip_prefix("data:").map(|x| x.trim()).unwrap_or(l);
    if l.is_empty() || l == "[DONE]" || l.starts_with("event:") || l.starts_with(':') {
        return Ok(None);
    }
    let Ok(v) = serde_json::from_str::<Value>(l) else { return Ok(None) };
    if let Some(e) = v["error"].as_str().or(v["error"]["message"].as_str()) {
        return Err(truncate(e, 300));
    }
    let t = v["choices"][0]["delta"]["content"].as_str().or(v["choices"][0]["message"]["content"].as_str()).or_else(|| v["delta"]["text"].as_str());
    // A whole answer in Anthropic's way.
    let whole = v["content"].as_array().map(|a| a.iter().filter_map(|c| c["text"].as_str()).collect::<String>());
    Ok(t.map(String::from).or(whole).filter(|t| !t.is_empty()))
}

/// What's posted: the OpenAI way or Anthropic's.
fn body(anthropic: bool, model: &str, brief: &str, turns: &Turns) -> Value {
    let mut m: Vec<Value> = turns.iter().map(|(me, t)| serde_json::json!({"role": if *me { "user" } else { "assistant" }, "content": t})).collect();
    if anthropic {
        return serde_json::json!({"model": model, "max_tokens": 2000, "stream": true, "system": brief, "messages": m});
    }
    m.insert(0, serde_json::json!({"role": "system", "content": brief}));
    serde_json::json!({"model": model, "stream": true, "messages": m})
}

fn post(url: &str, key: Option<&str>, anthropic: bool, body: &Value, stop: &Arc<AtomicBool>, part: &Arc<Mutex<String>>) -> Result<String, String> {
    use std::io::BufRead;
    let mut r = agent(url).post(url).header("Content-Type", "application/json").header("Accept", "text/event-stream, application/json");
    if anthropic {
        r = r.header("anthropic-version", "2023-06-01");
    }
    if let Some(k) = key.filter(|k| !k.is_empty()) {
        if k.chars().any(|c| c.is_control()) {
            return Err("The key has characters that can't be used.".into());
        }
        r = if anthropic { r.header("x-api-key", k) } else { r.header("Authorization", &format!("Bearer {k}")) };
    }
    let mut resp = r.send(body.to_string()).map_err(|e| trouble(&e))?;
    let code = resp.status().as_u16();
    match code {
        200 => {}
        401 | 403 => return Err("It refused the key.".into()),
        404 => return Err("It doesn't know that address or model.".into()),
        429 => return Err("Its limit is reached. Try later.".into()),
        300..=399 => return Err("It sends the question somewhere else, so it wasn't sent.".into()),
        c => {
            let t = resp.body_mut().with_config().limit(20_000).read_to_string().unwrap_or_default();
            return Err(piece(&t.replace('\n', " ")).err().map(|e| format!("It answered {c}: {e}")).unwrap_or(format!("It answered {c}.")));
        }
    }
    let mut reader = std::io::BufReader::new(resp.body_mut().with_config().limit(4_000_000).reader());
    let mut all = String::new();
    let mut text = String::new();
    let mut line = String::new();
    let mut any = false;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err("Stopped.".into());
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) if any => return Err("The answer was cut off.".into()),
            Err(e) => return Err(truncate(&e.to_string(), 160)),
        }
        all.push_str(&line);
        if let Some(t) = piece(&line)? {
            any = true;
            text.push_str(&t);
            if let Ok(mut p) = part.lock() {
                p.push_str(&t);
            }
        }
        if text.len() > 400_000 {
            return Err("Its answer was too long.".into());
        }
    }
    if !any {
        // Not streamed, over several lines.
        text = piece(&all.replace('\n', " "))?.unwrap_or_default();
    }
    if text.trim().is_empty() { Err("It answered with nothing.".into()) } else { Ok(text.trim().to_string()) }
}

fn get(url: &str, secs: u64) -> Option<Value> {
    let a = ureq::Agent::config_builder().max_redirects(0).proxy(None).http_status_as_error(false).timeout_global(Some(Duration::from_secs(secs))).user_agent("Kubedog").build().new_agent();
    let mut r = a.get(url).call().ok()?;
    if r.status().as_u16() != 200 {
        return None;
    }
    serde_json::from_str(&r.body_mut().with_config().limit(4_000_000).read_to_string().ok()?).ok()
}

/// The models a server lists.
fn list_models(url: &str, key: Option<&str>, anthropic: bool) -> Result<Vec<String>, String> {
    let mut r = agent(url).get(url).header("Accept", "application/json");
    if anthropic {
        r = r.header("anthropic-version", "2023-06-01");
    }
    if let Some(k) = key.filter(|k| !k.is_empty()) {
        if k.chars().any(|c| c.is_control()) {
            return Err("the key has characters that can't be used".into());
        }
        r = if anthropic { r.header("x-api-key", k) } else { r.header("Authorization", &format!("Bearer {k}")) };
    }
    let mut resp = r.call().map_err(|e| trouble(&e))?;
    match resp.status().as_u16() {
        200 => {}
        401 | 403 => return Err("it refused the key".into()),
        c => return Err(format!("it doesn't list them ({c}); type the name instead")),
    }
    let t = resp.body_mut().with_config().limit(4_000_000).read_to_string().map_err(|e| trouble(&e))?;
    let v: Value = serde_json::from_str(&t).map_err(|_| "it doesn't list them; type the name instead".to_string())?;
    let mut l: Vec<String> = v["data"].as_array().into_iter().flatten().filter_map(|m| m["id"].as_str()).filter(|m| !m.is_empty() && !m.chars().any(|c| c.is_control())).map(String::from).take(500).collect();
    if !anthropic {
        l.sort();
    }
    if l.is_empty() { Err("it lists none".into()) } else { Ok(l) }
}

/// Ollama's models, and whether each runs in a cloud.
fn ollama_models(v: &Value) -> Vec<(String, bool)> {
    v["models"].as_array().into_iter().flatten().filter_map(|m| {
        let n = m["name"].as_str()?.to_string();
        let remote = m["remote_host"].as_str().map(|s| !s.is_empty()).unwrap_or(false) || m["remote_model"].is_string() || cloud_name(&n);
        Some((n, remote))
    }).collect()
}

const OLLAMA: &str = "http://127.0.0.1:11434";
const LMSTUDIO: &str = "http://127.0.0.1:1234";

/// Looks for what's on this computer.
pub(super) fn look() -> Seen {
    let a = std::thread::spawn(|| aiharness::look(Harness::Claude));
    let b = std::thread::spawn(|| aiharness::look(Harness::Codex));
    Seen {
        ollama: get(&format!("{OLLAMA}/api/tags"), 3).filter(|v| v["models"].is_array()).map(|v| ollama_models(&v)),
        lmstudio: get(&format!("{LMSTUDIO}/v1/models"), 3).and_then(|v| Some(v["data"].as_array()?.iter().filter_map(|m| m["id"].as_str().map(String::from)).filter(|m| !m.contains("embed")).collect())),
        claude: a.join().ok().flatten(),
        codex: b.join().ok().flatten(),
    }
}

fn keychain(id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new("kubedog", &format!("ai-{id}")).map_err(|e| format!("The system's keychain: {e}"))
}

fn key_of(id: &str) -> Result<Option<String>, String> {
    match keychain(id)?.get_password() {
        Ok(k) => Ok(Some(k)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("The key couldn't be read from the keychain: {e}")),
    }
}

/// A typed command as program and options; quotes keep spaces together. No shell.
fn words(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut q: Option<char> = None;
    let mut open = false;
    for c in s.chars() {
        match (q, c) {
            (Some(x), c) if c == x => q = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                q = Some(c);
                open = true;
            }
            (None, c) if c.is_whitespace() => {
                if open || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                open = false;
            }
            (None, c) => cur.push(c),
        }
    }
    if open || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Everything asking needs, taken along into its thread.
#[derive(Clone)]
pub(super) struct Job {
    pub to: Use,
    pub url: String,
    pub command: String,
    pub claude: Option<aiharness::Found>,
    pub codex: Option<aiharness::Found>,
}

/// Asks. Called only from `KubedogApp::ai_send`, behind the gate.
fn send(j: &Job, brief: &str, turns: &Turns, stop: &Arc<AtomicBool>, part: &Arc<Mutex<String>>) -> Result<String, String> {
    // For a harness it's one text.
    let one = || match turns.as_slice() {
        [(_, t)] => t.clone(),
        l => l.iter().map(|(me, t)| format!("{}:\n{t}", if *me { "Question" } else { "Your earlier answer" })).collect::<Vec<_>>().join("\n\n"),
    };
    match j.to.id {
        "claude" => aiharness::ask(Harness::Claude, j.claude.as_ref().ok_or("Claude Code wasn't found.")?, &j.to.model, brief, &one(), &[], stop, part),
        "codex" => aiharness::ask(Harness::Codex, j.codex.as_ref().ok_or("Codex wasn't found.")?, &j.to.model, brief, &one(), &[], stop, part),
        "command" => {
            let w = words(&j.command);
            let (name, args) = w.split_first().ok_or("Enter the command first.")?;
            let path = if name.contains(['/', '\\']) { std::path::PathBuf::from(name) } else { aiharness::find(name).ok_or(format!("{name} wasn't found on this computer."))? };
            aiharness::ask(Harness::Own, &aiharness::Found { path, ..Default::default() }, "", brief, &one(), args, stop, part)
        }
        "ollama" => {
            // Where that model runs is looked at again, now.
            let v = get(&format!("{OLLAMA}/api/tags"), 5).ok_or("Ollama isn't running.")?;
            let m = ollama_models(&v).into_iter().find(|m| m.0 == j.to.model).ok_or("Ollama doesn't have that model any more.")?;
            if m.1 && j.to.place == Place::Here {
                return Err("That model runs in a cloud, not on this computer, so nothing was sent.".into());
            }
            post(&format!("{OLLAMA}/v1/chat/completions"), None, false, &body(false, &j.to.model, brief, turns), stop, part)
        }
        "lmstudio" => post(&format!("{LMSTUDIO}/v1/chat/completions"), None, false, &body(false, &j.to.model, brief, turns), stop, part),
        "server" => {
            let (u, p) = check_server(&j.url)?;
            if p == Place::Cloud && j.to.place != Place::Cloud {
                return Err("That address is a cloud service, so nothing was sent.".into());
            }
            post(&format!("{u}/chat/completions"), key_of("server")?.as_deref(), false, &body(false, &j.to.model, brief, turns), stop, part)
        }
        "anthropic" => {
            let k = key_of("anthropic")?.ok_or("There's no key for Anthropic yet (Settings > AI).")?;
            post("https://api.anthropic.com/v1/messages", Some(&k), true, &body(true, &j.to.model, brief, turns), stop, part)
        }
        _ => Err("That choice isn't known.".into()),
    }
}

// ---------- in the app ----------

pub(super) struct Running {
    pub id: u64,
    pub stop: Arc<AtomicBool>,
    pub part: Arc<Mutex<String>>,
    pub began: Instant,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub(super) struct AiState {
    pub seen: Option<Seen>,
    pub looking: bool,
    /// What a look found, handed over from its thread.
    inbox: Arc<Mutex<Option<Seen>>>,
    pub chat: Option<super::aichat::Chat>,
    /// The conversation is kept, its panel isn't shown.
    pub hidden: bool,
    /// What the open page drew, for the AI.
    pub notes: Vec<(Class, String, Option<super::podxray::Go>)>,
    pub n: u64,
    /// (cluster, backend) that were shown what's sent.
    pub shown: HashSet<(String, String)>,
    pub key_draft: HashMap<String, String>,
    pub key_word: HashMap<String, String>,
    pub test: Option<(Running, String)>,
    pub tested: Option<(String, Result<String, String>)>,
    pub url_draft: Option<String>,
    pub cmd_draft: Option<String>,
    /// Backends whose model is being typed.
    pub typing: HashSet<String>,
    /// Models a server listed when asked; None while asking.
    pub served: HashMap<String, Option<Result<Vec<String>, String>>>,
    pub served_url: String,
}

impl KubedogApp {
    pub(super) fn ai_gate(&self) -> Result<(), String> {
        gate(self.prefs.ai.on, self.screenshot.is_some())
    }

    pub(super) fn ai_look(&mut self, again: bool) {
        if self.ai_gate().is_err() || self.ai.looking || (self.ai.seen.is_some() && !again) {
            return;
        }
        self.ai.looking = true;
        let inbox = self.ai.inbox.clone();
        self.spawn(move |_| {
            let s = look();
            if let Ok(mut i) = inbox.lock() {
                *i = Some(s);
            }
            Msg::Text { key: "ai|look".into(), result: Ok(String::new()) }
        });
    }

    /// Sends a conversation to where the route leads. The only way out.
    pub(super) fn ai_send(&mut self, to: Use, brief: String, turns: Turns, test: bool) -> Result<Running, String> {
        self.ai_gate()?;
        let seen = self.ai.seen.clone().unwrap_or_default();
        self.ai.n += 1;
        let id = self.ai.n;
        let r = Running { id, stop: Arc::new(AtomicBool::new(false)), part: Arc::new(Mutex::new(String::new())), began: Instant::now() };
        let (stop, part) = (r.stop.clone(), r.part.clone());
        let j = Job { to, url: self.prefs.ai.url.clone(), command: self.prefs.ai.command.clone(), claude: seen.claude, codex: seen.codex };
        self.spawn(move |_| Msg::Text { key: format!("ai|{}|{id}", if test { "test" } else { "said" }), result: send(&j, &brief, &turns, &stop, &part) });
        Ok(r)
    }

    pub(super) fn on_ai(&mut self, key: &str, result: &Result<String, String>) -> bool {
        let Some(k) = key.strip_prefix("ai|") else { return false };
        if k == "look" {
            self.ai.looking = false;
            self.ai.seen = self.ai.inbox.lock().ok().and_then(|mut i| i.take()).or(Some(Seen::default()));
            self.ai_go_on();
        } else if let Some(id) = k.strip_prefix("test|") {
            if let Some((r, what)) = self.ai.test.take() {
                if r.id.to_string() == id {
                    self.ai.tested = Some((what, result.clone()));
                } else {
                    self.ai.test = Some((r, what));
                }
            }
        } else if let Some(k) = k.strip_prefix("models|") {
            let (id, url) = k.split_once('|').unwrap_or((k, ""));
            // An answer of an address that's no longer the one isn't used.
            if id != "server" || url == self.prefs.ai.url {
                self.ai.served.insert(id.to_string(), Some(result.clone().map(|t| t.lines().map(String::from).collect())));
            } else {
                self.ai.served.remove(id);
            }
        } else if let Some((what, id)) = k.split_once('|') {
            let done = |app: &mut Self| match what {
                "said" => app.ai_said(id, result),
                "looked" => app.ai_looked(id, result),
                _ => {}
            };
            if self.companion.chat.as_ref().map(|c| c.waits_for(id)).unwrap_or(false) {
                self.as_companion(done);
                self.companion_done();
            } else {
                done(self);
            }
        }
        true
    }

    /// Facts allowed at a place, as text: (text, log lines kept back, values kept back).
    pub(super) fn ai_sheet(&self, f: &Facts, which: &[usize], place: Place, names: Option<&Standins>, most: usize) -> (String, usize, usize) {
        super::aifacts::sheet(f, which, self.prefs.ai.may(Class::Log, place), self.prefs.ai.may(Class::Value, place), names, most)
    }

    /// The models there are: (name, how it's shown).
    pub(super) fn ai_models(&self, id: &str) -> Vec<(String, String)> {
        let Some(s) = &self.ai.seen else { return vec![] };
        let plain = |l: Vec<String>| l.into_iter().map(|m| (m.clone(), m)).collect::<Vec<_>>();
        match id {
            "claude" => s.claude.as_ref().map(|f| f.models.clone()).unwrap_or_default(),
            "codex" => s.codex.as_ref().map(|f| f.models.clone()).unwrap_or_default(),
            "ollama" => s.ollama.clone().unwrap_or_default().into_iter().map(|(m, remote)| (m.clone(), format!("{m} ({})", if remote { "cloud" } else { "this computer" }))).collect(),
            "lmstudio" => plain(s.lmstudio.clone().unwrap_or_default()),
            // A list of another address isn't this one's.
            "server" if self.ai.served_url != self.prefs.ai.url => vec![],
            _ => match self.ai.served.get(id) {
                Some(Some(Ok(l))) => plain(l.clone()),
                _ => vec![],
            },
        }
    }

    /// Asks a server for its models: only on a click, for it may need the key.
    pub(super) fn ai_fetch(&mut self, id: &'static str) {
        if self.ai_gate().is_err() || matches!(self.ai.served.get(id), Some(None)) {
            return;
        }
        let url = self.prefs.ai.url.clone();
        self.ai.served_url = url.clone();
        self.ai.served.insert(id.to_string(), None);
        self.spawn(move |_| {
            let r = match id {
                "anthropic" => key_of(id).and_then(|k| list_models("https://api.anthropic.com/v1/models?limit=100", Some(&k.ok_or("there's no key yet")?), true)),
                _ => check_server(&url).and_then(|(u, _)| list_models(&format!("{u}/models"), key_of(id)?.as_deref(), false)),
            };
            Msg::Text { key: format!("ai|models|{id}|{url}"), result: r.map(|l| l.join("\n")) }
        });
    }

    /// A pulldown of models. True when a server should be asked for its list.
    pub(super) fn model_menu(&mut self, ui: &mut Ui, at: &str, id: &str, m: &mut String, list: &[(String, String)], width: f32) -> bool {
        let mut fetch = false;
        let none = match id {
            "claude" | "codex" => "its own choice",
            "ollama" => "the first that runs here",
            "lmstudio" => "the first one",
            _ => "choose a model",
        };
        if self.ai.typing.contains(id) && at == "set" {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(m).hint_text("the model's name").font(FontId::proportional(z(13.0))).desired_width(width - u(44.0)));
                if ui.add(egui::Button::new(RichText::new("▾").size(z(13.0)))).on_hover_text("Back to the list").clicked() {
                    self.ai.typing.remove(id);
                }
            });
            return false;
        }
        let shown = if m.is_empty() { none.to_string() } else { list.iter().find(|x| x.0 == *m).map(|x| x.1.clone()).unwrap_or(m.clone()) };
        let asking = matches!(self.ai.served.get(id), Some(None));
        let mut other = false;
        egui::ComboBox::from_id_salt(("ai-model", at, id)).width(width).height(u(360.0)).truncate().selected_text(RichText::new(shown).size(z(13.0))).show_ui(ui, |ui| {
            if !matches!(id, "server" | "anthropic") {
                ui.selectable_value(m, String::new(), none);
            }
            if !m.is_empty() && !list.iter().any(|x| x.0 == *m) {
                let now = m.clone();
                ui.selectable_value(m, now.clone(), now);
            }
            for (v, t) in list {
                let r = ui.selectable_value(m, v.clone(), t);
                if v != t {
                    r.on_hover_text(v);
                }
            }
            if matches!(id, "server" | "anthropic") {
                if asking {
                    ui.label(RichText::new("Asking for the list…").size(z(13.0)).color(TEXT_SUBTLE()));
                } else if ui.selectable_label(false, RichText::new("Get the list").color(PRIMARY_TEXT())).clicked() {
                    fetch = true;
                }
            }
            if at == "set" && !matches!(id, "ollama" | "lmstudio") {
                other = ui.selectable_label(false, RichText::new("Type another one…").color(TEXT_SUBTLE())).clicked();
            }
        });
        if other {
            self.ai.typing.insert(id.to_string());
        }
        fetch
    }

    // ---------- settings ----------

    pub(super) fn settings_ai(&mut self, ui: &mut Ui) {
        settings::title(ui, "AI", "Optional. Kubedog finds the facts; an AI can explain them in plain words. It's told only those facts, never secrets, and can't change anything in your cluster.");
        let mut p = self.prefs.ai.clone();
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Use AI").size(z(15.0)).strong().color(TEXT_DEFAULT()));
                for (t, v) in [("Off", false), ("On", true)] {
                    if incident::chip_button(ui, t, p.on == v) {
                        p.on = v;
                    }
                }
            });
            ui.add_space(2.0);
            work::said(ui, if p.on { "The AI button at the top right opens a chat about what you're looking at. Explain buttons are in lists, on objects, in the Incident Room and on log errors. Nothing is asked by itself, unless you let the Ai-health-agent (5)." } else { "Off: nothing is looked for, asked or sent, and there are no Explain buttons." }, TEXT_SUBTLE());
        });
        if p.on {
            // For pictures: made up, nothing is looked at.
            if self.screenshot.is_some() && self.ai.seen.is_none() && std::env::var("KUBEDOG_SHOT_AI").is_ok() {
                self.ai.seen = Some(made_up());
            }
            self.ai_look(false);
            ui.add_space(12.0);
            self.ai_settings_who(ui, &mut p);
            ui.add_space(12.0);
            self.ai_settings_what(ui, &mut p);
            ui.add_space(12.0);
            self.ai_settings_clusters(ui, &mut p);
            ui.add_space(12.0);
            self.ai_settings_agent(ui, &mut p);
        }
        if p != self.prefs.ai {
            if !p.on {
                self.ai.chat = None;
                self.ai.test = None;
                self.ai.seen = None;
            }
            self.prefs.ai = p;
            self.save();
        }
    }

    fn ai_settings_who(&mut self, ui: &mut Ui, p: &mut AiPrefs) {
        let seen = self.ai.seen.clone();
        card(ui, |ui| {
            pg::panel(ui, "1. Which AI", "Auto takes the first that's ready: Claude Code, Codex, Ollama, LM Studio, and nothing else");
            ui.horizontal_wrapped(|ui| {
                if incident::chip_button(ui, "Auto", p.choice == "auto") {
                    p.choice = "auto".into();
                }
                for b in BACKENDS {
                    if incident::chip_button(ui, b.1, p.choice == b.0) {
                        p.choice = b.0.into();
                    }
                }
            });
            ui.add_space(6.0);
            let s = seen.clone().unwrap_or_default();
            if self.ai.looking || (seen.is_none() && self.screenshot.is_none()) {
                work::said(ui, "Looking at what's on this computer…", TEXT_SUBTLE());
            } else {
                match route(p, &s, &[]) {
                    Err(_) if seen.is_none() => {}
                    Ok(u) => {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(format!("Questions go to {}{}, which counts as", label(u.id), if u.model.is_empty() { String::new() } else { format!(" ({})", u.model) })).size(z(13.0)).color(TEXT_DEFAULT()));
                            pg::pill(ui, place_label(u.place), place_color(u.place));
                        });
                    }
                    Err(e) => work::said(ui, &e, WARNING()),
                }
            }
            ui.add_space(8.0);
            let mut fetch: Option<&'static str> = None;
            let used = route(p, &s, &[]).ok().filter(|_| seen.is_some()).map(|u| u.id);
            for (j, (id, name, what)) in BACKENDS.iter().enumerate() {
                let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(38.0)), Sense::hover());
                if used == Some(*id) {
                    ui.painter().rect_filled(r.expand2(egui::vec2(u(6.0), 0.0)), CornerRadius::same(6), BG_HOVER());
                    ui.painter().rect_filled(egui::Rect::from_min_size(r.min - egui::vec2(u(6.0), 0.0), egui::vec2(3.0, r.height())), CornerRadius::same(2), PRIMARY_TEXT());
                } else if j > 0 {
                    ui.painter().hline(r.x_range(), r.top(), Stroke::new(1.0, BORDER_SUBTLE()));
                }
                let state: (Color32, String) = match *id {
                    "claude" | "codex" => match if *id == "claude" { &s.claude } else { &s.codex } {
                        None => (BORDER_DEFAULT(), if seen.is_some() { "not found" } else { what }.into()),
                        Some(f) => match (&f.problem, f.login) {
                            (Some(e), _) => (WARNING(), e.clone()),
                            (None, Some(false)) => (WARNING(), format!("{}, not logged in", f.version)),
                            _ => (SUCCESS(), format!("{}, {}{}", f.version, if f.login == Some(true) { "logged in" } else { "login not known" }, if f.walled { ", the system keeps it out of your files" } else if *id == "codex" { ", can read your files" } else { "" })),
                        },
                    },
                    "ollama" => match &s.ollama {
                        None => (BORDER_DEFAULT(), if seen.is_some() { "not running" } else { what }.into()),
                        Some(l) => {
                            let cloud = l.iter().filter(|m| m.1).count();
                            (if cloud < l.len() { SUCCESS() } else { WARNING() }, format!("{}{}", many(l.len() as i64, "model"), if cloud > 0 { format!(", {cloud} of them in a cloud") } else { String::new() }))
                        }
                    },
                    "lmstudio" => match &s.lmstudio {
                        None => (BORDER_DEFAULT(), if seen.is_some() { "not running" } else { what }.into()),
                        Some(l) => (SUCCESS(), many(l.len() as i64, "model")),
                    },
                    "server" => match check_server(&p.url) {
                        Ok((u, _)) => (SUCCESS(), u),
                        Err(_) => (BORDER_DEFAULT(), "not set up".into()),
                    },
                    "command" if p.command.is_empty() => (BORDER_DEFAULT(), "not set up".into()),
                    _ => (BORDER_DEFAULT(), String::new()),
                };
                ui.painter().circle_filled(egui::pos2(r.left() + u(6.0), r.center().y), u(4.5), state.0);
                pg::label_at(ui, ui.painter(), egui::pos2(r.left() + u(20.0), r.center().y), name, 14.0, TEXT_DEFAULT(), u(130.0));
                mark_at(ui, egui::pos2(r.left() + u(150.0), r.center().y), place_of(id, p, &s));
                let mid = r.left() + u(310.0);
                pg::label_at(ui, ui.painter(), egui::pos2(mid, r.center().y), &format!("{}{}", if used == Some(*id) { "in use: " } else { "" }, if state.1.is_empty() { what.to_string() } else { state.1.clone() }), 12.5, TEXT_SUBTLE(), (r.right() - u(250.0) - mid).max(20.0));
                if *id != "command" {
                    let cell = egui::Rect::from_min_max(egui::pos2(r.right() - u(240.0), r.top() + u(5.0)), egui::pos2(r.right(), r.bottom() - u(5.0)));
                    let m = p.models.entry(id.to_string()).or_default();
                    let list = self.ai_models(id);
                    ui.scope_builder(egui::UiBuilder::new().max_rect(cell), |ui| {
                        if self.model_menu(ui, "set", id, m, &list, cell.width()) {
                            fetch = Some(id);
                        }
                    });
                }
            }
            if let Some(id) = fetch {
                // With what's filled in now.
                self.prefs.ai.url = p.url.clone();
                self.ai_fetch(id);
            }
            for id in ["server", "anthropic"] {
                if let Some(Err(e)) = self.ai.served.get(id).and_then(|x| x.as_ref()) {
                    work::said(ui, &format!("{}'s models: {e}", label(id)), WARNING());
                }
            }
            p.models.retain(|_, m| !m.is_empty());
            ui.add_space(8.0);
            if p.choice == "server" || !p.url.is_empty() || p.clusters.values().any(|x| x == "server") {
                let mut t = self.ai.url_draft.clone().unwrap_or(p.url.clone());
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Your server's address").size(z(13.0)).color(TEXT_MUTED()));
                    if ui.add(egui::TextEdit::singleline(&mut t).hint_text("https://llm.example.com/v1").desired_width(u(320.0))).lost_focus() {
                        p.url = t.trim().to_string();
                    }
                });
                match check_server(&t) {
                    Ok((x, pl)) => work::said(ui, &format!("{x}/chat/completions, {}", place_words(pl)), TEXT_PLACEHOLDER()),
                    Err(e) if !t.is_empty() => work::said(ui, &e, WARNING()),
                    _ => {}
                }
                self.ai.url_draft = Some(t);
                self.ai_key(ui, "server");
            }
            if p.choice == "anthropic" || p.clusters.values().any(|x| x == "anthropic") {
                self.ai_key(ui, "anthropic");
            }
            if p.choice == "command" || !p.command.is_empty() || p.clusters.values().any(|x| x == "command") {
                let mut t = self.ai.cmd_draft.clone().unwrap_or(p.command.clone());
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Your command").size(z(13.0)).color(TEXT_MUTED()));
                    if ui.add(egui::TextEdit::singleline(&mut t).hint_text("for example: my-ai --plain").desired_width(u(320.0))).lost_focus() {
                        p.command = t.trim().to_string();
                    }
                });
                work::said(ui, "It's started in an empty folder without your settings; the question is on its input. Kubedog can't see what else it does.", TEXT_PLACEHOLDER());
                self.ai.cmd_draft = Some(t);
            }
            ui.checkbox(&mut p.files_ok, RichText::new("Allow one that can read my files (your own command, or Codex where the system can't keep it out)").size(z(13.0)));
            ui.checkbox(&mut p.suggest, RichText::new("It may end with a suggested change, as text. Kubedog never applies it.").size(z(13.0)));
            ui.add_space(8.0);
            let to = route(p, &s, &[]).ok();
            ui.horizontal(|ui| {
                if button(ui, "Look again", false, false) {
                    self.ai_look(true);
                }
                if let Some(t) = to {
                    if self.ai.test.is_some() {
                        ui.spinner();
                        ui.label(RichText::new(format!("Asking {}…", label(t.id))).size(z(13.0)).color(TEXT_SUBTLE()));
                        if button(ui, "Stop", false, false) {
                            self.ai.test = None;
                        }
                    } else if button(ui, &format!("Try {} with a made-up question", label(t.id)), false, false) {
                        self.ai.tested = None;
                        let q = "Facts:\n[F1] The made-up container web ended with OOMKilled.\n[F2] Its memory limit is 64Mi.\n\nQuestion: Why does it restart? One sentence.".to_string();
                        let what = label(t.id).to_string();
                        match self.ai_send(t, super::aifacts::brief(false, None), vec![(true, q)], true) {
                            Ok(r) => self.ai.test = Some((r, what)),
                            Err(e) => self.ai.tested = Some((what, Err(e))),
                        }
                    }
                }
            });
            match &self.ai.tested {
                Some((w, Ok(t))) => work::said(ui, &format!("{w} works: \"{}\"", truncate(t, 300)), SUCCESS()),
                Some((w, Err(e))) => work::said(ui, &format!("{w}: {e}"), WARNING()),
                None => {}
            }
        });
    }

    /// A key goes to the system's keychain, and nowhere else.
    fn ai_key(&mut self, ui: &mut Ui, id: &str) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Key for {}", if id == "server" { "your server (if it needs one)" } else { "Anthropic" })).size(z(13.0)).color(TEXT_MUTED()));
            let d = self.ai.key_draft.entry(id.to_string()).or_default();
            ui.add(egui::TextEdit::singleline(d).password(true).hint_text("paste it here").desired_width(u(220.0)));
            let k = d.trim().to_string();
            let mut word = None;
            if ui.add_enabled(!k.is_empty(), egui::Button::new(RichText::new("Keep it in the keychain").size(z(13.0)))).clicked() {
                word = Some(match self.ai_gate().and_then(|_| keychain(id)?.set_password(&k).map_err(|e| e.to_string())) {
                    Ok(()) => "kept".to_string(),
                    Err(e) => format!("not kept: {}", truncate(&e, 120)),
                });
            }
            if button(ui, "Forget it", false, false) {
                word = Some(match self.ai_gate().and_then(|_| keychain(id)?.delete_credential().map_err(|e| e.to_string())) {
                    Ok(()) => "forgotten".into(),
                    Err(_) => "there was none".into(),
                });
            }
            if let Some(w) = word {
                if let Some(d) = self.ai.key_draft.get_mut(id) {
                    d.clear();
                }
                self.ai.key_word.insert(id.to_string(), w);
            }
            if let Some(w) = self.ai.key_word.get(id) {
                ui.label(RichText::new(w).size(z(12.5)).color(TEXT_SUBTLE()));
            }
        });
    }

    fn ai_settings_what(&mut self, ui: &mut Ui, p: &mut AiPrefs) {
        let names: Vec<String> = self.contexts.iter().map(|c| c.name.clone()).collect();
        let l = self.ai.seen.as_ref().map(|s| ways(p, s, &names)).unwrap_or_default();
        card(ui, |ui| {
            pg::panel(ui, "2. What may be sent where", "each AI above follows the column of its marker; secret values, keys and logins are never sent");
            let rows: [(&str, &str, &mut [bool; 3]); 4] = [
                ("Facts", "health, warnings, images, requests, and what changed (not from what to what)", &mut p.facts),
                ("Log lines", "errors and warnings from logs", &mut p.logs),
                ("Values", "variables and settings, before and after a change", &mut p.values),
                ("Stand-ins for names", "for clusters, namespaces, nodes, hosts and addresses; put back in the answer", &mut p.names),
            ];
            let wide = u(170.0).min(ui.available_width() / 5.0);
            let cols = |r: egui::Rect, i: usize| r.right() - wide * (3 - i) as f32;
            let used: Vec<Vec<&'static str>> = PLACES.iter().map(|x| used_at(&l, x.0)).collect();
            // Behind the columns that count now.
            let back = ui.painter().add(egui::Shape::Noop);
            let top = ui.cursor().top();
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(54.0)), Sense::hover());
            for (i, (pl, _)) in PLACES.iter().enumerate() {
                mark_at(ui, egui::pos2(cols(r, i), r.top() + u(17.0)), Some(*pl));
                let t = if l.is_empty() { String::new() } else if used[i].is_empty() { "not used now".to_string() } else { format!("used by {}", used[i].iter().map(|x| label(x)).collect::<Vec<_>>().join(", ")) };
                pg::label_at(ui, ui.painter(), egui::pos2(cols(r, i) + u(2.0), r.top() + u(39.0)), &t, 12.0, if used[i].is_empty() { TEXT_PLACEHOLDER() } else { TEXT_MUTED() }, wide - u(12.0));
            }
            for (t, hint, l) in rows {
                let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(64.0)), Sense::hover());
                ui.painter().hline(r.x_range(), r.top(), Stroke::new(1.0, BORDER_SUBTLE()));
                let w = cols(r, 0) - r.left() - u(16.0);
                pg::label_at(ui, ui.painter(), egui::pos2(r.left(), r.center().y - u(14.0)), t, 14.0, TEXT_DEFAULT(), w);
                pg::label_at(ui, ui.painter(), egui::pos2(r.left(), r.center().y + u(6.0)), hint, 12.0, TEXT_PLACEHOLDER(), w);
                for (i, b) in l.iter_mut().enumerate() {
                    let c = egui::Rect::from_min_size(egui::pos2(cols(r, i), r.center().y - u(12.0)), egui::vec2(u(30.0), u(24.0)));
                    ui.put(c, egui::Checkbox::without_text(b)).on_hover_text(format!("{t}: {}", PLACES[i].1));
                }
            }
            let bottom = ui.cursor().top();
            let shapes: Vec<egui::Shape> = PLACES.iter().enumerate().filter(|(i, _)| !used[*i].is_empty()).map(|(i, (pl, _))| {
                let c = egui::Rect::from_min_max(egui::pos2(cols(r, i) - u(10.0), top), egui::pos2(cols(r, i) + wide - u(14.0), bottom));
                egui::Shape::Rect(egui::epaint::RectShape::new(c, CornerRadius::same(8), place_color(*pl).gamma_multiply(0.03), Stroke::new(1.5, place_color(*pl).gamma_multiply(0.6)), egui::StrokeKind::Inside))
            }).collect();
            ui.painter().set(back, egui::Shape::Vec(shapes));
            ui.add_space(8.0);
            work::said(ui, "What looks like a secret is taken out first. Before the first question about a cluster goes to a cloud, you see what will be sent; not for what the Ai-health-agent (5) sends when you let it, nor for later look-ups (4).", TEXT_SUBTLE());
        });
    }

    fn ai_settings_clusters(&mut self, ui: &mut Ui, p: &mut AiPrefs) {
        let names: Vec<String> = self.contexts.iter().map(|c| c.name.clone()).collect();
        let l = self.ai.seen.as_ref().map(|s| ways(p, s, &names)).unwrap_or_default();
        card(ui, |ui| {
            pg::panel(ui, "3. Per cluster", "the same as in 1 unless you choose otherwise");
            egui::Grid::new("ai-clusters").num_columns(3).spacing(egui::vec2(u(30.0), u(8.0))).show(ui, |ui| {
                for c in names {
                    ui.horizontal(|ui| {
                        let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
                        ui.painter().circle_filled(d.center(), 3.5, context_color(&c));
                        ui.label(RichText::new(ctx_label(&c)).size(z(14.0)).color(TEXT_DEFAULT())).on_hover_text(&c);
                    });
                    let now = p.clusters.get(&c).cloned().unwrap_or_default();
                    let mut pick = now.clone();
                    egui::ComboBox::from_id_salt(("ai-cluster", &c)).width(u(200.0)).selected_text(match now.as_str() {
                        "" => "as in 1",
                        "never" => "never",
                        x => label(x),
                    }).show_ui(ui, |ui| {
                        ui.selectable_value(&mut pick, String::new(), "as in 1");
                        ui.selectable_value(&mut pick, "never".into(), "never");
                        for b in BACKENDS {
                            ui.selectable_value(&mut pick, b.0.into(), b.1);
                        }
                    });
                    ui.horizontal(|ui| match l.iter().find(|x| x.0 == c).map(|x| &x.1) {
                        _ if now == "never" => {
                            ui.label(RichText::new("nothing is ever sent").size(z(12.5)).color(TEXT_SUBTLE()));
                        }
                        Some(Ok(w)) => {
                            pg::pill(ui, place_label(w.place), place_color(w.place));
                            ui.label(RichText::new(label(w.id)).size(z(12.5)).color(TEXT_MUTED()));
                        }
                        Some(Err(e)) => {
                            ui.label(RichText::new(truncate(e, 90)).size(z(12.5)).color(WARNING()));
                        }
                        None => {}
                    });
                    if pick != now {
                        if pick.is_empty() {
                            p.clusters.remove(&c);
                        } else {
                            p.clusters.insert(c.clone(), pick);
                        }
                    }
                    ui.end_row();
                }
            });
        });
    }

    fn ai_settings_agent(&mut self, ui: &mut Ui, p: &mut AiPrefs) {
        card(ui, |ui| {
            pg::panel(ui, "4. Look-ups", "the AI may have Kubedog read more of the cluster to answer you");
            ui.horizontal_wrapped(|ui| {
                for (id, t) in AGENT {
                    if incident::chip_button(ui, t, p.agent == id) {
                        p.agent = id.into();
                    }
                }
            });
            ui.add_space(4.0);
            work::said(ui, match p.agent.as_str() {
                "ask" => "It says what it wants to look at, and you allow it or not, each time.",
                "auto" => "It looks at what it needs while it answers. Every look-up is shown in the chat.",
                _ => "It only gets the facts of where you are.",
            }, TEXT_MUTED());
            work::said(ui, "It can't run kubectl by itself: it names one of a few ways of reading (lists, an object, events, logs, usage), and Kubedog checks and runs it. No secrets, no commands in pods, no changes. Results follow the table in 2, in the conversation's clusters only.", TEXT_SUBTLE());
        });
        ui.add_space(12.0);
        card(ui, |ui| {
            pg::panel(ui, "5. Ai-health-agent", "watches your clusters and opens a case in the Incident Room when something stays broken");
            work::said(ui, "Watching is done by Kubedog's own rules, without AI. \"Let AI investigate\" is a separate choice: then facts of new problems are sent without asking each time, following 1, 2 and 3.", TEXT_SUBTLE());
            ui.add_space(6.0);
            let names: Vec<String> = self.contexts.iter().map(|c| c.name.clone()).collect();
            for c in names {
                ui.horizontal_wrapped(|ui| {
                    let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
                    ui.painter().circle_filled(d.center(), 3.5, context_color(&c));
                    let how = p.watch.get(&c).cloned();
                    for (t, v) in [("Off", None), ("Watch", Some("watch")), ("Watch, and let AI investigate", Some("ai"))] {
                        if incident::chip_button(ui, t, how.as_deref() == v) && how.as_deref() != v {
                            // Through the companion, which also ends what runs.
                            self.companion_set(&c, v);
                            p.watch = self.prefs.ai.watch.clone();
                        }
                    }
                    ui.label(RichText::new(ctx_label(&c)).size(z(14.0)).color(TEXT_DEFAULT())).on_hover_text(&c);
                });
                ui.add_space(2.0);
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Investigations by itself, at most an hour").size(z(13.0)).color(TEXT_MUTED()));
                ui.add(egui::DragValue::new(&mut p.watch_cap).range(0..=20));
            });
        });
    }

    /// The main page says it exists.
    pub(super) fn ai_note(&mut self, ui: &mut Ui) {
        if self.prefs.ai.on || self.prefs.ai.hide_note {
            return;
        }
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let (d, _) = ui.allocate_exact_size(egui::vec2(u(10.0), u(10.0)), Sense::hover());
                ui.painter().circle_filled(d.center(), u(4.5), PRIMARY_TEXT());
                ui.label(RichText::new("New: Kubedog can ask an AI to explain what it finds").size(z(14.5)).color(TEXT_DEFAULT()));
                ui.label(RichText::new("off").size(z(12.5)).color(TEXT_PLACEHOLDER()));
            });
            work::said(ui, "With Claude Code or Codex if you have them, or Ollama or LM Studio on this computer. You decide what may be sent, and nothing is sent until you ask.", TEXT_SUBTLE());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if button(ui, "Turn it on", true, false) {
                    self.prefs.ai.on = true;
                    self.settings_section = "AI";
                    self.save();
                    if self.connected {
                        self.navigate(View::Settings, None);
                    } else {
                        self.toast("AI is on. What may be sent is in Settings > AI, once a cluster is open.".into(), false);
                    }
                }
                if button(ui, "Not now", false, false) {
                    self.prefs.ai.hide_note = true;
                    self.save();
                }
                ui.label(RichText::new("You'll find it in Settings > AI.").size(z(12.5)).color(TEXT_PLACEHOLDER()));
            });
        });
        ui.add_space(14.0);
    }
}

/// For pictures and tests.
pub(super) fn made_up() -> Seen {
    let f = |v: &str, l: &[&str]| Some(aiharness::Found { version: v.into(), login: Some(true), walled: true, models: l.iter().map(|m| (m.to_string(), format!("{m} (made up)"))).collect(), ..Default::default() });
    Seen { claude: f("1.0", &["big", "middle", "small"]), codex: f("1.0", &["one", "two"]), ollama: Some(vec![("here".into(), false), ("there:cloud".into(), true)]), lmstudio: None }
}

/// One colour per place, the same everywhere.
pub(super) fn place_color(p: Place) -> Color32 {
    match p {
        Place::Here => SUCCESS(),
        Place::Server => WARNING(),
        Place::Cloud => INFO(),
    }
}

pub(super) fn place_label(p: Place) -> &'static str {
    PLACES[p as usize].1
}

/// A marker in a fixed spot: which place an AI belongs to.
fn mark_at(ui: &Ui, at: egui::Pos2, p: Option<Place>) {
    let (t, col) = match p {
        Some(p) => (place_label(p), place_color(p)),
        None => ("Depends on the model", TEXT_SUBTLE()),
    };
    let g = ui.painter().layout_no_wrap(t.to_string(), FontId::proportional(z(12.0)), col);
    let r = egui::Rect::from_min_size(egui::pos2(at.x, at.y - g.size().y / 2.0 - u(2.5)), g.size() + egui::vec2(u(18.0), u(5.0)));
    ui.painter().rect(r, CornerRadius::same(10), col.gamma_multiply(0.13), Stroke::new(1.0, col.gamma_multiply(0.45)), egui::StrokeKind::Inside);
    ui.painter().galley(egui::pos2(r.left() + u(9.0), r.center().y - g.size().y / 2.0), g, col);
}

pub(super) fn place_words(p: Place) -> &'static str {
    match p {
        Place::Here => "stays on this computer",
        Place::Server => "goes to your own server",
        Place::Cloud => "goes to a cloud service",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn found(walled: bool) -> Option<aiharness::Found> {
        Some(aiharness::Found { login: Some(true), walled, ..Default::default() })
    }

    #[test]
    fn the_gate() {
        assert!(gate(false, false).is_err() && gate(true, true).is_err() && gate(true, false).is_ok());
        assert!(!AiPrefs::default().on && !AiPrefs::from_json(&Value::Null).on);
    }

    #[test]
    fn where_questions_go() {
        let mut p = AiPrefs::default();
        let mut s = Seen { claude: found(true), codex: found(true), ollama: Some(vec![("a:cloud".into(), true), ("b".into(), false)]), lmstudio: Some(vec!["m".into()]) };
        let id = |p: &AiPrefs, s: &Seen| route(p, s, &[]).map(|u| (u.id, u.place));
        assert_eq!(id(&p, &s), Ok(("claude", Place::Cloud)));
        s.claude = None;
        assert_eq!(id(&p, &s), Ok(("codex", Place::Cloud)));
        // Without the wall only when it's allowed.
        s.codex = found(false);
        assert_eq!(id(&p, &s), Ok(("ollama", Place::Here)));
        p.files_ok = true;
        assert_eq!(id(&p, &s), Ok(("codex", Place::Cloud)));
        s.codex = None;
        s.ollama = Some(vec![("a:cloud".into(), true)]);
        assert_eq!(id(&p, &s), Ok(("ollama", Place::Cloud)));
        s.ollama = None;
        assert_eq!(id(&p, &s), Ok(("lmstudio", Place::Here)));
        s.lmstudio = None;
        // And nothing after that, whatever is filled in.
        p.url = "https://llm.example.com".into();
        p.models.insert("server".into(), "x".into());
        assert!(id(&p, &s).unwrap_err().contains("Set one up"));
        p.choice = "server".into();
        assert_eq!(id(&p, &s), Ok(("server", Place::Server)));
        p.models.insert("server".into(), "x:cloud".into());
        assert_eq!(id(&p, &s), Ok(("server", Place::Cloud)));
    }

    #[test]
    fn the_strictest_cluster() {
        let mut p = AiPrefs::default();
        let s = Seen { claude: found(true), codex: found(true), ..Default::default() };
        let c = |l: &[&str]| l.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        p.clusters.insert("b".into(), "never".into());
        p.clusters.insert("c".into(), "codex".into());
        p.clusters.insert("d".into(), "claude".into());
        assert!(route(&p, &s, &c(&["a", "b"])).is_err());
        assert_eq!(route(&p, &s, &c(&["a", "c"])).unwrap().id, "codex");
        assert!(route(&p, &s, &c(&["c", "d"])).unwrap_err().contains("different"));
        assert_eq!(AiPrefs::from_json(&json!({"clusters": {"x": "gone"}})).clusters["x"], "never");
    }

    #[test]
    fn markers() {
        let mut p = AiPrefs::default();
        let mut s = Seen { claude: found(true), ollama: Some(vec![("a:cloud".into(), true), ("b".into(), false)]), lmstudio: Some(vec!["m".into()]), ..Default::default() };
        for id in ["claude", "codex", "anthropic", "command"] {
            assert_eq!(place_of(id, &p, &s), Some(Place::Cloud));
        }
        assert_eq!((place_of("ollama", &p, &s), place_of("lmstudio", &p, &s), place_of("server", &p, &s)), (Some(Place::Here), Some(Place::Here), Some(Place::Server)));
        p.models.insert("ollama".into(), "a:cloud".into());
        p.url = "https://api.openai.com/v1".into();
        assert_eq!((place_of("ollama", &p, &s), place_of("server", &p, &s)), (Some(Place::Cloud), Some(Place::Cloud)));
        // A marker never says something else than what's really done.
        for id in ["claude", "ollama", "lmstudio"] {
            p.choice = id.into();
            assert_eq!(route(&p, &s, &[]).ok().map(|u| u.place), place_of(id, &p, &s));
        }
        p.choice = "claude".into();
        p.clusters.insert("x".into(), "lmstudio".into());
        p.clusters.insert("y".into(), "never".into());
        let l = ways(&p, &s, &["x".into(), "y".into(), "z".into()]);
        assert_eq!((used_at(&l, Place::Here), used_at(&l, Place::Server), used_at(&l, Place::Cloud)), (vec!["lmstudio"], vec![], vec!["claude"]));
        s.ollama = None;
        p.models.clear();
        assert_eq!(place_of("ollama", &p, &s), None);
    }

    #[test]
    fn what_goes_where() {
        let p = AiPrefs::default();
        assert!(p.may(Class::Log, Place::Here) && p.may(Class::Log, Place::Server) && !p.may(Class::Log, Place::Cloud));
        assert!(p.may(Class::Value, Place::Here) && !p.may(Class::Value, Place::Server) && !p.may(Class::Value, Place::Cloud));
        assert!(p.names[Place::Cloud as usize] && !p.names[Place::Here as usize]);
        let mut q = p.clone();
        q.on = true;
        q.logs = [false, true, true];
        q.clusters.insert("a".into(), "never".into());
        assert!(q.agent == "off" && q.watch.is_empty());
        q.agent = "ask".into();
        q.watch.insert("a".into(), "ai".into());
        assert_eq!(AiPrefs::from_json(&json!({"agent": "everything", "watch": {"a": "all"}})), AiPrefs::default());
        assert_eq!(AiPrefs::from_json(&q.json()), q);
        // No key is ever in the settings.
        assert!(!q.json().to_string().contains("key"));
    }

    #[test]
    fn servers() {
        assert_eq!(check_server("llm.example.com").unwrap(), ("https://llm.example.com/v1".into(), Place::Server));
        assert_eq!(check_server("http://10.0.0.5:8000/v1/").unwrap(), ("http://10.0.0.5:8000/v1".into(), Place::Server));
        assert_eq!(check_server("https://api.openai.com/v1").unwrap().1, Place::Cloud);
        assert_eq!(check_server("https://x.openai.azure.com/openai/v1").unwrap().1, Place::Cloud);
        for bad in ["http://llm.example.com", "https://a:b@x.example.com", "http://127.0.0.1:11434", "ftp://x", "", "https://x/?a=b"] {
            assert!(check_server(bad).is_err(), "{bad}");
        }
        assert!(cloud_name("kimi:cloud") && cloud_name("gpt-oss:120b-cloud") && !cloud_name("llama3"));
        assert_eq!(ollama_models(&json!({"models": [{"name": "a", "remote_host": "https://x"}, {"name": "b"}, {"name": "c", "remote_model": "y"}]})), vec![("a".to_string(), true), ("b".into(), false), ("c".into(), true)]);
    }

    #[test]
    fn pieces() {
        assert_eq!(piece(r#"data: {"choices":[{"delta":{"content":"Hi"}}]}"#), Ok(Some("Hi".into())));
        assert_eq!(piece(r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}"#), Ok(Some("Hi".into())));
        assert_eq!(piece("data: [DONE]"), Ok(None));
        assert_eq!(piece(r#"{"error":{"message":"no"}}"#), Err("no".into()));
        assert_eq!(piece(r#"{"choices":[{"message":{"content":"All"}}]}"#), Ok(Some("All".into())));
        assert_eq!(words("a 'b c' --d=\"e f\" ''"), vec!["a", "b c", "--d=e f", ""]);
        let b = body(false, "m", "brief", &vec![(true, "q".into()), (false, "a".into())]);
        assert!(b["messages"][0]["role"] == "system" && b["messages"][2]["role"] == "assistant");
        let b = body(true, "m", "brief", &vec![(true, "q".into())]);
        assert!(b["system"] == "brief" && b["messages"].as_array().unwrap().len() == 1);
    }

    /// A stand-in server.
    fn serve(answer: &'static str) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/chat/completions", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut got = String::new();
            let mut b = [0u8; 4096];
            loop {
                let n = s.read(&mut b).unwrap();
                got.push_str(&String::from_utf8_lossy(&b[..n]));
                if n == 0 || got.contains("\"stream\":true") && got.trim_end().ends_with('}') {
                    break;
                }
            }
            s.write_all(answer.as_bytes()).unwrap();
            got
        });
        (url, h)
    }

    #[test]
    fn a_stand_in_server() {
        let ask = |url: &str, key: Option<&str>| {
            let (stop, part) = (Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(String::new())));
            let r = post(url, key, false, &body(false, "m", "brief", &vec![(true, "question".into())]), &stop, &part);
            let p = part.lock().unwrap().clone();
            (r, p)
        };
        let (u, h) = serve("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\ndata: [DONE]\n\n");
        assert_eq!(ask(&u, Some("made-up")), (Ok("Hello".into()), "Hello".into()));
        let got = h.join().unwrap();
        assert!(got.contains("Bearer made-up") && got.contains("question"));
        // Its list of models, with a stand-in that answers one request.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let u = format!("http://{}/v1/models", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 4096];
            let n = s.read(&mut b).unwrap();
            let t = r#"{"data":[{"id":"m2"},{"id":"m1"},{"x":1}]}"#;
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{t}", t.len()).as_bytes()).unwrap();
            String::from_utf8_lossy(&b[..n]).to_string()
        });
        assert_eq!(list_models(&u, Some("made-up"), false), Ok(vec!["m1".to_string(), "m2".into()]));
        assert!(h.join().unwrap().contains("Bearer made-up"));
        let (u, h) = serve("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        assert!(ask(&u, None).0.unwrap_err().contains("key"));
        h.join().unwrap();
        // Never sent on to somewhere else.
        let (u, h) = serve("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        assert!(ask(&u, None).0.unwrap_err().contains("somewhere else"));
        h.join().unwrap();
    }

    /// With what's really on this computer and made-up facts only. Run by hand:
    /// cargo test for_real -- --ignored --nocapture
    #[test]
    #[ignore]
    fn for_real() {
        let s = look();
        let short = |f: &Option<aiharness::Found>| f.as_ref().map(|f| (f.version.clone(), f.login, f.problem.clone(), f.walled));
        println!("claude {:?}\ncodex {:?}\nollama {:?}\nlmstudio {:?}", short(&s.claude), short(&s.codex), s.ollama.as_ref().map(|l| l.len()), s.lmstudio);
        let brief = super::super::aifacts::brief(false, None);
        let q = "Facts:\n[F1] The made-up container web ended with OOMKilled.\n[F2] Its memory limit is 64Mi.\n\nQuestion: Waarom herstart hij? Een zin.".to_string();
        for id in ["claude", "codex"] {
            // The cheapest of the models it lists.
            let l = if id == "claude" { &s.claude } else { &s.codex }.as_ref().map(|f| f.models.clone()).unwrap_or_default();
            println!("{id} lists {l:?}");
            let m = l.iter().find(|m| m.0.contains("haiku") || m.0.contains("luna")).map(|m| m.0.clone()).unwrap_or_default();
            let p = AiPrefs { choice: id.into(), models: [(id.to_string(), m)].into(), ..Default::default() };
            let Ok(to) = route(&p, &s, &[]) else { continue };
            let j = Job { to, url: String::new(), command: String::new(), claude: s.claude.clone(), codex: s.codex.clone() };
            let (stop, part) = (Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(String::new())));
            println!("{id}: {:?}", send(&j, &brief, &vec![(true, q.clone())], &stop, &part));
        }
    }

    /// Look-ups with the real harnesses and made-up results. By hand:
    /// cargo test looks_for_real -- --ignored --nocapture
    #[test]
    #[ignore]
    fn looks_for_real() {
        use super::super::aitools;
        let s = look();
        let brief = super::super::aifacts::brief(false, Some(&aitools::manual(true, &["made-up".into()])));
        for id in ["claude", "codex"] {
            let p = AiPrefs { choice: id.into(), ..Default::default() };
            let Ok(to) = route(&p, &s, &[]) else { continue };
            let j = Job { to, url: String::new(), command: String::new(), claude: s.claude.clone(), codex: s.codex.clone() };
            let mut turns: Turns = vec![(true, "Facts:\n[F1] This is about pod web-1 in namespace shop.\n[F2] Container web isn't ready: CrashLoopBackOff, 7 restarts\n\nQuestion: Why does it crash?".into())];
            for round in 0..4 {
                let (stop, part) = (Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(String::new())));
                let r = send(&j, &brief, &turns, &stop, &part);
                println!("{id} {round}: {r:?}");
                let Ok(t) = r else { break };
                let (_, l) = aitools::asked(&t);
                if l.is_empty() {
                    break;
                }
                let limits = HashMap::new();
                for v in &l {
                    println!("   {:?}", aitools::check(v, &aitools::Allowed { ctxs: &[("c".into(), "made-up".into())], limits: &limits, logs: true }).map(|x| x.words()));
                }
                turns.push((false, t));
                turns.push((true, format!("Results of the look-ups:\n[F{}] Log of web-1: FATAL can't reach database db.shop:5432, connection refused\n[F{}] No events\n", 3 + round * 2, 4 + round * 2)));
            }
        }
    }
}
