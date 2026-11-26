//! Apache Pulsar: its parts, its topics with who writes and reads them, and what's piling up.

use super::pg::{big, bytes, check_panel, curve, label_at, panel, pill, spark, stream, two, Check, PgId};
use super::*;

/// One Pulsar found among the pods.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Found {
    pub(super) id: PgId,
    brokers: Vec<String>,
    /// All in one pod, without a login of its own.
    standalone: bool,
}

fn ready(p: &Value) -> bool {
    p["status"]["conditions"].as_array().into_iter().flatten().any(|c| c["type"] == "Ready" && c["status"] == "True")
}

fn is_pulsar(p: &Value) -> bool {
    p["spec"]["containers"].as_array().into_iter().flatten().any(|c| {
        let img = c["image"].as_str().unwrap_or("").split('@').next().unwrap_or("");
        let repo = img.rsplit_once(':').filter(|x| !x.1.contains('/')).map(|x| x.0).unwrap_or(img);
        matches!(repo.rsplit('/').next(), Some("pulsar" | "pulsar-all"))
    })
}

fn find(ctx: &str, pods: &[Value]) -> Vec<Found> {
    let mut out: Vec<Found> = vec![];
    for p in pods.iter().filter(|p| is_pulsar(p) && p["status"]["phase"] == "Running") {
        let m = &p["metadata"];
        let (ns, name, l) = (m["namespace"].as_str().unwrap_or(""), m["name"].as_str().unwrap_or(""), &m["labels"]);
        let standalone = match l["component"].as_str() {
            Some("broker") => false,
            Some(_) => continue,
            None => true,
        };
        let cluster = if standalone {
            // The pod's owner: "pulsar-5f585cd8f" without the hash, or the stateful set's name.
            let o = &m["ownerReferences"][0];
            let n = o["name"].as_str().unwrap_or(name);
            match o["kind"].as_str() { Some("ReplicaSet") => n.rsplit_once('-').map(|x| x.0).unwrap_or(n), Some("Job") => continue, _ => n }
        } else {
            l["cluster"].as_str().or(l["release"].as_str()).unwrap_or("pulsar")
        };
        let id = PgId { ctx: ctx.into(), ns: ns.into(), name: cluster.into() };
        match out.iter_mut().find(|f| f.id == id) {
            Some(f) => f.brokers.push(name.into()),
            None => out.push(Found { id, brokers: vec![name.into()], standalone }),
        }
    }
    for f in &mut out {
        f.brokers.sort();
    }
    out.sort_by(|a, b| (&a.id.ns, &a.id.name).cmp(&(&b.id.ns, &b.id.name)));
    out
}

fn fetch(k: &Kubectl, f: &Found) -> Result<String, String> {
    let id = &f.id;
    let mut who = "no login".to_string();
    let mut auth = None;
    for (s, key) in [(format!("{}-token-admin", id.name), "TOKEN"), (format!("{}-token-superuser", id.name), "TOKEN"), (format!("{}-secrets", id.name), "ADMIN_TOKEN")] {
        if f.standalone {
            break;
        }
        if let Ok(t) = login::secret_value(k, &id.ctx, &id.ns, &s, key) {
            who = format!("the admin token in {s}");
            auth = Some(t);
            break;
        }
    }
    let base = ["/admin/v2/broker-stats/load-report", "/admin/v2/broker-stats/topics"];
    let extra = ["/admin/v2/tenants", "/admin/v2/bookies/all", "/admin/v2/brokers/version"];
    let parts: Vec<Result<Value, String>> = std::thread::scope(|sc| {
        let hs: Vec<_> = f
            .brokers
            .iter()
            .enumerate()
            .map(|(n, b)| {
                let auth = match &auth { Some(t) => login::Auth::Token(t.clone()), None => login::Auth::None };
                sc.spawn(move || -> Result<Value, String> {
                    let t = login::tunnel(k, &id.ctx, &id.ns, &format!("pod/{b}"), 8080)?;
                    let paths: Vec<String> = base.iter().chain(if n == 0 { extra.iter() } else { [].iter() }).map(|s| s.to_string()).collect();
                    let got = login::get(&auth, &format!("http://{b}:8080"), &t, &paths, None)?;
                    // A standalone broker has no load report (204); its topics add up to the same.
                    if let Some((c, _)) = got.get(1).filter(|g| g.0 != 200) {
                        return Err(match c { 401 | 403 => "the login was refused".into(), c => format!("it answered {c}") });
                    }
                    let j = |i: usize| got.get(i).filter(|g| g.0 == 200).and_then(|g| serde_json::from_str::<Value>(&g.1).ok()).unwrap_or(Value::Null);
                    let mut o = serde_json::json!({ "name": b, "load": null, "topics": topics(&j(1)) });
                    o["load"] = if j(0).is_object() { pick(&j(0)) } else { added_up(&o["topics"]) };
                    if n == 0 {
                        o["tenants"] = j(2);
                        o["bookies"] = j(3)["bookies"].clone();
                        o["version"] = Value::String(got.get(4).filter(|g| g.0 == 200).map(|g| g.1.trim().trim_matches('"').to_string()).unwrap_or_default());
                    }
                    Ok(o)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err("failed".into()))).collect()
    });
    let mut out = serde_json::json!({ "who": who, "brokers": [] });
    let mut errors = vec![];
    let mut brokers = vec![];
    for (b, r) in f.brokers.iter().zip(parts) {
        match r {
            Ok(v) => {
                for key in ["tenants", "bookies", "version"] {
                    if !v[key].is_null() {
                        out[key] = v[key].clone();
                    }
                }
                brokers.push(v);
            }
            Err(e) => errors.push(format!("{b}: {e}")),
        }
    }
    if brokers.is_empty() {
        return Err(errors.join("; "));
    }
    out["brokers"] = Value::Array(brokers);
    out["errors"] = errors.into();
    Ok(out.to_string())
}

/// The parts of a load report used here.
fn pick(l: &Value) -> Value {
    let share = |k: &str| l[k]["usage"].as_f64().zip(l[k]["limit"].as_f64()).map(|(a, b)| a / b.max(1.0) * 100.0).unwrap_or(0.0);
    serde_json::json!({ "cpu": share("cpu"), "memory": share("memory"), "direct": share("directMemory"), "in": l["msgRateIn"], "out": l["msgRateOut"], "tin": l["msgThroughputIn"], "tout": l["msgThroughputOut"], "producers": l["numProducers"], "consumers": l["numConsumers"] })
}

/// What a load report would say, from the topics. No CPU and memory.
fn added_up(topics: &Value) -> Value {
    let list = || topics.as_array().into_iter().flatten();
    let sum = |k: &str| list().map(|t| t[k].as_f64().unwrap_or(0.0)).fold(0.0, |a, b| a + b);
    let readers: u64 = list().flat_map(|t| t["subs"].as_array().into_iter().flatten()).map(|s| s["consumers"].as_u64().unwrap_or(0)).sum();
    serde_json::json!({ "in": sum("in"), "out": sum("out"), "tin": sum("tin"), "tout": sum("tout"), "producers": sum("producers") as u64, "consumers": readers })
}

/// A broker's topics, partitions still apart.
fn topics(v: &Value) -> Vec<Value> {
    let mut out = vec![];
    for (_, bundles) in v.as_object().into_iter().flatten() {
        for (_, domains) in bundles.as_object().into_iter().flatten() {
            for (_, ts) in domains.as_object().into_iter().flatten() {
                for (name, t) in ts.as_object().into_iter().flatten() {
                    let subs: Vec<Value> = t["subscriptions"].as_object().into_iter().flatten().map(|(n, s)| {
                        serde_json::json!({ "name": n, "type": s["type"], "backlog": s["msgBacklog"], "out": s["msgRateOut"], "unacked": s["unackedMessages"], "blocked": s["blockedSubscriptionOnUnackedMsgs"], "consumers": s["consumers"].as_array().map(|a| a.len()).unwrap_or(0) })
                    }).collect();
                    out.push(serde_json::json!({ "name": name, "in": t["msgRateIn"], "out": t["msgRateOut"], "tin": t["msgThroughputIn"], "tout": t["msgThroughputOut"], "total": t["msgInCount"], "storage": t["storageSize"], "producers": t["producerCount"], "subs": subs }));
                }
            }
        }
    }
    out
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Sub {
    name: String,
    kind: String,
    backlog: f64,
    out: f64,
    unacked: f64,
    consumers: f64,
    blocked: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Topic {
    /// "tenant/namespace" and the name in it.
    ns: String,
    name: String,
    persistent: bool,
    partitions: usize,
    brokers: Vec<String>,
    rate_in: f64,
    rate_out: f64,
    total: f64,
    storage: f64,
    producers: f64,
    subs: Vec<Sub>,
}

impl Topic {
    fn backlog(&self) -> f64 {
        self.subs.iter().fold(0.0, |a, s| a + s.backlog)
    }
    /// Pulsar's own bookkeeping.
    fn internal(&self) -> bool {
        self.ns.starts_with("pulsar/") || self.name.starts_with("__")
    }
}

/// Topics with their partitions added up.
fn all_topics(v: &Value) -> Vec<Topic> {
    let mut out: Vec<Topic> = vec![];
    for b in v["brokers"].as_array().into_iter().flatten() {
        let broker = b["name"].as_str().unwrap_or("");
        for t in b["topics"].as_array().into_iter().flatten() {
            let full = t["name"].as_str().unwrap_or("");
            let (dom, path) = full.split_once("://").unwrap_or(("persistent", full));
            let (ns, mut name) = path.rsplit_once('/').unwrap_or(("", path));
            let mut part = false;
            if let Some((base, n)) = name.rsplit_once("-partition-") {
                if !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) {
                    name = base;
                    part = true;
                }
            }
            let persistent = dom == "persistent";
            let i = out.iter().position(|x| x.ns == ns && x.name == name && x.persistent == persistent).unwrap_or_else(|| {
                out.push(Topic { ns: ns.into(), name: name.into(), persistent, ..Default::default() });
                out.len() - 1
            });
            let x = &mut out[i];
            x.partitions += part as usize;
            if !x.brokers.iter().any(|b| b == broker) {
                x.brokers.push(broker.into());
            }
            let f = |k: &str| t[k].as_f64().unwrap_or(0.0);
            x.rate_in += f("in");
            x.rate_out += f("out");
            x.total += f("total");
            x.storage += f("storage");
            x.producers = if part { x.producers.max(f("producers")) } else { x.producers + f("producers") };
            for s in t["subs"].as_array().into_iter().flatten() {
                let n = s["name"].as_str().unwrap_or("");
                let j = x.subs.iter().position(|y| y.name == n).unwrap_or_else(|| {
                    x.subs.push(Sub { name: n.into(), kind: s["type"].as_str().unwrap_or("").into(), ..Default::default() });
                    x.subs.len() - 1
                });
                let g = |k: &str| s[k].as_f64().unwrap_or(0.0);
                let y = &mut x.subs[j];
                y.backlog += g("backlog");
                y.out += g("out");
                y.unacked += g("unacked");
                y.consumers = y.consumers.max(g("consumers"));
                y.blocked |= s["blocked"].as_bool().unwrap_or(false);
            }
        }
    }
    // What's piling up first, then the busiest.
    out.sort_by(|a, b| {
        let key = |t: &Topic| (t.backlog(), t.rate_in + t.rate_out, t.total);
        key(b).partial_cmp(&key(a)).unwrap_or(std::cmp::Ordering::Equal).then(a.name.cmp(&b.name))
    });
    out
}

/// Messages in and out per second over all brokers.
pub(super) fn reading(v: &Value) -> (f64, f64) {
    let sum = |k: &str| v["brokers"].as_array().into_iter().flatten().map(|b| b["load"][k].as_f64().unwrap_or(0.0)).fold(0.0, |a, b| a + b);
    (sum("in"), sum("out"))
}

pub(super) fn count(n: f64) -> String {
    if n >= 1e6 {
        format!("{:.1}M", n / 1e6)
    } else if n >= 1e4 {
        format!("{:.0}k", n / 1e3)
    } else {
        format!("{n:.0}")
    }
}

/// Look it over, worst first. `parts`: (component, ready, total).
fn checks(v: Option<&Value>, parts: &[(String, usize, usize)]) -> Vec<Check> {
    let mut out: Vec<Check> = vec![];
    let mut add = |tone: Tone, title: &str, detail: String| out.push(Check { tone, title: title.into(), detail });
    for (c, r, t) in parts {
        let name = match c.as_str() { "bookie" => "Storage (bookies)", "zookeeper" => "Coordination (ZooKeeper)", "broker" => "Brokers", "proxy" => "Proxies", o => o };
        // ZooKeeper needs more than half.
        let dead = *r == 0 || (c == "zookeeper" && r * 2 <= *t);
        add(if r >= t { Tone::Success } else if dead { Tone::Danger } else { Tone::Warning }, name, format!("{r} of {t} ready"));
    }
    if let Some(v) = v {
        for e in v["errors"].as_array().into_iter().flatten().filter_map(|e| e.as_str()) {
            add(Tone::Warning, "Couldn't ask a broker", e.to_string());
        }
        let ts: Vec<Topic> = all_topics(v).into_iter().filter(|t| !t.internal()).collect();
        let names = |l: &[String]| truncate(&l.join(", "), 160);
        let left: Vec<String> = ts.iter().flat_map(|t| t.subs.iter().filter(|s| s.backlog > 0.0 && s.consumers == 0.0).map(|s| format!("{} → {} ({})", t.name, s.name, count(s.backlog)))).collect();
        let slow: Vec<String> = ts.iter().flat_map(|t| t.subs.iter().filter(|s| s.backlog >= 10_000.0 && s.consumers > 0.0).map(|s| format!("{} → {} ({})", t.name, s.name, count(s.backlog)))).collect();
        let blocked: Vec<String> = ts.iter().flat_map(|t| t.subs.iter().filter(|s| s.blocked).map(|s| format!("{} → {}", t.name, s.name))).collect();
        let dead: Vec<String> = ts.iter().filter(|t| t.name.ends_with("-DLQ") && (t.backlog() > 0.0 || t.total > 0.0)).map(|t| t.name.clone()).collect();
        if !blocked.is_empty() {
            add(Tone::Danger, "Blocked by unconfirmed messages", names(&blocked));
        }
        if !left.is_empty() {
            add(Tone::Danger, "Messages nobody reads", names(&left));
        }
        if !slow.is_empty() {
            add(Tone::Warning, "Readers behind", names(&slow));
        }
        if blocked.is_empty() && left.is_empty() && slow.is_empty() {
            add(Tone::Success, "Nothing piling up", format!("{} topics", ts.len()));
        }
        if !dead.is_empty() {
            add(Tone::Warning, "Dead-letter topics in use", names(&dead));
        }
        let per: Vec<usize> = v["brokers"].as_array().into_iter().flatten().map(|b| b["topics"].as_array().map(|a| a.len()).unwrap_or(0)).collect();
        if per.len() > 1 && per.contains(&0) && per.iter().sum::<usize>() > per.len() {
            add(Tone::Muted, "Topics are unevenly spread", per.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" / ") + " per broker");
        }
        let hot = v["brokers"].as_array().into_iter().flatten().map(|b| b["load"]["direct"].as_f64().unwrap_or(0.0).max(b["load"]["cpu"].as_f64().unwrap_or(0.0))).fold(0.0, f64::max);
        if hot >= 85.0 {
            add(Tone::Warning, "A broker is near its limit", format!("{hot:.0}% of CPU or direct memory"));
        }
    }
    let rank = |t: Tone| match t { Tone::Danger => 0, Tone::Warning => 1, _ => 2 };
    out.sort_by_key(|c| rank(c.tone));
    out
}

impl KubedogApp {
    pub(super) fn pulsars(&self, ctx: &str) -> Vec<Found> {
        self.lists.get(&Self::list_key(ctx, Kind::Pods)).map(|l| find(ctx, &l.items)).unwrap_or_default()
    }

    pub(super) fn has_pulsar(&self) -> bool {
        let gen: u64 = self.active.iter().map(|c| self.lists.get(&Self::list_key(c, Kind::Pods)).map(|l| l.gen).unwrap_or(0)).sum::<u64>() + 1;
        let (at, yes) = self.pulsar_seen.get();
        if at == gen {
            return yes;
        }
        let yes = self.active.iter().any(|c| !self.pulsars(c).is_empty());
        self.pulsar_seen.set((gen, yes));
        yes
    }

    fn pu_key(id: &PgId) -> String {
        format!("pulsar|{}|{}|{}", id.ctx, id.ns, id.name)
    }

    fn pu_found(&self, id: &PgId) -> Option<Found> {
        self.pulsars(&id.ctx).into_iter().find(|f| f.id == *id)
    }

    /// (component, ready, total) of a Pulsar's pods.
    pub(super) fn pu_parts(&self, f: &Found) -> Vec<(String, usize, usize)> {
        let id = &f.id;
        let pods = self.lists.get(&Self::list_key(&id.ctx, Kind::Pods)).map(|l| l.items.as_slice()).unwrap_or(&[]);
        if f.standalone {
            let mine: Vec<&Value> = pods.iter().filter(|p| f.brokers.iter().any(|b| p["metadata"]["name"].as_str() == Some(b)) && p["metadata"]["namespace"].as_str() == Some(&id.ns)).collect();
            return vec![("broker".into(), mine.iter().filter(|p| ready(p)).count(), mine.len())];
        }
        let mut out = vec![];
        for c in ["proxy", "broker", "bookie", "zookeeper"] {
            let mine: Vec<&Value> = pods
                .iter()
                .filter(|p| p["metadata"]["namespace"].as_str() == Some(&id.ns) && p["metadata"]["labels"]["component"].as_str() == Some(c) && p["metadata"]["labels"]["cluster"].as_str().or(p["metadata"]["labels"]["release"].as_str()) == Some(&id.name))
                .collect();
            if !mine.is_empty() {
                out.push((c.to_string(), mine.iter().filter(|p| ready(p)).count(), mine.len()));
            }
        }
        out
    }

    pub(super) fn refresh_pulsar(&mut self, force: bool) {
        if self.power_off("pulsar") {
            return;
        }
        if self.view != View::Pulsar {
            return;
        }
        let Some(f) = self.pu_sel.clone().and_then(|id| self.pu_found(&id)) else { return };
        let key = Self::pu_key(&f.id);
        self.serve(&key, force, move |k| fetch(k, &f));
    }

    pub(super) fn pulsar_ready(&self) -> bool {
        self.has_pulsar() && self.pu_sel.as_ref().map(|id| !self.login_allowed(&Self::pu_key(id)) || self.served.get(&Self::pu_key(id)).map(|s| s.fetched.is_some()).unwrap_or(false)).unwrap_or(true)
    }

    pub(super) fn pulsar_view(&mut self, ui: &mut Ui) {
        if let Some(id) = self.pu_sel.clone() {
            self.pulsar_page(ui, &id);
            return;
        }
        let search = self.search.to_lowercase();
        let mut cards = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for f in self.pulsars(c) {
                if !self.ns_ok(&f.id.ns) || !(search.is_empty() || f.id.name.contains(&search) || f.id.ns.contains(&search)) {
                    continue;
                }
                let parts = self.pu_parts(&f);
                let worst = checks(None, &parts).first().map(|c| c.tone).unwrap_or(Tone::Muted);
                let text = if f.standalone { "Standalone, all in one pod".to_string() } else { parts.iter().map(|(c, r, t)| format!("{r}/{t} {c}")).collect::<Vec<_>>().join("  ·  ") };
                cards.push((f.id, tone_color(worst), vec![(if worst == Tone::Success { "Everything is ready".to_string() } else { "Not everything is ready".to_string() }, tone_color(worst)), (text, TEXT_MUTED())]));
            }
        }
        self.header(ui, true, Some(format!("{} Pulsar", cards.len())), true);
        ui.add_space(8.0);
        let mut open = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| open = self.super_cards(ui, &cards));
        if open.is_some() {
            self.pu_sel = open;
            self.refresh_current(false);
        }
    }

    fn pulsar_page(&mut self, ui: &mut Ui, id: &PgId) {
        if self.super_back(ui, id, "Pulsar") {
            self.pu_sel = None;
            return;
        }
        let Some(f) = self.pu_found(id) else {
            ui.spinner();
            return;
        };
        let key = Self::pu_key(id);
        let (data, error, hist) = match self.served.get(&key) {
            Some(s) => (s.data.clone(), s.error.clone(), s.hist.iter().copied().collect::<Vec<_>>()),
            None => (None, None, vec![]),
        };
        let parts = self.pu_parts(&f);
        let allowed = self.login_allowed(&key);
        let mut forget = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} /", id.ns)).size(z(20.0)).color(TEXT_SUBTLE()));
            ui.label(RichText::new(&id.name).size(z(20.0)).color(TEXT_DEFAULT()));
            if let Some(v) = data.as_ref().and_then(|d| d["version"].as_str()).filter(|v| !v.is_empty()) {
                pill(ui, &format!("Pulsar {v}"), INFO());
            }
            for (c, r, t) in &parts {
                pill(ui, &format!("{r}/{t} {c}"), if r >= t { SUCCESS() } else { WARNING() });
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if allowed {
                    forget = button(ui, if f.standalone { "Stop looking" } else { "Log out" }, false, false);
                    if let Some(w) = data.as_ref().and_then(|d| d["who"].as_str()) {
                        ui.label(RichText::new(format!("reading with {w}")).size(z(12.0)).color(TEXT_SUBTLE()));
                    }
                }
            });
        });
        ui.add_space(6.0);
        if forget {
            self.allow_login(&key, false);
            return;
        }
        let mut area = egui::ScrollArea::vertical().id_salt("pu-page").auto_shrink([false, false]);
        if self.screenshot.is_some() {
            if let Some(y) = std::env::var("KUBEDOG_SHOT_SCROLL").ok().and_then(|v| v.parse::<f32>().ok()) {
                area = area.vertical_scroll_offset(y);
            }
        }
        area.show(ui, |ui| {
            if !allowed {
                let how = if f.standalone { "This one runs in a single pod; Kubedog asks it without a login.".to_string() } else { format!("It uses the admin token in secret {0}-token-admin (or {0}-token-superuser, or {0}-secrets). That token may change things in Pulsar, so Kubedog only ever sends reads with it.", id.name) };
                self.login_card(ui, &key, &id.name, &how, !f.standalone);
            }
            if let Some(e) = &error {
                Frame::new().fill(WARN_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(8)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("Couldn't look inside: {e}")).size(z(12.5)).color(WARNING()));
                });
                ui.add_space(8.0);
            }
            let list = checks(data.as_ref(), &parts);
            let Some(v) = &data else {
                if allowed && error.is_none() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Asking the brokers…").color(TEXT_SUBTLE()));
                    });
                }
                card(ui, |ui| check_panel(ui, &list));
                return;
            };
            let topics = all_topics(v);
            pu_lanes(ui, &topics);
            ui.add_space(12.0);
            two(ui, |ui| check_panel(ui, &list), |ui| pu_activity(ui, v, &topics, &hist));
            ui.add_space(12.0);
            two(ui, |ui| pu_brokers(ui, v), |ui| pu_backlog(ui, &topics));
            ui.add_space(16.0);
        });
    }
}

/// The busiest topics as lanes: writers, the topic, its readers.
fn pu_lanes(ui: &mut Ui, topics: &[Topic]) {
    let shown: Vec<&Topic> = topics.iter().filter(|t| !t.internal()).take(8).collect();
    let total = topics.iter().filter(|t| !t.internal()).count();
    Frame::new().fill(BG_SUBTLE()).stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(12)).inner_margin(Margin::symmetric(16, 12)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        panel(ui, "Topics", &if total > shown.len() { format!("what's piling up first, then the busiest: {} of {total}", shown.len()) } else { "what's piling up first, then the busiest".to_string() });
        if shown.is_empty() {
            ui.label(RichText::new("No topics are loaded right now.").color(TEXT_SUBTLE()));
        }
        let time = ui.input(|i| i.time) as f32;
        for (n, t) in shown.iter().enumerate() {
            // The ones in trouble first.
            let mut subs: Vec<&Sub> = t.subs.iter().collect();
            subs.sort_by(|a, b| (b.blocked, b.backlog).partial_cmp(&(a.blocked, a.backlog)).unwrap_or(std::cmp::Ordering::Equal));
            subs.truncate(4);
            let sub_h = u(34.0);
            let h = (subs.len().max(1) as f32 * (sub_h + 6.0)).max(u(60.0)) + u(10.0);
            let (area, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), Sense::hover());
            let p = ui.painter().clone();
            let w = area.width();
            // Writers.
            let pr = egui::Rect::from_center_size(egui::pos2(area.left() + u(60.0), area.center().y), egui::vec2(u(112.0), u(34.0)));
            let pcol = if t.producers > 0.0 { INFO() } else { TEXT_PLACEHOLDER() };
            p.rect_stroke(pr, CornerRadius::same(17), Stroke::new(1.0, pcol.gamma_multiply(0.7)), egui::StrokeKind::Inside);
            p.text(pr.center(), egui::Align2::CENTER_CENTER, format!("{} writer{}", count(t.producers), if t.producers == 1.0 { "" } else { "s" }), FontId::proportional(z(12.0)), pcol);
            // The topic.
            let backlog = t.backlog();
            let col = if t.subs.iter().any(|s| s.blocked || (s.backlog > 0.0 && s.consumers == 0.0)) { DANGER() } else if backlog >= 10_000.0 { WARNING() } else { SUCCESS() };
            let tw = (w * 0.34).clamp(u(230.0), u(430.0));
            let tr = egui::Rect::from_center_size(egui::pos2(area.left() + w * 0.42, area.center().y), egui::vec2(tw, u(56.0)));
            stream(&p, pr.right_center(), tr.left_center(), pcol, time * 0.5 + n as f32 * 0.21, dots(t.rate_in), t.producers > 0.0);
            p.rect_filled(tr, CornerRadius::same(9), BG_CARD());
            p.rect_stroke(tr, CornerRadius::same(9), Stroke::new(1.0, col.gamma_multiply(0.75)), egui::StrokeKind::Inside);
            label_at(ui, &p, tr.left_top() + egui::vec2(12.0, u(18.0)), &t.name, 13.5, TEXT_DEFAULT(), tw - 24.0);
            let parts = if t.partitions > 1 { format!(" · {} partitions", t.partitions) } else { String::new() };
            label_at(ui, &p, tr.left_top() + egui::vec2(12.0, u(38.0)), &format!("{}{parts} · {} in all · {}", t.ns, count(t.total), bytes(t.storage)), 11.5, TEXT_SUBTLE(), tw - 24.0);
            ui.interact(tr, egui::Id::new(("pu-topic", n)), Sense::hover()).on_hover_text(format!("{}/{}\n{:.1} messages/s in, {:.1} out\n{} waiting\non {}", t.ns, t.name, t.rate_in, t.rate_out, count(backlog), t.brokers.join(", ")));
            // Readers.
            let sx = area.right() - u(330.0).min(w * 0.3);
            if t.subs.len() > subs.len() {
                p.text(egui::pos2(tr.center().x, tr.bottom() + u(10.0)), egui::Align2::CENTER_CENTER, format!("{} subscriptions, 4 shown", t.subs.len()), FontId::proportional(z(11.0)), TEXT_PLACEHOLDER());
            }
            let th = subs.len() as f32 * (sub_h + 6.0) - 6.0;
            if subs.is_empty() {
                label_at(ui, &p, egui::pos2(sx, area.center().y), "no subscriptions", 12.0, TEXT_PLACEHOLDER(), u(200.0));
            }
            for (i, s) in subs.iter().enumerate() {
                let r = egui::Rect::from_min_size(egui::pos2(sx, area.center().y - th / 2.0 + i as f32 * (sub_h + 6.0)), egui::vec2(area.right() - sx, sub_h));
                let c = if s.blocked || (s.backlog > 0.0 && s.consumers == 0.0) { DANGER() } else if s.backlog >= 10_000.0 { WARNING() } else if s.consumers == 0.0 { TEXT_PLACEHOLDER() } else { SUCCESS() };
                let (a, b) = (tr.right_center(), r.left_center());
                stream(&p, a, b, c, time * 0.5 + i as f32 * 0.3 + n as f32 * 0.17, dots(s.out), s.consumers > 0.0);
                if s.backlog > 0.0 {
                    let g = p.layout_no_wrap(format!("{} waiting", count(s.backlog)), FontId::proportional(z(11.0)), c);
                    let br = egui::Rect::from_center_size(curve(a, b, 0.5), g.size() + egui::vec2(14.0, 6.0));
                    p.rect_filled(br, CornerRadius::same(9), BG_SUBTLE());
                    p.rect_stroke(br, CornerRadius::same(9), Stroke::new(1.0, c.gamma_multiply(0.6)), egui::StrokeKind::Inside);
                    p.galley(br.center() - g.size() / 2.0, g, c);
                }
                p.rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, c.gamma_multiply(0.6)), egui::StrokeKind::Inside);
                label_at(ui, &p, r.left_center() + egui::vec2(10.0, 0.0), &s.name, 12.5, TEXT_DEFAULT(), r.width() - u(110.0));
                p.text(r.right_center() - egui::vec2(10.0, 0.0), egui::Align2::RIGHT_CENTER, format!("{} reader{}", count(s.consumers), if s.consumers == 1.0 { "" } else { "s" }), FontId::proportional(z(11.5)), c);
                ui.interact(r, egui::Id::new(("pu-sub", n, i)), Sense::hover()).on_hover_text(format!("{} ({})\n{} waiting, {} unconfirmed\n{:.1} messages/s{}", s.name, s.kind, count(s.backlog), count(s.unacked), s.out, if s.blocked { "\nblocked: too many unconfirmed messages" } else { "" }));
            }
        }
    });
    if ui.input(|i| i.viewport().focused.unwrap_or(false)) {
        ui.ctx().request_repaint_after(Duration::from_millis(40));
    }
}

/// How many dots a stream shows: none when nothing flows.
fn dots(rate: f64) -> usize {
    if rate < 0.01 {
        0
    } else if rate < 1.0 {
        1
    } else if rate < 50.0 {
        3
    } else {
        5
    }
}

fn pu_activity(ui: &mut Ui, v: &Value, topics: &[Topic], hist: &[(i64, f64, f64)]) {
    panel(ui, "Activity", "brokers count once a minute");
    let (i, o) = reading(v);
    let per = |x: f64| format!("{x:.1}/s");
    let sum = |k: &str| -> f64 { v["brokers"].as_array().into_iter().flatten().map(|b| b["load"][k].as_f64().unwrap_or(0.0)).fold(0.0, |a, b| a + b) };
    ui.horizontal_wrapped(|ui| {
        for (val, label, col) in [
            (per(i), "messages in", PRIMARY_TEXT()),
            (per(o), "messages out", SUCCESS()),
            (format!("{}/s", bytes(sum("tin") + sum("tout"))), "traffic", TEXT_MUTED()),
            (count(topics.iter().fold(0.0, |a, t| a + t.backlog())), "waiting", TEXT_MUTED()),
            (bytes(topics.iter().fold(0.0, |a, t| a + t.storage)), "stored", TEXT_MUTED()),
        ] {
            big(ui, &val, label, col);
            ui.add_space(14.0);
        }
    });
    ui.add_space(6.0);
    if hist.len() > 1 {
        spark(ui, &hist.iter().map(|h| h.1).collect::<Vec<_>>(), u(44.0), PRIMARY_TEXT(), per);
        ui.add_space(4.0);
        spark(ui, &hist.iter().map(|h| h.2).collect::<Vec<_>>(), u(44.0), SUCCESS(), per);
    }
    let names: Vec<&str> = v["tenants"].as_array().into_iter().flatten().filter_map(|t| t.as_str()).collect();
    if !names.is_empty() {
        kv(ui, "Tenants", names.join(", "));
    }
}

fn pu_brokers(ui: &mut Ui, v: &Value) {
    panel(ui, "Brokers", if v["brokers"][0]["load"]["cpu"].is_null() { "this kind doesn't report CPU and memory" } else { "share of CPU and direct memory" });
    for b in v["brokers"].as_array().into_iter().flatten() {
        let l = &b["load"];
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(44.0)), Sense::hover());
            let p = ui.painter();
            let w = r.width();
            label_at(ui, p, egui::pos2(r.left(), r.top() + u(13.0)), b["name"].as_str().unwrap_or(""), 13.0, TEXT_DEFAULT(), w * 0.45);
            label_at(ui, p, egui::pos2(r.left(), r.top() + u(31.0)), &format!("topics {}  ·  writers {}  ·  readers {}", b["topics"].as_array().map(|a| a.len()).unwrap_or(0), l["producers"].as_i64().unwrap_or(0), l["consumers"].as_i64().unwrap_or(0)), 11.5, TEXT_SUBTLE(), w * 0.45);
            for (i, (name, k)) in [("CPU", "cpu"), ("memory", "direct")].iter().enumerate() {
                let Some(x) = l[*k].as_f64() else { continue };
                let y = r.top() + u(13.0 + 18.0 * i as f32);
                let bar = egui::Rect::from_min_size(egui::pos2(r.left() + w * 0.62, y - 3.5), egui::vec2(w * 0.26, 7.0));
                label_at(ui, p, egui::pos2(r.left() + w * 0.49, y), name, 11.5, TEXT_SUBTLE(), w * 0.12);
                p.rect_filled(bar, CornerRadius::same(3), BG_MUTED());
                p.rect_filled(egui::Rect::from_min_size(bar.min, egui::vec2((bar.width() * (x / 100.0).clamp(0.0, 1.0) as f32).max(2.0), 7.0)), CornerRadius::same(3), if x >= 85.0 { WARNING() } else { [CPU_BAR(), SUCCESS()][i] });
                p.text(egui::pos2(r.right(), y), egui::Align2::RIGHT_CENTER, format!("{x:.0}%"), FontId::proportional(z(11.5)), TEXT_MUTED());
            }
        });
    }
}

fn pu_backlog(ui: &mut Ui, topics: &[Topic]) {
    panel(ui, "Waiting messages", "per subscription");
    let mut all: Vec<(&Topic, &Sub)> = topics.iter().filter(|t| !t.internal()).flat_map(|t| t.subs.iter().map(move |s| (t, s))).filter(|x| x.1.backlog > 0.0).collect();
    all.sort_by(|a, b| b.1.backlog.partial_cmp(&a.1.backlog).unwrap_or(std::cmp::Ordering::Equal));
    if all.is_empty() {
        ui.label(RichText::new("None: every subscription has read everything.").size(z(12.5)).color(SUCCESS()));
        return;
    }
    let max = all[0].1.backlog.max(1.0);
    for (t, s) in all.iter().take(12) {
        let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(26.0)), Sense::hover());
        let p = ui.painter();
        let col = if s.consumers == 0.0 || s.blocked { DANGER() } else if s.backlog >= 10_000.0 { WARNING() } else { SUCCESS() };
        p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2((r.width() * (s.backlog / max) as f32).max(3.0), r.height() - 3.0)), CornerRadius::same(4), col.gamma_multiply(0.2));
        label_at(ui, p, r.left_center() + egui::vec2(8.0, -1.5), &format!("{} → {}", t.name, s.name), 12.5, TEXT_DEFAULT(), r.width() - u(120.0));
        p.text(r.right_center() - egui::vec2(8.0, 1.5), egui::Align2::RIGHT_CENTER, count(s.backlog), FontId::proportional(z(12.5)), col);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_them() {
        let pod = |ns: &str, name: &str, img: &str, labels: Value, owner: Value| serde_json::json!({"metadata": {"namespace": ns, "name": name, "labels": labels, "ownerReferences": [owner]}, "spec": {"containers": [{"image": img}]}, "status": {"phase": "Running"}});
        let l = |c: &str| serde_json::json!({"component": c, "cluster": "pulsar"});
        let ss = serde_json::json!({"kind": "StatefulSet", "name": "x"});
        let pods = vec![
            pod("a", "pulsar-broker-1", "docker.io/apachepulsar/pulsar:5.0.1", l("broker"), ss.clone()),
            pod("a", "pulsar-broker-0", "reg:5000/apachepulsar/pulsar-all:5", l("broker"), ss.clone()),
            pod("a", "pulsar-bookie-0", "apachepulsar/pulsar:5", l("bookie"), ss.clone()),
            pod("a", "console", "x/pulsar-console-api:1", Value::Null, ss.clone()),
            pod("b", "pulsar-5f585cd8f-mz4pd", "apachepulsar/pulsar@sha256:ab", Value::Null, serde_json::json!({"kind": "ReplicaSet", "name": "pulsar-5f585cd8f"})),
            pod("b", "init-xyz", "apachepulsar/pulsar:5", Value::Null, serde_json::json!({"kind": "Job", "name": "init"})),
        ];
        let f = find("c", &pods);
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!((f[0].id.name.as_str(), f[0].standalone, f[0].brokers.join(",").as_str()), ("pulsar", false, "pulsar-broker-0,pulsar-broker-1"));
        assert_eq!((f[1].id.name.as_str(), f[1].standalone), ("pulsar", true));
    }

    #[test]
    fn topics_and_checks() {
        let sub = |b: i64, c: usize| serde_json::json!({"type": "Shared", "msgBacklog": b, "msgRateOut": 1.0, "unackedMessages": 0, "blockedSubscriptionOnUnackedMsgs": false, "consumers": vec![serde_json::json!({}); c]});
        let raw = serde_json::json!({"t/n": {"0x0": {"persistent": {
            "persistent://t/n/orders-partition-0": {"msgRateIn": 2.0, "msgInCount": 5, "storageSize": 10, "producerCount": 1, "subscriptions": {"s": sub(3, 1)}},
            "persistent://t/n/orders-partition-1": {"msgRateIn": 1.0, "msgInCount": 5, "storageSize": 10, "producerCount": 1, "subscriptions": {"s": sub(4, 1)}},
            "persistent://t/n/__change_events": {"subscriptions": {}}
        }}}});
        let v = serde_json::json!({"brokers": [{"name": "b0", "load": {"in": 3.0, "out": 1.0}, "topics": topics(&raw)}], "errors": []});
        let t = all_topics(&v);
        assert_eq!(t.len(), 2);
        assert_eq!((t[0].name.as_str(), t[0].partitions, t[0].rate_in, t[0].backlog(), t[0].producers), ("orders", 2, 3.0, 7.0, 1.0));
        assert!(t[1].internal());
        assert_eq!(reading(&v), (3.0, 1.0));
        let a = added_up(&v["brokers"][0]["topics"]);
        assert_eq!((a["in"].as_f64(), a["consumers"].as_u64(), a["cpu"].is_null()), (Some(3.0), Some(2), true));
        let parts = vec![("zookeeper".to_string(), 3, 3)];
        assert!(checks(Some(&v), &parts).iter().all(|c| c.tone == Tone::Success));
        let raw = serde_json::json!({"t/n": {"0x0": {"persistent": {"persistent://t/n/x": {"subscriptions": {"gone": sub(9, 0), "slow": sub(20000, 2)}}, "persistent://t/n/x-DLQ": {"msgInCount": 2, "subscriptions": {}}}}}});
        let v = serde_json::json!({"brokers": [{"name": "b0", "load": {}, "topics": topics(&raw)}]});
        let r = checks(Some(&v), &[("zookeeper".to_string(), 1, 3), ("bookie".to_string(), 2, 3)]);
        for (title, tone) in [("Messages nobody reads", Tone::Danger), ("Readers behind", Tone::Warning), ("Dead-letter topics in use", Tone::Warning), ("Coordination (ZooKeeper)", Tone::Danger), ("Storage (bookies)", Tone::Warning)] {
            assert!(r.iter().any(|c| c.title == title && c.tone == tone), "{title} {r:?}");
        }
    }
}
